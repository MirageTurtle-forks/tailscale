// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func registerTrafficTestClient(s *Server, node key.NodePublic) *sclient {
	c := &sclient{s: s, key: node, logf: logger.Discard}
	s.registerClient(c)
	return c
}

func trafficByNode(snapshot NodeTrafficSnapshot) map[key.NodePublic]NodeTraffic {
	ret := make(map[key.NodePublic]NodeTraffic, len(snapshot.Nodes))
	for _, traffic := range snapshot.Nodes {
		ret[traffic.Node] = traffic
	}
	return ret
}

type trafficTestForwarder struct {
	packets chan []byte
}

func (f trafficTestForwarder) ForwardPacket(_, _ key.NodePublic, packet []byte) error {
	f.packets <- packet
	return nil
}

func (trafficTestForwarder) String() string { return "traffic-test-forwarder" }

func TestNodeTrafficMetricsPeriods(t *testing.T) {
	s := New(key.NewNode(), logger.Discard)
	defer s.Close()

	start := time.Date(2026, 9, 4, 1, 2, 3, 0, time.UTC)
	s.mu.Lock()
	s.nodeTrafficPeriodStart = start
	s.mu.Unlock()

	node1 := key.NewNode().Public()
	node2 := key.NewNode().Public()
	c1 := registerTrafficTestClient(s, node1)
	c2 := registerTrafficTestClient(s, node2)
	c1.recordNodeSentBytes(100)
	c1.recordNodeReceivedBytes(40)
	c2.recordNodeSentBytes(7)

	end := start.Add(time.Minute)
	first := s.rotateNodeTraffic(end)
	if first.Start != start || first.End != end {
		t.Fatalf("first period = [%v, %v), want [%v, %v)", first.Start, first.End, start, end)
	}
	got := trafficByNode(first)
	if traffic := got[node1]; traffic.SentBytes != 100 || traffic.ReceivedBytes != 40 {
		t.Errorf("node1 traffic = %+v, want sent=100 received=40", traffic)
	}
	if traffic := got[node2]; traffic.SentBytes != 7 || traffic.ReceivedBytes != 0 {
		t.Errorf("node2 traffic = %+v, want sent=7 received=0", traffic)
	}

	// Traffic from a client that disconnects during the period must survive
	// until that period is rotated.
	c1.recordNodeSentBytes(11)
	c1.recordNodeReceivedBytes(13)
	s.unregisterClient(c1)
	c2.recordNodeReceivedBytes(17)
	secondEnd := end.Add(time.Minute)
	second := s.rotateNodeTraffic(secondEnd)
	got = trafficByNode(second)
	if traffic := got[node1]; traffic.SentBytes != 11 || traffic.ReceivedBytes != 13 {
		t.Errorf("disconnected node traffic = %+v, want sent=11 received=13", traffic)
	}
	if traffic := got[node2]; traffic.SentBytes != 0 || traffic.ReceivedBytes != 17 {
		t.Errorf("node2 second-period traffic = %+v, want sent=0 received=17", traffic)
	}

	third := s.rotateNodeTraffic(secondEnd.Add(time.Minute))
	if len(third.Nodes) != 0 {
		t.Errorf("third period has traffic %v, want none", third.Nodes)
	}
}

func TestNodeTrafficMetricsDataPath(t *testing.T) {
	s := New(key.NewNode(), logger.Discard)
	defer s.Close()
	s.tcpWriteTimeout = 0

	source := registerTrafficTestClient(s, key.NewNode().Public())
	destination := registerTrafficTestClient(s, key.NewNode().Public())
	remoteDestination := key.NewNode().Public()
	forwarded := make(chan []byte, 1)
	s.AddPacketForwarder(remoteDestination, trafficTestForwarder{packets: forwarded})

	payload := []byte("payload counted without DERP framing")
	wire := bytes.NewBuffer(remoteDestination.AppendTo(nil))
	wire.Write(payload)
	source.br = bufio.NewReader(wire)
	if err := source.handleFrameSendPacket(derp.FrameSendPacket, uint32(key.NodePublicRawLen+len(payload))); err != nil {
		t.Fatal(err)
	}
	if got := <-forwarded; !bytes.Equal(got, payload) {
		t.Fatalf("forwarded payload = %q, want %q", got, payload)
	}

	destination.bw = &lazyBufioWriter{w: io.Discard}
	if err := destination.sendPacket(source.key, payload); err != nil {
		t.Fatal(err)
	}

	snapshot := s.rotateNodeTraffic(time.Now())
	got := trafficByNode(snapshot)
	if traffic := got[source.key]; traffic.SentBytes != uint64(len(payload)) || traffic.ReceivedBytes != 0 {
		t.Errorf("source traffic = %+v, want sent=%d received=0", traffic, len(payload))
	}
	if traffic := got[destination.key]; traffic.SentBytes != 0 || traffic.ReceivedBytes != uint64(len(payload)) {
		t.Errorf("destination traffic = %+v, want sent=0 received=%d", traffic, len(payload))
	}
}

func TestServeDebugTraffik(t *testing.T) {
	s := New(key.NewNode(), logger.Discard)
	defer s.Close()

	c := registerTrafficTestClient(s, key.NewNode().Public())
	c.recordNodeSentBytes(23)
	completed := s.rotateNodeTraffic(time.Now())
	c.recordNodeReceivedBytes(29)

	recorder := httptest.NewRecorder()
	s.ServeDebugTraffik(recorder, httptest.NewRequest("GET", "/debug/traffik", nil))
	if got, want := recorder.Header().Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	var response struct {
		LastPeriod    *NodeTrafficSnapshot `json:"lastPeriod"`
		CurrentPeriod NodeTrafficSnapshot  `json:"currentPeriod"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.LastPeriod == nil || len(response.LastPeriod.Nodes) != 1 {
		t.Fatalf("last period = %+v, want one node", response.LastPeriod)
	}
	if response.LastPeriod.Nodes[0].SentBytes != 23 {
		t.Errorf("last sent bytes = %d, want 23", response.LastPeriod.Nodes[0].SentBytes)
	}
	if response.LastPeriod.Start != completed.Start || response.LastPeriod.End != completed.End {
		t.Errorf("last period range = [%v, %v), want [%v, %v)", response.LastPeriod.Start, response.LastPeriod.End, completed.Start, completed.End)
	}
	current := trafficByNode(response.CurrentPeriod)
	if traffic := current[c.key]; traffic.SentBytes != 0 || traffic.ReceivedBytes != 29 {
		t.Errorf("current traffic = %+v, want sent=0 received=29", traffic)
	}
}

func TestRunNodeTrafficMetricsRejectsInvalidPeriod(t *testing.T) {
	s := New(key.NewNode(), logger.Discard)
	defer s.Close()
	if err := s.RunNodeTrafficMetrics(t.Context(), 0, nil); err == nil {
		t.Fatal("RunNodeTrafficMetrics with zero period succeeded")
	}
}

func TestRunNodeTrafficMetricsEmitsPeriod(t *testing.T) {
	s := New(key.NewNode(), logger.Discard)
	defer s.Close()
	c := registerTrafficTestClient(s, key.NewNode().Public())
	c.recordNodeSentBytes(31)

	ctx, cancel := context.WithCancel(t.Context())
	emitted := make(chan NodeTrafficSnapshot, 2)
	done := make(chan error, 1)
	go func() {
		done <- s.RunNodeTrafficMetrics(ctx, time.Millisecond, func(snapshot NodeTrafficSnapshot) {
			select {
			case emitted <- snapshot:
			default:
			}
		})
	}()

	select {
	case snapshot := <-emitted:
		traffic := trafficByNode(snapshot)[c.key]
		if traffic.SentBytes != 31 || traffic.ReceivedBytes != 0 {
			t.Errorf("emitted traffic = %+v, want sent=31 received=0", traffic)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for traffic period")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out stopping traffic metrics")
	}
}

func TestNodeTrafficMetricsConcurrentRotation(t *testing.T) {
	s := New(key.NewNode(), logger.Discard)
	defer s.Close()
	c := registerTrafficTestClient(s, key.NewNode().Public())

	const (
		writers    = 8
		iterations = 10_000
	)
	var writersDone sync.WaitGroup
	writersDone.Add(writers)
	for range writers {
		go func() {
			defer writersDone.Done()
			for range iterations {
				c.recordNodeSentBytes(1)
				c.recordNodeReceivedBytes(2)
			}
		}()
	}

	var sent, received uint64
	addSnapshot := func(snapshot NodeTrafficSnapshot) {
		traffic := trafficByNode(snapshot)[c.key]
		sent += traffic.SentBytes
		received += traffic.ReceivedBytes
	}
	for range 100 {
		addSnapshot(s.rotateNodeTraffic(time.Now()))
	}
	writersDone.Wait()

	// Race disconnection against the final rotation. Whichever gets the
	// server lock first must leave the remaining bytes available to rotation.
	unregistered := make(chan struct{})
	go func() {
		s.unregisterClient(c)
		close(unregistered)
	}()
	addSnapshot(s.rotateNodeTraffic(time.Now()))
	<-unregistered
	addSnapshot(s.rotateNodeTraffic(time.Now()))

	if want := uint64(writers * iterations); sent != want {
		t.Errorf("total sent bytes = %d, want %d", sent, want)
	}
	if want := uint64(writers * iterations * 2); received != want {
		t.Errorf("total received bytes = %d, want %d", received, want)
	}
}
