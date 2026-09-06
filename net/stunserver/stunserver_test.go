// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package stunserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/util/must"
)

func TestEventJSON(t *testing.T) {
	event := Event{
		EventType:     "stun",
		Time:          time.Date(2026, 9, 4, 1, 2, 3, 0, time.UTC),
		RequestIP:     netip.MustParseAddr("192.0.2.1"),
		RequestPort:   12345,
		ServerIP:      netip.MustParseAddr("2001:db8::1"),
		ServerPort:    3478,
		MappedIP:      netip.MustParseAddr("192.0.2.1"),
		MappedPort:    12345,
		AddressFamily: "ipv4",
		TransactionID: "00112233445566778899aabb",
		RequestBytes:  40,
		ResponseBytes: 32,
		Status:        EventStatusSuccess,
	}
	b, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"event_type":"stun","time":"2026-09-04T01:02:03Z","request_ip":"192.0.2.1","request_port":12345,"server_ip":"2001:db8::1","server_port":3478,"mapped_ip":"192.0.2.1","mapped_port":12345,"address_family":"ipv4","transaction_id":"00112233445566778899aabb","request_bytes":40,"response_bytes":32,"status":"success"}`
	if string(b) != want {
		t.Fatalf("event JSON = %s, want %s", b, want)
	}
}

func TestSTUNServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx)
	events := make(chan Event, 1)
	s.SetEventHandler(func(event Event) { events <- event })
	must.Do(s.Listen("localhost:0"))
	var w sync.WaitGroup
	w.Add(1)
	var serveErr error
	go func() {
		defer w.Done()
		serveErr = s.Serve()
	}()

	c := must.Get(net.DialUDP("udp", nil, s.LocalAddr().(*net.UDPAddr)))
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	txid := stun.NewTxID()
	_, err := c.Write(stun.Request(txid))
	if err != nil {
		t.Fatalf("failed to write STUN request: %v", err)
	}
	var buf [64 << 10]byte
	n, err := c.Read(buf[:])
	if err != nil {
		t.Fatalf("failed to read STUN response: %v", err)
	}
	if !stun.Is(buf[:n]) {
		t.Fatalf("response is not STUN")
	}
	tid, _, err := stun.ParseResponse(buf[:n])
	if err != nil {
		t.Fatalf("failed to parse STUN response: %v", err)
	}
	if tid != txid {
		t.Fatalf("STUN response has wrong transaction ID; got %d, want %d", tid, txid)
	}

	select {
	case event := <-events:
		if event.EventType != "stun" {
			t.Errorf("event type = %q, want stun", event.EventType)
		}
		if event.Status != EventStatusSuccess {
			t.Errorf("event status = %q, want %q", event.Status, EventStatusSuccess)
		}
		requestAddr := c.LocalAddr().(*net.UDPAddr).AddrPort()
		if event.RequestIP != requestAddr.Addr() || event.RequestPort != requestAddr.Port() {
			t.Errorf("event request address = %v:%d, want %v", event.RequestIP, event.RequestPort, requestAddr)
		}
		serverAddr := s.LocalAddr().(*net.UDPAddr).AddrPort()
		if event.ServerIP != serverAddr.Addr() || event.ServerPort != serverAddr.Port() {
			t.Errorf("event server address = %v:%d, want %v", event.ServerIP, event.ServerPort, serverAddr)
		}
		if event.MappedIP != event.RequestIP || event.MappedPort != event.RequestPort {
			t.Errorf("event mapped address = %v:%d, want request address %v", event.MappedIP, event.MappedPort, requestAddr)
		}
		if event.TransactionID != hex.EncodeToString(txid[:]) {
			t.Errorf("event transaction ID = %q, want %x", event.TransactionID, txid)
		}
		if event.RequestBytes != len(stun.Request(txid)) {
			t.Errorf("event request bytes = %d, want %d", event.RequestBytes, len(stun.Request(txid)))
		}
		if event.ResponseBytes != n {
			t.Errorf("event response bytes = %d, want %d", event.ResponseBytes, n)
		}
		if event.Time.IsZero() {
			t.Error("event time is zero")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for STUN event")
	}

	cancel()
	w.Wait()
	if serveErr != nil {
		t.Fatalf("failed to listen and serve: %v", serveErr)
	}
}

func TestSTUNServerRejectedPacketEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx)
	events := make(chan Event, 1)
	s.SetEventHandler(func(event Event) { events <- event })
	must.Do(s.Listen("localhost:0"))
	go s.Serve()

	c := must.Get(net.DialUDP("udp", nil, s.LocalAddr().(*net.UDPAddr)))
	defer c.Close()
	pkt := []byte("not STUN")
	if _, err := c.Write(pkt); err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-events:
		if event.Status != EventStatusNotSTUN {
			t.Errorf("event status = %q, want %q", event.Status, EventStatusNotSTUN)
		}
		if event.RequestBytes != len(pkt) {
			t.Errorf("event request bytes = %d, want %d", event.RequestBytes, len(pkt))
		}
		requestAddr := c.LocalAddr().(*net.UDPAddr).AddrPort()
		if event.RequestIP != requestAddr.Addr() || event.RequestPort != requestAddr.Port() {
			t.Errorf("event request address = %v:%d, want %v", event.RequestIP, event.RequestPort, requestAddr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for rejected-packet event")
	}

	pkt = stun.Request(stun.NewTxID())
	pkt[len(pkt)-1] ^= 1 // invalidate the fingerprint
	if _, err := c.Write(pkt); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Status != EventStatusInvalidRequest {
			t.Errorf("event status = %q, want %q", event.Status, EventStatusInvalidRequest)
		}
		if event.Error == "" {
			t.Error("invalid-request event has no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for invalid-request event")
	}
}

func BenchmarkServerSTUN(b *testing.B) {
	b.ReportAllocs()
	ctx := b.Context()

	s := New(ctx)
	s.Listen("localhost:0")
	go s.Serve()
	addr := s.LocalAddr().(*net.UDPAddr)

	var resBuf [1500]byte
	cc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}

	tx := stun.NewTxID()
	req := stun.Request(tx)
	for range b.N {
		if _, err := cc.WriteToUDP(req, addr); err != nil {
			b.Fatal(err)
		}
		_, _, err := cc.ReadFromUDP(resBuf[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}
