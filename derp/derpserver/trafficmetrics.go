// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"tailscale.com/types/key"
)

// NodeTraffic contains the DERP payload bytes sent and received by one node
// during an accounting period. SentBytes and ReceivedBytes are both from the
// node's perspective.
type NodeTraffic struct {
	Node          key.NodePublic `json:"node"`
	SentBytes     uint64         `json:"sentBytes"`
	ReceivedBytes uint64         `json:"receivedBytes"`
}

// NodeTrafficSnapshot contains per-node traffic for the half-open interval
// [Start, End). Nodes with no traffic during the interval are omitted.
type NodeTrafficSnapshot struct {
	Start time.Time     `json:"start"`
	End   time.Time     `json:"end"`
	Nodes []NodeTraffic `json:"nodes"`
}

type nodeTrafficCounts struct {
	sentBytes     uint64
	receivedBytes uint64
}

// Mesh connections are excluded because their key identifies the peer DERP,
// not an end node. For cross-DERP traffic, the source is counted at the ingress
// DERP and the destination is counted at the egress DERP.
func (c *sclient) recordNodeSentBytes(n int) {
	if n > 0 && !c.canMesh {
		c.nodeSentBytes.Add(uint64(n))
	}
}

func (c *sclient) recordNodeReceivedBytes(n int) {
	if n > 0 && !c.canMesh {
		c.nodeReceivedBytes.Add(uint64(n))
	}
}

// stashNodeTrafficLocked preserves traffic recorded by c before c is removed
// from the server's client map. s.mu must be held.
func (s *Server) stashNodeTrafficLocked(c *sclient) {
	if c.canMesh {
		return
	}
	sent := c.nodeSentBytes.Swap(0)
	received := c.nodeReceivedBytes.Swap(0)
	if sent == 0 && received == 0 {
		return
	}
	if s.nodeTrafficUnregistered == nil {
		s.nodeTrafficUnregistered = map[key.NodePublic]nodeTrafficCounts{}
	}
	total := s.nodeTrafficUnregistered[c.key]
	total.sentBytes += sent
	total.receivedBytes += received
	s.nodeTrafficUnregistered[c.key] = total
}

func addNodeTraffic(m map[key.NodePublic]nodeTrafficCounts, node key.NodePublic, sent, received uint64) {
	if sent == 0 && received == 0 {
		return
	}
	total := m[node]
	total.sentBytes += sent
	total.receivedBytes += received
	m[node] = total
}

// nodeTrafficSnapshotLocked builds a snapshot. If reset is true, it also
// begins a new accounting period. s.mu must be held.
func (s *Server) nodeTrafficSnapshotLocked(end time.Time, reset bool) NodeTrafficSnapshot {
	end = end.UTC()
	start := s.nodeTrafficPeriodStart
	if start.IsZero() {
		start = end
	}

	totals := make(map[key.NodePublic]nodeTrafficCounts, len(s.nodeTrafficUnregistered)+s.numLocalClientKeys)
	for node, total := range s.nodeTrafficUnregistered {
		totals[node] = total
	}
	for _, clients := range s.clients.All() {
		clients.ForeachClient(func(c *sclient) {
			if c.canMesh {
				return
			}
			var sent, received uint64
			if reset {
				sent = c.nodeSentBytes.Swap(0)
				received = c.nodeReceivedBytes.Swap(0)
			} else {
				sent = c.nodeSentBytes.Load()
				received = c.nodeReceivedBytes.Load()
			}
			addNodeTraffic(totals, c.key, sent, received)
		})
	}

	nodes := make([]NodeTraffic, 0, len(totals))
	for node, total := range totals {
		if total.sentBytes == 0 && total.receivedBytes == 0 {
			continue
		}
		nodes = append(nodes, NodeTraffic{
			Node:          node,
			SentBytes:     total.sentBytes,
			ReceivedBytes: total.receivedBytes,
		})
	}
	snapshot := NodeTrafficSnapshot{Start: start.UTC(), End: end, Nodes: nodes}
	if reset {
		s.nodeTrafficPeriodStart = end
		s.nodeTrafficUnregistered = map[key.NodePublic]nodeTrafficCounts{}
		last := cloneNodeTrafficSnapshot(snapshot)
		s.nodeTrafficLast = &last
	}
	return snapshot
}

func cloneNodeTrafficSnapshot(snapshot NodeTrafficSnapshot) NodeTrafficSnapshot {
	snapshot.Nodes = slices.Clone(snapshot.Nodes)
	return snapshot
}

func sortNodeTrafficSnapshot(snapshot *NodeTrafficSnapshot) {
	slices.SortFunc(snapshot.Nodes, func(a, b NodeTraffic) int {
		return a.Node.Compare(b.Node)
	})
}

func (s *Server) rotateNodeTraffic(end time.Time) NodeTrafficSnapshot {
	s.mu.Lock()
	snapshot := s.nodeTrafficSnapshotLocked(end, true)
	s.mu.Unlock()
	sortNodeTrafficSnapshot(&snapshot)
	return snapshot
}

// RunNodeTrafficMetrics rotates the per-node traffic counters every period.
// After each completed period, it calls emit outside the server lock. It must
// be run at most once for a Server. A final, possibly short period is emitted
// when ctx is canceled.
func (s *Server) RunNodeTrafficMetrics(ctx context.Context, period time.Duration, emit func(NodeTrafficSnapshot)) error {
	if period <= 0 {
		return errors.New("node traffic metrics period must be positive")
	}

	s.mu.Lock()
	if s.nodeTrafficRunning {
		s.mu.Unlock()
		return errors.New("node traffic metrics already running")
	}
	s.nodeTrafficRunning = true
	if s.nodeTrafficPeriodStart.IsZero() {
		s.nodeTrafficPeriodStart = time.Now().UTC()
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.nodeTrafficRunning = false
		s.mu.Unlock()
	}()

	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			snapshot := s.rotateNodeTraffic(time.Now())
			if emit != nil {
				emit(snapshot)
			}
		case <-ctx.Done():
			snapshot := s.rotateNodeTraffic(time.Now())
			if emit != nil {
				emit(snapshot)
			}
			return nil
		}
	}
}

// ServeDebugTraffik serves the most recently completed accounting period and
// the current period-to-date as JSON. Access control is applied by tsweb when
// cmd/derper registers this handler below /debug/.
func (s *Server) ServeDebugTraffik(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	s.mu.Lock()
	current := s.nodeTrafficSnapshotLocked(now, false)
	var last *NodeTrafficSnapshot
	if s.nodeTrafficLast != nil {
		cloned := cloneNodeTrafficSnapshot(*s.nodeTrafficLast)
		last = &cloned
	}
	s.mu.Unlock()
	sortNodeTrafficSnapshot(&current)
	if last != nil {
		sortNodeTrafficSnapshot(last)
	}

	response := struct {
		LastPeriod    *NodeTrafficSnapshot `json:"lastPeriod,omitempty"`
		CurrentPeriod NodeTrafficSnapshot  `json:"currentPeriod"`
	}{
		LastPeriod:    last,
		CurrentPeriod: current,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
