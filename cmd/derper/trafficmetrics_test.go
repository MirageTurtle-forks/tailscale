// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
)

func TestWriteNodeTrafficLog(t *testing.T) {
	start := time.Date(2026, 9, 4, 1, 2, 3, 0, time.UTC)
	end := start.Add(time.Minute)
	node1 := key.NewNode().Public()
	node2 := key.NewNode().Public()
	snapshot := derpserver.NodeTrafficSnapshot{
		Start: start,
		End:   end,
		Nodes: []derpserver.NodeTraffic{
			{Node: node1, SentBytes: 10, ReceivedBytes: 20},
			{Node: node2, SentBytes: 30, ReceivedBytes: 40},
		},
	}

	var output bytes.Buffer
	if err := writeNodeTrafficLog(json.NewEncoder(&output), snapshot); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&output)
	for i, want := range snapshot.Nodes {
		var got nodeTrafficLogRecord
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("decoding record %d: %v", i, err)
		}
		if got.PeriodStart != start || got.PeriodEnd != end {
			t.Errorf("record period = [%v, %v), want [%v, %v)", got.PeriodStart, got.PeriodEnd, start, end)
		}
		if got.NodeKey != want.Node || got.SentBytes != want.SentBytes || got.ReceivedBytes != want.ReceivedBytes {
			t.Errorf("record traffic = %+v, want %+v", got, want)
		}
	}
	var extra nodeTrafficLogRecord
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("decoding after final record: %v, want EOF", err)
	}
}

func TestWriteNodeTrafficLogEmptyPeriod(t *testing.T) {
	var output bytes.Buffer
	if err := writeNodeTrafficLog(json.NewEncoder(&output), derpserver.NodeTrafficSnapshot{}); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("empty period output = %q, want empty", output.String())
	}
}

func TestNodeTrafficDebugAccess(t *testing.T) {
	s := derpserver.New(key.NewNode(), t.Logf)
	defer s.Close()
	mux := http.NewServeMux()
	registerNodeTrafficDebug(tsweb.Debugger(mux), s)

	for _, test := range []struct {
		name       string
		remoteAddr string
		wantStatus int
	}{
		{name: "public", remoteAddr: "192.0.2.1:1234", wantStatus: http.StatusForbidden},
		{name: "loopback", remoteAddr: "127.0.0.1:1234", wantStatus: http.StatusOK},
		{name: "tailnet", remoteAddr: "100.64.0.1:1234", wantStatus: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest("GET", "/debug/traffik", nil)
			request.RemoteAddr = test.remoteAddr
			mux.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
		})
	}
}
