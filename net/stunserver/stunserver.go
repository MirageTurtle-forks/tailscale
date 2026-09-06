// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package stunserver implements a STUN server. The package publishes a number of stats
// to expvar under the top level label "stun". Logs are sent to the standard log package.
package stunserver

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"time"

	"tailscale.com/metrics"
	"tailscale.com/net/stun"
)

var (
	stats           = metrics.NewSet("stun")
	stunDisposition = stats.NewLabelMap("counter_requests", "disposition")
	stunAddrFamily  = stats.NewLabelMap("counter_addrfamily", "family")
	stunReadError   = stunDisposition.Get("read_error")
	stunNotSTUN     = stunDisposition.Get("not_stun")
	stunWriteError  = stunDisposition.Get("write_error")
	stunSuccess     = stunDisposition.Get("success")

	stunIPv4 = stunAddrFamily.Get("ipv4")
	stunIPv6 = stunAddrFamily.Get("ipv6")
)

type STUNServer struct {
	ctx          context.Context // ctx signals service shutdown
	pc           *net.UDPConn    // pc is the UDP listener
	eventHandler func(Event)
}

// EventStatus describes the terminal result of processing a STUN server event.
type EventStatus string

const (
	EventStatusSuccess        EventStatus = "success"
	EventStatusNotSTUN        EventStatus = "not_stun"
	EventStatusInvalidRequest EventStatus = "invalid_request"
	EventStatusReadError      EventStatus = "read_error"
	EventStatusWriteError     EventStatus = "write_error"
)

// Event contains one raw STUN server event. RequestIP and RequestPort identify
// the source observed by the server. MappedIP and MappedPort are returned to the
// requester. ServerIP and ServerPort identify the listener; ServerIP may be
// unspecified when the server listens on all interfaces.
type Event struct {
	EventType     string      `json:"event_type"`
	Time          time.Time   `json:"time"`
	RequestIP     netip.Addr  `json:"request_ip,omitzero"`
	RequestPort   uint16      `json:"request_port,omitempty"`
	ServerIP      netip.Addr  `json:"server_ip,omitzero"`
	ServerPort    uint16      `json:"server_port,omitempty"`
	MappedIP      netip.Addr  `json:"mapped_ip,omitzero"`
	MappedPort    uint16      `json:"mapped_port,omitempty"`
	AddressFamily string      `json:"address_family,omitempty"`
	TransactionID string      `json:"transaction_id,omitempty"`
	RequestBytes  int         `json:"request_bytes,omitempty"`
	ResponseBytes int         `json:"response_bytes,omitempty"`
	Status        EventStatus `json:"status"`
	Error         string      `json:"error,omitempty"`
}

// New creates a new STUN server. The server is shutdown when ctx is done.
func New(ctx context.Context) *STUNServer {
	return &STUNServer{ctx: ctx}
}

// SetEventHandler configures h to receive one synchronous callback for every
// UDP datagram processed by the server and every non-terminal socket read
// error. It must be called before Serve. A slow handler applies backpressure to
// STUN processing.
func (s *STUNServer) SetEventHandler(h func(Event)) {
	s.eventHandler = h
}

func (s *STUNServer) emitEvent(e Event) {
	if s.eventHandler != nil {
		s.eventHandler(e)
	}
}

func (s *STUNServer) serverAddrPort() netip.AddrPort {
	if s.pc == nil {
		return netip.AddrPort{}
	}
	return s.pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (s *STUNServer) newEvent() Event {
	serverAddr := s.serverAddrPort()
	return Event{
		EventType:  "stun",
		Time:       time.Now().UTC(),
		ServerIP:   serverAddr.Addr(),
		ServerPort: serverAddr.Port(),
	}
}

// Listen binds the listen socket for the server at listenAddr.
func (s *STUNServer) Listen(listenAddr string) error {
	uaddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	s.pc, err = net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	log.Printf("STUN server listening on %v", s.LocalAddr())
	// close the listener on shutdown in order to break out of the read loop
	go func() {
		<-s.ctx.Done()
		s.pc.Close()
	}()
	return nil
}

// Serve starts serving responses to STUN requests. Listen must be called before Serve.
func (s *STUNServer) Serve() error {
	var buf [64 << 10]byte
	var (
		n   int
		ua  *net.UDPAddr
		err error
	)
	for {
		n, ua, err = s.pc.ReadFromUDP(buf[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			event := s.newEvent()
			event.Status = EventStatusReadError
			event.Error = err.Error()
			s.emitEvent(event)
			log.Printf("STUN ReadFrom: %v", err)
			time.Sleep(time.Second)
			stunReadError.Add(1)
			continue
		}
		event := s.newEvent()
		requestAddr := ua.AddrPort()
		event.RequestIP = requestAddr.Addr()
		event.RequestPort = requestAddr.Port()
		event.RequestBytes = n
		if ua.IP.To4() != nil {
			event.AddressFamily = "ipv4"
		} else {
			event.AddressFamily = "ipv6"
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			stunNotSTUN.Add(1)
			event.Status = EventStatusNotSTUN
			s.emitEvent(event)
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			stunNotSTUN.Add(1)
			event.Status = EventStatusInvalidRequest
			event.Error = err.Error()
			s.emitEvent(event)
			continue
		}
		event.TransactionID = hex.EncodeToString(txid[:])
		if ua.IP.To4() != nil {
			stunIPv4.Add(1)
		} else {
			stunIPv6.Add(1)
		}
		addr, _ := netip.AddrFromSlice(ua.IP)
		mappedAddr := netip.AddrPortFrom(addr, uint16(ua.Port))
		event.MappedIP = mappedAddr.Addr()
		event.MappedPort = mappedAddr.Port()
		res := stun.Response(txid, mappedAddr)
		event.ResponseBytes = len(res)
		_, err = s.pc.WriteTo(res, ua)
		if err != nil {
			stunWriteError.Add(1)
			event.Status = EventStatusWriteError
			event.Error = err.Error()
		} else {
			stunSuccess.Add(1)
			event.Status = EventStatusSuccess
		}
		s.emitEvent(event)
	}
}

// ListenAndServe starts the STUN server on listenAddr.
func (s *STUNServer) ListenAndServe(listenAddr string) error {
	if err := s.Listen(listenAddr); err != nil {
		return err
	}
	return s.Serve()
}

// LocalAddr returns the local address of the STUN server. It must not be called before ListenAndServe.
func (s *STUNServer) LocalAddr() net.Addr {
	return s.pc.LocalAddr()
}
