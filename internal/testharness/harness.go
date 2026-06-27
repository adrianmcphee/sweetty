// Package testharness drives a fake protocol end to end over an in-memory pipe
// and lets a test inspect both the bytes sent on the wire and the structured
// events captured to the log. It is the backbone of the verification suite: a
// test connects as the attacker, scripts an interaction, and asserts on what the
// honeypot said and what it recorded.
package testharness

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"time"

	"sweetty/internal/event"
	"sweetty/internal/server"
)

// Harness is one in-memory connection to a running protocol, or (in listener mode)
// a real TCP listener a client dials itself.
type Harness struct {
	Client   net.Conn
	listener net.Listener
	logPath  string
	logger   *event.Logger
}

// New starts proto over a net.Pipe and returns a harness whose Client is the
// attacker end. server.FastMode is enabled so multi-minute tarpits do not stall
// the test. Call Close when done.
func New(proto server.Protocol) (*Harness, error) {
	server.SetFastMode(true)
	f, err := os.CreateTemp("", "sweetty-harness-*.log")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	f.Close()
	lg, err := event.New(path)
	if err != nil {
		return nil, err
	}
	clientConn, serverConn := net.Pipe()
	go server.RunConn(serverConn, lg, proto)
	return &Harness{Client: clientConn, logPath: path, logger: lg}, nil
}

// NewListener starts proto on a real TCP loopback listener and returns a harness
// whose Addr a client dials itself. It exists for protocols (SSH) whose handshake
// writes from both ends at once and so cannot run over the synchronous, unbuffered
// net.Pipe that New uses; turn-based protocols are fine on New. Unlike New it does
// not pre-open a Client. The event-log helpers (Entries, HasEvent, WaitEvent, ...)
// work identically. server.FastMode is enabled so tarpits/time-wasters do not stall.
func NewListener(proto server.Protocol) (*Harness, error) {
	server.SetFastMode(true)
	f, err := os.CreateTemp("", "sweetty-harness-*.log")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	f.Close()
	lg, err := event.New(path)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		lg.Close()
		os.Remove(path)
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed on Close
			}
			go server.RunConn(conn, lg, proto)
		}
	}()
	return &Harness{listener: ln, logPath: path, logger: lg}, nil
}

// Addr is the dial address of a listener-mode harness, or "" for a pipe harness.
func (h *Harness) Addr() string {
	if h.listener != nil {
		return h.listener.Addr().String()
	}
	return ""
}

func (h *Harness) Close() {
	if h.Client != nil {
		h.Client.Close()
	}
	if h.listener != nil {
		h.listener.Close()
	}
	h.logger.Close()
	os.Remove(h.logPath)
}

// Send writes raw text to the server.
func (h *Harness) Send(s string) { h.Client.Write([]byte(s)) }

// SendBytes writes raw bytes to the server.
func (h *Harness) SendBytes(b []byte) { h.Client.Write(b) }

// SendLine writes a line terminated with CRLF (as a telnet/line client would).
func (h *Harness) SendLine(s string) { h.Client.Write([]byte(s + "\r\n")) }

// ReadFor collects bytes until the server falls idle, bounded by d. Once output
// has started, two consecutive empty read windows (~80ms) mean the server has
// finished this burst and is blocked on the next read, so it returns early
// instead of waiting out the full deadline. This is safe because the harness runs
// with server.FastMode, which makes every banner/output write a single burst with
// no mid-output sleeps; d stays the hard upper bound for output that never starts.
func (h *Harness) ReadFor(d time.Duration) string {
	deadline := time.Now().Add(d)
	var sb strings.Builder
	buf := make([]byte, 4096)
	idle := 0
	for time.Now().Before(deadline) {
		h.Client.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
		n, err := h.Client.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			idle = 0
		} else if err != nil && isTimeout(err) && sb.Len() > 0 {
			idle++
			if idle >= 2 {
				return sb.String()
			}
		}
		if err != nil && !isTimeout(err) {
			break
		}
	}
	return sb.String()
}

// ReadUntil collects bytes until substr appears or d elapses. The bool reports
// whether substr was seen.
func (h *Harness) ReadUntil(substr string, d time.Duration) (string, bool) {
	deadline := time.Now().Add(d)
	var sb strings.Builder
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		h.Client.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
		n, err := h.Client.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if strings.Contains(sb.String(), substr) {
				return sb.String(), true
			}
		}
		if err != nil && !isTimeout(err) {
			break
		}
	}
	return sb.String(), false
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// Entries parses every event captured so far from the log file.
func (h *Harness) Entries() []event.Entry {
	data, _ := os.ReadFile(h.logPath)
	var out []event.Entry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e event.Entry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// HasEvent reports whether any captured event has the given type.
func (h *Harness) HasEvent(name string) bool {
	for _, e := range h.Entries() {
		if e.Event == name {
			return true
		}
	}
	return false
}

// FindEvent returns the first captured event of the given type, or false.
func (h *Harness) FindEvent(name string) (event.Entry, bool) {
	for _, e := range h.Entries() {
		if e.Event == name {
			return e, true
		}
	}
	return event.Entry{}, false
}

// WaitEvent polls the log until an event of the given type appears or d elapses,
// so a test is not racing the moment the server writes the line.
func (h *Harness) WaitEvent(name string, d time.Duration) (event.Entry, bool) {
	deadline := time.Now().Add(d)
	for {
		if e, ok := h.FindEvent(name); ok {
			return e, true
		}
		if time.Now().After(deadline) {
			return event.Entry{}, false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// Commands returns the command strings captured as COMMAND events.
func (h *Harness) Commands() []string {
	var out []string
	for _, e := range h.Entries() {
		if e.Event == "COMMAND" {
			out = append(out, e.Command)
		}
	}
	return out
}
