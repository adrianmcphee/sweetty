package server

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// TestHoldOpenReleasesOnDisconnect proves a tarpit hold ends the instant the client
// goes away, so a connect/disconnect storm cannot pin goroutines and file
// descriptors for the full multi-minute duration. HoldOpen is asked to hold for ten
// minutes but must return within a moment of the client closing.
func TestHoldOpenReleasesOnDisconnect(t *testing.T) {
	prev := FastMode()
	SetFastMode(false)
	defer func() { SetFastMode(prev) }()

	client, srv := net.Pipe()
	defer srv.Close()
	s := &Session{conn: srv, reader: bufio.NewReader(srv), IdleTimeout: time.Minute}

	done := make(chan struct{})
	go func() {
		s.HoldOpen(10 * time.Minute)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond) // let HoldOpen enter its blocking read
	client.Close()                    // the attacker disconnects

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HoldOpen did not return after the client disconnected: resources stay pinned for the whole tarpit")
	}
}

// TestHoldOpenFastModeReturnsImmediately proves the test seam short-circuits the
// hold so the suite never stalls on a real multi-minute tarpit.
func TestHoldOpenFastModeReturnsImmediately(t *testing.T) {
	prev := FastMode()
	SetFastMode(true)
	defer func() { SetFastMode(prev) }()

	client, srv := net.Pipe()
	defer client.Close()
	defer srv.Close()
	s := &Session{conn: srv, reader: bufio.NewReader(srv), IdleTimeout: time.Minute}

	done := make(chan struct{})
	go func() {
		s.HoldOpen(10 * time.Minute)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HoldOpen did not honour FastMode")
	}
}
