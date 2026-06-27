package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func parse(t *testing.T, data []byte) (Addr, bool, error) {
	t.Helper()
	return Parse(bufio.NewReader(bytes.NewReader(data)))
}

// TestV1Recovers proves the human-readable v1 header yields the real client and
// destination, and that the bytes after the header are left for the protocol.
func TestV1Recovers(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("PROXY TCP4 203.0.113.7 198.51.100.2 56324 443\r\nGET / HTTP/1.1\r\n"))
	a, ok, err := Parse(br)
	if err != nil || !ok {
		t.Fatalf("v1 parse: ok=%v err=%v", ok, err)
	}
	if a.Src != "203.0.113.7:56324" {
		t.Fatalf("src = %q, want 203.0.113.7:56324", a.Src)
	}
	if a.Dst != "198.51.100.2:443" {
		t.Fatalf("dst = %q, want 198.51.100.2:443", a.Dst)
	}
	rest, _ := br.ReadString('\n')
	if rest != "GET / HTTP/1.1\r\n" {
		t.Fatalf("payload after header = %q, want the GET line intact", rest)
	}
}

// TestV2Recovers builds a binary v2 TCP4 header and proves the same recovery.
func TestV2Recovers(t *testing.T) {
	var b bytes.Buffer
	b.Write(v2sig)
	b.WriteByte(0x21) // version 2, command PROXY
	b.WriteByte(0x11) // AF_INET + STREAM (TCP4)
	binary.Write(&b, binary.BigEndian, uint16(12))
	b.Write([]byte{192, 0, 2, 9})                     // src ip
	b.Write([]byte{198, 51, 100, 2})                  // dst ip
	binary.Write(&b, binary.BigEndian, uint16(40000)) // src port
	binary.Write(&b, binary.BigEndian, uint16(22))    // dst port
	b.WriteString("SSH-2.0-libssh\r\n")

	br := bufio.NewReader(&b)
	a, ok, err := Parse(br)
	if err != nil || !ok {
		t.Fatalf("v2 parse: ok=%v err=%v", ok, err)
	}
	if a.Src != "192.0.2.9:40000" || a.Dst != "198.51.100.2:22" {
		t.Fatalf("v2 endpoints = %q / %q", a.Src, a.Dst)
	}
	if rest, _ := br.ReadString('\n'); rest != "SSH-2.0-libssh\r\n" {
		t.Fatalf("payload after v2 header = %q", rest)
	}
}

// TestNoHeaderUntouched proves ordinary traffic that happens to start with 'P'
// or a carriage return is not consumed and reports no header.
func TestNoHeaderUntouched(t *testing.T) {
	for _, in := range []string{"PASS secret\r\n", "PING\r\n", "\r\nhello", "USER root\r\n"} {
		br := bufio.NewReader(strings.NewReader(in))
		_, ok, err := Parse(br)
		if err != nil || ok {
			t.Fatalf("%q: expected no header, got ok=%v err=%v", in, ok, err)
		}
		all, _ := br.ReadString('\n')
		if all != firstLine(in) {
			t.Fatalf("%q: stream was consumed, first line read back as %q", in, all)
		}
	}
}

// TestV1UnknownIsNoAddress proves a valid UNKNOWN line is consumed but yields no
// client, so the caller keeps the direct peer address.
func TestV1UnknownIsNoAddress(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("PROXY UNKNOWN\r\npayload"))
	_, ok, err := Parse(br)
	if err != nil || ok {
		t.Fatalf("UNKNOWN: ok=%v err=%v, want consumed with no address", ok, err)
	}
	if rest, _ := br.ReadString('d'); rest != "payload" {
		t.Fatalf("UNKNOWN header not consumed, read %q", rest)
	}
}

// TestMalformedV1IsError proves a line that announces PROXY but does not parse is
// rejected rather than silently trusted.
func TestMalformedV1IsError(t *testing.T) {
	for _, in := range []string{"PROXY TCP4 999.0.0.1 1.2.3.4 1 2\r\n", "PROXY TCP4 1.2.3.4\r\n", "PROXY TCP4 1.2.3.4 5.6.7.8 70000 2\r\n"} {
		if _, ok, err := parse(t, []byte(in)); err == nil || ok {
			t.Fatalf("%q: expected error, got ok=%v err=%v", in, ok, err)
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i+1]
	}
	return s
}
