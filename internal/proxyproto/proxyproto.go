// Package proxyproto reads the HAProxy PROXY protocol header (v1 text and v2
// binary) from the front of a connection. When sweetty sits behind an HAProxy
// edge configured with send-proxy, every backend connection is prefixed with
// this header, which carries the address the attacker really connected from. The
// whole value of the sensor is that source intelligence, so the accept loop must
// recover it rather than logging the proxy's loopback address.
//
// The parser only reads; it never dials, writes, or executes. It leaves the
// reader positioned at the first real protocol byte so the emulated service sees
// exactly what the client sent.
package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
)

// Addr carries the original connection endpoints recovered from a header: who
// really connected (Src) and the address they reached (Dst), each as "ip:port".
type Addr struct {
	Src string
	Dst string
}

// v2sig is the 12-byte signature that opens every PROXY protocol v2 header.
var v2sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// Parse reads a PROXY protocol header from br if one is present, leaving br
// positioned at the first real protocol byte. It returns ok=true with the
// recovered endpoints for a TCP header, and ok=false when no header is present
// (the stream is left untouched) or the header carries no usable client address
// (a v1 UNKNOWN line or a v2 LOCAL or non-TCP header, both of which are
// consumed). A header that announces itself but is malformed is an error, since
// a misframed stream cannot be trusted.
func Parse(br *bufio.Reader) (Addr, bool, error) {
	pre, err := br.Peek(1)
	if err != nil {
		return Addr{}, false, err
	}
	switch pre[0] {
	case 'P':
		return parseV1(br)
	case 0x0D:
		return parseV2(br)
	default:
		return Addr{}, false, nil
	}
}

// maxV1Len is the PROXY protocol v1 maximum header length including the trailing
// CRLF (the spec caps it at 107 bytes). Bounding the read matters because every
// other hostile read in the server is byte-capped; without this, a peer that sends
// "PROXY " and then a newline-free stream grows the reader's buffer until the
// process OOMs, held off only by the 5s accept deadline.
const maxV1Len = 107

// readV1Line reads the v1 header line, rejecting anything past the spec's 107-byte
// ceiling instead of buffering an unbounded stream the way bufio.ReadString would.
func readV1Line(br *bufio.Reader) (string, error) {
	var b []byte
	for range maxV1Len {
		c, err := br.ReadByte()
		if err != nil {
			return "", errors.New("proxyproto: truncated v1 header")
		}
		b = append(b, c)
		if c == '\n' {
			return string(b), nil
		}
	}
	return "", errors.New("proxyproto: v1 header exceeds 107 bytes")
}

// parseV1 handles the human-readable v1 line: "PROXY TCP4 src dst sport dport".
func parseV1(br *bufio.Reader) (Addr, bool, error) {
	pre, err := br.Peek(6)
	if err != nil || string(pre) != "PROXY " {
		// A 'P' that does not open the reserved prefix is ordinary traffic.
		return Addr{}, false, nil
	}
	line, err := readV1Line(br)
	if err != nil {
		return Addr{}, false, err
	}
	f := strings.Split(strings.TrimRight(line, "\r\n"), " ")
	// UNKNOWN means the proxy could not determine the source (for example its own
	// health check); the header is valid but carries no client to recover.
	if len(f) >= 2 && f[1] == "UNKNOWN" {
		return Addr{}, false, nil
	}
	if len(f) != 6 || (f[1] != "TCP4" && f[1] != "TCP6") {
		return Addr{}, false, errors.New("proxyproto: malformed v1 header")
	}
	if net.ParseIP(f[2]) == nil || net.ParseIP(f[3]) == nil {
		return Addr{}, false, errors.New("proxyproto: bad v1 address")
	}
	if !validPort(f[4]) || !validPort(f[5]) {
		return Addr{}, false, errors.New("proxyproto: bad v1 port")
	}
	return Addr{Src: net.JoinHostPort(f[2], f[4]), Dst: net.JoinHostPort(f[3], f[5])}, true, nil
}

// parseV2 handles the binary v2 header. Only TCP-over-IP carries a client
// address worth recovering; LOCAL, UNSPEC, and datagram families are consumed
// and reported as no-address so the caller falls back to the direct peer.
func parseV2(br *bufio.Reader) (Addr, bool, error) {
	hdr, err := br.Peek(16)
	if err != nil || !bytes.Equal(hdr[:12], v2sig) {
		// Starts with CR but is not the v2 signature: ordinary traffic.
		return Addr{}, false, nil
	}
	length := int(binary.BigEndian.Uint16(hdr[14:16]))
	full := make([]byte, 16+length)
	if _, err := io.ReadFull(br, full); err != nil {
		return Addr{}, false, errors.New("proxyproto: truncated v2 header")
	}
	verCmd := full[12]
	if verCmd>>4 != 0x2 {
		return Addr{}, false, errors.New("proxyproto: bad v2 version")
	}
	if verCmd&0x0F == 0x0 { // LOCAL: proxy-originated, no client to recover
		return Addr{}, false, nil
	}
	addrs := full[16:]
	switch full[13] {
	case 0x11: // TCP over IPv4
		if len(addrs) < 12 {
			return Addr{}, false, errors.New("proxyproto: short v2 ipv4 block")
		}
		return Addr{
			Src: net.JoinHostPort(net.IP(addrs[0:4]).String(), itoaU16(addrs[8:10])),
			Dst: net.JoinHostPort(net.IP(addrs[4:8]).String(), itoaU16(addrs[10:12])),
		}, true, nil
	case 0x21: // TCP over IPv6
		if len(addrs) < 36 {
			return Addr{}, false, errors.New("proxyproto: short v2 ipv6 block")
		}
		return Addr{
			Src: net.JoinHostPort(net.IP(addrs[0:16]).String(), itoaU16(addrs[32:34])),
			Dst: net.JoinHostPort(net.IP(addrs[16:32]).String(), itoaU16(addrs[34:36])),
		}, true, nil
	default:
		return Addr{}, false, nil // non-TCP family: consumed, no address
	}
}

func itoaU16(b []byte) string { return strconv.Itoa(int(binary.BigEndian.Uint16(b))) }

func validPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= 65535
}
