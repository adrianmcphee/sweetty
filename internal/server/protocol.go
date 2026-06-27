package server

// Protocol is implemented by every fake service. Handle owns the connection for
// its whole lifetime. Name is used in logs and startup output. ClientFirst
// reports whether the client is expected to send data before the server speaks:
// true for request/response protocols (HTTP), false for banner-first protocols
// (telnet, SSH, FTP). The server uses it to decide how to detect bare-connect
// port scans without misclassifying a client that is simply waiting for a banner.
type Protocol interface {
	Name() string
	ClientFirst() bool
	Handle(s *Session)
}
