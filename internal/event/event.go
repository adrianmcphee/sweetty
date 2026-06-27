// Package event owns the structured event log: the on-disk JSON schema and the
// Logger that stamps, serializes, and writes each event while echoing a compact
// human summary to stdout. The Entry struct is the single source of truth for the
// log schema, so an event can never silently lose a field.
package event

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"sweetty/internal/util"
)

// Entry is the structured shape of every event. All fields are optional via
// omitempty except time/event/ip/port, so each event carries only what is
// relevant. The struct is the single source of truth for the log schema; keeping
// it typed (rather than a free-form map) means an event can never silently lose a
// field.
type Entry struct {
	Time       string            `json:"time"`     // RFC3339 UTC
	EpochMs    int64             `json:"epoch_ms"` // milliseconds since epoch
	Event      string            `json:"event"`
	Session    string            `json:"session,omitempty"` // per-connection id
	Sensor     string            `json:"sensor,omitempty"`  // honeypot host name
	IP         string            `json:"ip"`                // remote "ip:port"
	SrcIP      string            `json:"src_ip,omitempty"`  // remote ip only
	DstIP      string            `json:"dst_ip,omitempty"`  // local ip
	Port       int               `json:"port"`              // listener port
	Protocol   string            `json:"protocol,omitempty"`
	Persona    string            `json:"persona,omitempty"`
	Username   string            `json:"username,omitempty"`
	Password   string            `json:"password,omitempty"`
	Command    string            `json:"command,omitempty"`
	Request    string            `json:"request,omitempty"` // HTTP request line
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
	Body       string            `json:"body,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	URL        string            `json:"url,omitempty"`
	Host       string            `json:"host,omitempty"`
	Filename   string            `json:"filename,omitempty"`
	SHA256     string            `json:"sha256,omitempty"` // hash of an in-band payload
	DurationMs int64             `json:"duration_ms,omitempty"`
	CmdCount   int               `json:"cmd_count,omitempty"`
	Data       string            `json:"data,omitempty"` // raw / misc
	Note       string            `json:"note,omitempty"` // analyst annotation
	Message    string            `json:"message,omitempty"`
}

type Logger struct {
	file    *os.File
	sensor  string
	mu      sync.Mutex
	dropped int  // events lost to write errors (disk full, broken fd)
	warned  bool // a write failure has been reported to stderr once
}

func New(path string) (*Logger, error) {
	// 0600: the log captures attacker credentials, commands, and payloads, so it
	// must not be world-readable to other local users on the sensor host.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	return &Logger{file: f, sensor: host}, nil
}

// Close closes the underlying file under the lock and nils it, so a Log call that
// races shutdown sees a nil file and no-ops cleanly instead of writing to a closed
// descriptor and raising a false "events are being dropped" alarm.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.file
	l.file = nil
	if f == nil {
		return nil
	}
	return f.Close()
}

// Log stamps, marshals, and writes one event under the lock, then prints a
// compact human summary to stdout. json.Marshal escapes control bytes, so a
// newline embedded in a captured field cannot forge a second log line.
func (l *Logger) Log(e Entry) {
	now := time.Now().UTC()
	e.Time = now.Format(time.RFC3339)
	e.EpochMs = now.UnixMilli()
	if e.Sensor == "" {
		e.Sensor = l.sensor
	}
	if e.Message == "" {
		e.Message = summaryDetail(e)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	if l.file != nil {
		if _, werr := l.file.Write(append(data, '\n')); werr != nil {
			// The log is the product, so a silently-dropped event is the worst
			// failure mode. Count every loss and surface the first one to stderr
			// (where an operator or systemd journal will see it) without spamming.
			l.dropped++
			if !l.warned {
				l.warned = true
				fmt.Fprintf(os.Stderr, "event log write failed; events are now being dropped: %v\n", werr)
			}
		}
	}
	l.mu.Unlock()
	// The file write is the integrity-critical part and is done under the lock; the
	// console echo is not, so print it after unlocking. Holding the global log mutex
	// across a Printf would let a blocked stdout sink (a full pipe, a stalled reader)
	// stall every other session's logging behind it. e is a local copy, so reading
	// its fields here races nothing.
	fmt.Printf("[%s] %-21s %-16s %s\n", e.Time[11:19], e.IP, e.Event, util.SanitizeDisplay(e.Message))
}

func summaryDetail(e Entry) string {
	switch {
	case e.Command != "":
		return e.Command
	case e.Username != "" && e.Password != "":
		return e.Username + " / " + e.Password
	case e.Username != "":
		return "user=" + e.Username
	case e.URL != "":
		return e.URL
	case e.Request != "":
		return e.Request
	case e.Path != "":
		return e.Path
	case e.Event == "SESSION_END":
		return strconv.Itoa(e.CmdCount) + " cmds, " + (time.Duration(e.DurationMs) * time.Millisecond).Round(time.Millisecond).String()
	case e.Data != "":
		return e.Data
	default:
		return ""
	}
}

// PortScan logs a bare-connect scan. No session exists yet, so it takes the raw
// remote address.
func (l *Logger) PortScan(remoteAddr string, dstPort int, proto string) {
	l.Log(Entry{
		Event:    "PORT_SCAN",
		IP:       remoteAddr,
		SrcIP:    util.HostOnly(remoteAddr),
		Port:     dstPort,
		Protocol: proto,
	})
}

// System logs an operational notice from the management plane, such as the
// portal loading its country database. It is not attacker activity; it exists so
// operator-facing messages land in the same stream the dashboard already tails.
func (l *Logger) System(format string, args ...any) {
	l.Log(Entry{Event: "SYSTEM", Message: fmt.Sprintf(format, args...)})
}
