// Package geo resolves an IP address to a coarse location for the management
// portal's analytics. It runs only in the portal plane, never in the honeypot
// listeners, and it makes no network calls: special-use ranges are classified
// from the address itself, and country resolution is a pure lookup against an
// operator-supplied database loaded once at startup. This keeps the honeypot's
// egress-deny posture intact while still letting an operator see where a planted
// bait was triggered from.
package geo

import (
	"bufio"
	"encoding/csv"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Location is what the resolver knows about an address. Country is an ISO-3166
// alpha-2 code when a country database is loaded and the address falls in a
// known range; it is empty for special-use or unresolved addresses. Scope names
// the address class, so a private or loopback hit reads honestly instead of
// being silently dropped.
type Location struct {
	Scope   string `json:"scope"`             // global, private, loopback, cgnat, linklocal, multicast, reserved, doc, unspecified, invalid
	Country string `json:"country,omitempty"` // ISO alpha-2, empty when unknown
	Source  string `json:"source,omitempty"`  // "db" when from the country database, else ""
}

// specialRanges are the IPv4 and IPv6 blocks the builtin classifier recognizes
// without any database. The stdlib helpers cover loopback, private, link-local,
// multicast, and unspecified; these are the blocks it does not, plus the
// documentation ranges that show up in scans and test traffic.
var specialRanges = []struct {
	prefix netip.Prefix
	scope  string
}{
	{netip.MustParsePrefix("100.64.0.0/10"), "cgnat"},
	{netip.MustParsePrefix("192.0.2.0/24"), "doc"},
	{netip.MustParsePrefix("198.51.100.0/24"), "doc"},
	{netip.MustParsePrefix("203.0.113.0/24"), "doc"},
	{netip.MustParsePrefix("2001:db8::/32"), "doc"},
	{netip.MustParsePrefix("198.18.0.0/15"), "reserved"},  // benchmarking
	{netip.MustParsePrefix("192.0.0.0/24"), "reserved"},   // IETF protocol assignments
	{netip.MustParsePrefix("192.88.99.0/24"), "reserved"}, // 6to4 relay anycast (deprecated)
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},    // future use
	{netip.MustParsePrefix("0.0.0.0/8"), "reserved"},      // "this network"
}

// countryRange is one inclusive IPv4 span mapped to a country, stored as host
// integers so lookup is a binary search.
type countryRange struct {
	start, end uint32
	country    string
}

// Resolver classifies addresses and, when a country database is loaded, maps
// global IPv4 addresses to a country. The zero value is usable and resolves
// only scope; call LoadCSV to add country resolution.
type Resolver struct {
	ranges []countryRange // sorted by start, non-overlapping after load
}

// NewResolver returns a resolver that classifies scope but knows no countries
// until LoadCSV is called.
func NewResolver() *Resolver { return &Resolver{} }

// Locate classifies ip and, for a global IPv4 address with a loaded database,
// fills in the country. An unparseable address resolves to scope "invalid"
// rather than an error, so a malformed log field never breaks the view.
func (r *Resolver) Locate(ip string) Location {
	addr, ok := parseAddr(ip)
	if !ok {
		return Location{Scope: "invalid"}
	}
	switch {
	case addr.IsUnspecified():
		return Location{Scope: "unspecified"}
	case addr.IsLoopback():
		return Location{Scope: "loopback"}
	case addr.IsMulticast():
		return Location{Scope: "multicast"}
	case addr.IsLinkLocalUnicast():
		return Location{Scope: "linklocal"}
	case addr.IsPrivate():
		return Location{Scope: "private"}
	}
	for _, s := range specialRanges {
		if s.prefix.Contains(addr) {
			return Location{Scope: s.scope}
		}
	}
	// Globally routable: resolve a country if the database knows this address.
	loc := Location{Scope: "global"}
	if country, ok := r.country(addr); ok {
		loc.Country = country
		loc.Source = "db"
	}
	return loc
}

// country binary-searches the loaded ranges for a global IPv4 address. IPv6
// country lookup is not supported by the builtin database format, so an IPv6
// address returns no country even when a database is loaded.
func (r *Resolver) country(addr netip.Addr) (string, bool) {
	if len(r.ranges) == 0 || !addr.Is4() {
		return "", false
	}
	v := beUint32(addr.As4())
	// Rightmost range whose start is <= v, then bounds-check its end.
	i := sort.Search(len(r.ranges), func(i int) bool { return r.ranges[i].start > v }) - 1
	if i < 0 {
		return "", false
	}
	if v <= r.ranges[i].end && r.ranges[i].country != "" {
		return r.ranges[i].country, true
	}
	return "", false
}

// Loaded reports how many country ranges are loaded, for an operator-facing
// "database active" signal.
func (r *Resolver) Loaded() int { return len(r.ranges) }

// LoadCSV loads an operator-supplied IPv4 country database and returns the
// number of usable ranges. It accepts the common free formats: a three-column
// "start,end,country" row where start and end are either dotted IPv4 or host
// integers, or a two-column "cidr,country" row. Blank lines, "#" comments, and
// unparseable rows are skipped so a stray header or footer never aborts the
// load. Calling it replaces any previously loaded database.
func (r *Resolver) LoadCSV(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	rd := csv.NewReader(bufio.NewReader(f))
	rd.FieldsPerRecord = -1 // rows vary between the 2- and 3-column forms
	rd.ReuseRecord = true
	rd.TrimLeadingSpace = true

	var ranges []countryRange
	for {
		rec, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A malformed row (bad quoting in one line) is a recoverable csv parse
			// error; skip it and keep loading the rest of the database rather than
			// truncating everything after the first bad line.
			continue
		}
		if cr, ok := parseRecord(rec); ok {
			ranges = append(ranges, cr)
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	r.ranges = ranges
	return len(ranges), nil
}

// parseRecord turns one CSV row into a country range. A two-field row is read
// as cidr,country; any row with three or more fields is read as
// start,end,country.
func parseRecord(rec []string) (countryRange, bool) {
	if len(rec) >= 1 && strings.HasPrefix(strings.TrimSpace(rec[0]), "#") {
		return countryRange{}, false
	}
	switch {
	case len(rec) == 2:
		p, err := netip.ParsePrefix(strings.TrimSpace(rec[0]))
		if err != nil || !p.Addr().Is4() {
			return countryRange{}, false
		}
		cc := country(rec[1])
		if cc == "" {
			return countryRange{}, false
		}
		lo := beUint32(p.Masked().Addr().As4())
		hi := lo | (0xffffffff >> p.Bits())
		return countryRange{start: lo, end: hi, country: cc}, true
	case len(rec) >= 3:
		lo, ok1 := parseBound(rec[0])
		hi, ok2 := parseBound(rec[1])
		cc := country(rec[2])
		if !ok1 || !ok2 || cc == "" || hi < lo {
			return countryRange{}, false
		}
		return countryRange{start: lo, end: hi, country: cc}, true
	}
	return countryRange{}, false
}

// parseBound reads a range bound as either a dotted IPv4 address or a host
// integer, the two forms the common free databases ship.
func parseBound(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(s); err == nil && addr.Is4() {
		return beUint32(addr.As4()), true
	}
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n), true
	}
	return 0, false
}

// country normalizes a country field to an uppercase ISO alpha-2 code, or ""
// when the field is not a two-letter code.
func country(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
		return ""
	}
	return s
}

// parseAddr parses a bare IP or an "ip:port" remote address into a comparable,
// unmapped Addr.
func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

// beUint32 reads four address bytes as a big-endian host integer.
func beUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
