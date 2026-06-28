package geo

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScopeClassification locks the builtin classifier against the special-use
// ranges that show up in honeypot traffic. These are facts about the address
// itself, so they must be exact and never depend on a database.
func TestScopeClassification(t *testing.T) {
	r := NewResolver()
	cases := []struct {
		ip, scope string
	}{
		{"0.0.0.0", "unspecified"},
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"10.1.2.3", "private"},
		{"172.16.5.5", "private"},
		{"192.168.1.1", "private"},
		{"fc00::1", "private"},
		{"100.64.0.1", "cgnat"},
		{"169.254.1.1", "linklocal"},
		{"fe80::1", "linklocal"},
		{"224.0.0.1", "multicast"},
		{"ff02::1", "multicast"},
		{"192.0.2.10", "doc"},
		{"198.51.100.10", "doc"},
		{"203.0.113.10", "doc"},
		{"2001:db8::1", "doc"},
		{"198.18.0.1", "reserved"},
		{"240.0.0.1", "reserved"},
		{"8.8.8.8", "global"},
		{"1.1.1.1", "global"},
		{"2606:4700::1", "global"},
		{"not-an-ip", "invalid"},
		{"", "invalid"},
	}
	for _, c := range cases {
		if got := r.Locate(c.ip).Scope; got != c.scope {
			t.Errorf("Locate(%q).Scope = %q, want %q", c.ip, got, c.scope)
		}
	}
}

// TestNoCountryWithoutDatabase proves a global address resolves to a scope but
// no country until an operator loads a database, and never invents one.
func TestNoCountryWithoutDatabase(t *testing.T) {
	r := NewResolver()
	loc := r.Locate("8.8.8.8")
	if loc.Country != "" || loc.Source != "" {
		t.Fatalf("country resolved with no database loaded: %+v", loc)
	}
	if r.Loaded() != 0 {
		t.Fatalf("Loaded() = %d with no database", r.Loaded())
	}
}

// TestCountryLookupRangeForm loads the start,end,country form and proves a
// binary-search lookup lands in the right range, with addresses just outside a
// range resolving to no country.
func TestCountryLookupRangeForm(t *testing.T) {
	csv := "# free country db, range form\n" +
		"1.0.0.0,1.0.0.255,AU\n" +
		"8.8.8.0,8.8.8.255,US\n" +
		"81.2.69.0,81.2.69.255,GB\n"
	r := loadFromString(t, csv)
	if n := r.Loaded(); n != 3 {
		t.Fatalf("Loaded() = %d, want 3", n)
	}
	check := func(ip, want string) {
		t.Helper()
		loc := r.Locate(ip)
		if loc.Country != want {
			t.Fatalf("Locate(%q).Country = %q, want %q", ip, loc.Country, want)
		}
		if want != "" && loc.Source != "db" {
			t.Fatalf("Locate(%q).Source = %q, want db", ip, loc.Source)
		}
	}
	check("8.8.8.8", "US")
	check("1.0.0.50", "AU")
	check("81.2.69.142", "GB")
	check("9.9.9.9", "")   // above every range
	check("8.8.7.255", "") // one below the US range
	check("8.8.9.0", "")   // one above the US range
}

// TestCountryLookupIntegerAndCIDRForms proves the integer range form and the
// cidr,country form both load and resolve, since the free databases ship both.
func TestCountryLookupIntegerAndCIDRForms(t *testing.T) {
	// 8.8.8.0 = 134744064, 8.8.8.255 = 134744319.
	intForm := "134744064,134744319,US\n"
	if got := loadFromString(t, intForm).Locate("8.8.8.8").Country; got != "US" {
		t.Fatalf("integer form: Locate(8.8.8.8).Country = %q, want US", got)
	}
	cidrForm := "1.0.0.0/24,AU\n203.0.113.0/24,ZZ\n"
	r := loadFromString(t, cidrForm)
	if got := r.Locate("1.0.0.7").Country; got != "AU" {
		t.Fatalf("cidr form: Locate(1.0.0.7).Country = %q, want AU", got)
	}
	// 203.0.113.0/24 is a documentation block: scope wins over any country row,
	// since it can never be a real source.
	if loc := r.Locate("203.0.113.9"); loc.Scope != "doc" || loc.Country != "" {
		t.Fatalf("doc range should not carry a country: %+v", loc)
	}
}

// TestMalformedRowsAreSkipped proves a header line and a junk row do not abort
// the load: the good rows around them still resolve.
func TestMalformedRowsAreSkipped(t *testing.T) {
	csv := "start,end,country\n" + // header, not an IP
		"garbage-without-enough-columns\n" +
		"8.8.8.0,8.8.8.255,US\n" +
		"1.0.0.0,1.0.0.255,toolong\n" // bad country code
	r := loadFromString(t, csv)
	if n := r.Loaded(); n != 1 {
		t.Fatalf("Loaded() = %d, want 1 (only the US row is valid)", n)
	}
	if got := r.Locate("8.8.8.8").Country; got != "US" {
		t.Fatalf("Locate(8.8.8.8).Country = %q, want US", got)
	}
}

// TestRecoverableCsvErrorDoesNotTruncate proves a single malformed row (a stray
// quote that makes encoding/csv return a parse error) does not discard the rest
// of the database: the good rows both before and after it still resolve.
func TestRecoverableCsvErrorDoesNotTruncate(t *testing.T) {
	body := "1.0.0.0,1.0.0.255,AU\n" +
		"8.8.8.0,8.8.8.\"5,US\n" + // stray quote: a recoverable csv parse error
		"81.2.69.0,81.2.69.255,GB\n"
	r := loadFromString(t, body)
	if got := r.Locate("1.0.0.50").Country; got != "AU" {
		t.Fatalf("row before the bad line was lost: %q", got)
	}
	if got := r.Locate("81.2.69.10").Country; got != "GB" {
		t.Fatalf("row after the bad line was truncated: %q", got)
	}
}

func loadFromString(t *testing.T, body string) *Resolver {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geo.csv")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	r := NewResolver()
	if _, err := r.LoadCSV(path); err != nil {
		t.Fatal(err)
	}
	return r
}
