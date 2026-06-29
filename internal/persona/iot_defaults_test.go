package persona

import (
	"testing"
	"time"
)

// TestApplianceAcceptsDefaultCredsFast checks an IoT/appliance persona admits a
// known factory default for root on the first try, while a non-default password
// still has to earn it through the brute-force gate and a non-existent account is
// rejected outright.
func TestApplianceAcceptsDefaultCredsFast(t *testing.T) {
	p := GenerateProfile("legacy")
	if p.Profile != "legacy" {
		t.Fatalf("expected an appliance (legacy) persona, got %q", p.Profile)
	}
	p.SetBruteForce(BruteForceConfig{Enabled: true, AfterTries: 4, After: 45 * time.Second, Probability: 0.4})

	if ok, bf := p.AcceptFrom("1.2.3.4", "root", "vizxv"); !ok || bf {
		t.Fatalf("appliance should accept root/vizxv outright (ok=%v bruteForced=%v)", ok, bf)
	}
	if ok, _ := p.AcceptFrom("5.6.7.8", "root", "not-a-factory-default"); ok {
		t.Fatal("a non-default password must not be accepted on the first try")
	}
	if ok, _ := p.AcceptFrom("9.9.9.9", "admin", "admin"); ok {
		t.Fatal("admin is not an account on this persona; must not be accepted")
	}
}

// TestServerPersonaRejectsIoTDefaults checks a server persona does not hand out a
// shell for IoT default creds (that would be a tell on a server), while the real
// per-instance password still works.
func TestServerPersonaRejectsIoTDefaults(t *testing.T) {
	p := GenerateProfile("web")
	p.SetBruteForce(BruteForceConfig{Enabled: true, AfterTries: 4, After: 45 * time.Second, Probability: 0.4})

	if ok, _ := p.AcceptFrom("1.2.3.4", "root", "vizxv"); ok {
		t.Fatal("a server persona must not accept IoT default creds outright")
	}
	if ok, bf := p.AcceptFrom("1.2.3.4", "root", p.RootPassword); !ok || bf {
		t.Fatalf("the real root password must always work (ok=%v bruteForced=%v)", ok, bf)
	}
}
