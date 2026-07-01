package hosttraffic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Real-ish conntrack lines (with nf_conntrack_acct=1). NATed LAN->internet flow:
// orig src is the LAN host (upload bytes), reply bytes are the download.
const sample = `ipv4     2 tcp      6 111 TIME_WAIT src=192.168.3.35 dst=104.16.9.34 sport=56824 dport=443 packets=276 bytes=44530 src=104.16.9.34 dst=192.168.18.2 sport=443 dport=56824 packets=159 bytes=1676127 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 6 src=192.168.3.18 dst=192.168.3.3 sport=40924 dport=53 packets=1 bytes=60 src=192.168.3.3 dst=192.168.3.18 sport=53 dport=40924 packets=1 bytes=188 mark=0 zone=0 use=2
ipv4     2 tcp      6 104 SYN_SENT src=192.168.3.35 dst=1.2.3.4 sport=46372 dport=80 packets=1 bytes=60 [UNREPLIED] src=1.2.3.4 dst=192.168.18.2 sport=80 dport=46372 mark=0 zone=0 use=2
ipv4     2 tcp      6 100 ESTABLISHED src=8.8.8.8 dst=192.168.18.2 sport=443 dport=1234 packets=1 bytes=500 src=192.168.18.2 dst=8.8.8.8 sport=1234 dport=443 packets=1 bytes=100 mark=0 zone=0 use=2
`

func TestParseConntrack(t *testing.T) {
	got := parseConntrack(sample, "192.168.3.0/24")
	// Hosts .35 and .18 are in the subnet; the 8.8.8.8-origin flow is ignored.
	if len(got) != 2 {
		t.Fatalf("expected 2 LAN hosts, got %d: %+v", len(got), got)
	}
	// Top talker must be .35 (44530+1676127 ≫ .18's 60+188).
	if got[0].IP != "192.168.3.35" {
		t.Fatalf("expected .35 as top talker, got %+v", got[0])
	}
	// .35 aggregates the TIME_WAIT flow (tx 44530, rx 1676127) plus the
	// UNREPLIED SYN (tx +60, no reply bytes).
	if got[0].TxBytes != 44590 || got[0].RxBytes != 1676127 {
		t.Errorf(".35 bytes wrong: tx=%d rx=%d", got[0].TxBytes, got[0].RxBytes)
	}
	if got[1].IP != "192.168.3.18" || got[1].TxBytes != 60 || got[1].RxBytes != 188 {
		t.Errorf(".18 wrong: %+v", got[1])
	}
}

func TestParseConntrackBadSubnet(t *testing.T) {
	if len(parseConntrack(sample, "not-a-cidr")) != 0 {
		t.Error("bad subnet should yield no results")
	}
}

// TestEnsureAccountingEnablesAndPersists is the regression test for the root
// cause of "per-host traffic stopped calculating": nf_conntrack_acct was off.
func TestEnsureAccountingEnablesAndPersists(t *testing.T) {
	dir := t.TempDir()
	acct := filepath.Join(dir, "nf_conntrack_acct")
	persist := filepath.Join(dir, "99-linkguard-conntrack.conf")
	// Simulate accounting disabled by the kernel.
	if err := os.WriteFile(acct, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Service{exec: firewall.NewRealExecutor(0), acctPath: acct, persistPath: persist}
	s.EnsureAccounting()

	got, err := os.ReadFile(acct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1\n" {
		t.Errorf("acct not enabled: got %q, want %q", got, "1\n")
	}
	drop, err := os.ReadFile(persist)
	if err != nil {
		t.Fatalf("drop-in not written: %v", err)
	}
	if !strings.Contains(string(drop), "nf_conntrack_acct = 1") {
		t.Errorf("drop-in missing sysctl line: %q", drop)
	}
}

// TestEnsureAccountingDryRunNoWrite ensures dry-run mode never touches the kernel.
func TestEnsureAccountingDryRunNoWrite(t *testing.T) {
	dir := t.TempDir()
	acct := filepath.Join(dir, "nf_conntrack_acct")
	if err := os.WriteFile(acct, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Service{exec: firewall.NewDryRunExecutor(), acctPath: acct, persistPath: filepath.Join(dir, "drop.conf")}
	s.EnsureAccounting()

	got, _ := os.ReadFile(acct)
	if string(got) != "0\n" {
		t.Errorf("dry-run modified acct: got %q, want %q", got, "0\n")
	}
}
