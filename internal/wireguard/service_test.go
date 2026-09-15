package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type serviceExec struct {
	mu        sync.Mutex
	calls     []string
	writes    []string
	active    bool
	enabled   bool
	failStrip bool
	wgDump    string
	pingOut   string
}

func (e *serviceExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, strings.Join(append([]string{cmd}, args...), " "))
	switch cmd {
	case "install":
		return "", os.MkdirAll(args[len(args)-1], 0o700)
	case "chmod":
		return "", os.Chmod(args[len(args)-1], 0o600)
	case "chown":
		return "", nil
	case "mv":
		return "", os.Rename(args[len(args)-2], args[len(args)-1])
	case "rm":
		err := os.Remove(args[len(args)-1])
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	case "systemctl":
		if len(args) > 0 && args[0] == "enable" {
			e.enabled = true
		}
		if len(args) > 0 && (args[0] == "restart" || args[0] == "start") {
			e.active = true
		}
		if len(args) > 0 && args[0] == "disable" {
			e.active = false
			e.enabled = false
		}
	}
	return "", nil
}

func (e *serviceExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, strings.Join(append([]string{cmd}, args...), " "))
	switch cmd {
	case "dpkg-query":
		return "install ok installed", nil
	case "wg-quick":
		if e.failStrip {
			return "", errors.New("candidate refused")
		}
		return "", nil
	case "systemctl":
		if len(args) > 0 && args[0] == "is-enabled" {
			if e.enabled {
				return "enabled", nil
			}
			return "disabled", errors.New("disabled")
		}
		if e.active {
			return "active", nil
		}
		return "inactive", errors.New("inactive")
	case "wg":
		if e.active {
			if len(args) > 2 && args[0] == "show" && args[2] == "dump" && e.wgDump != "" {
				return e.wgDump, nil
			}
			return InterfaceName, nil
		}
		return "", errors.New("down")
	case "ping":
		if e.pingOut != "" {
			return e.pingOut, nil
		}
		return "", errors.New("timeout")
	}
	return "", nil
}

func (*serviceExec) IsDryRun() bool { return false }
func (e *serviceExec) WriteFile(path string, data []byte, mode os.FileMode) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.writes = append(e.writes, path+":"+mode.String())
	return os.WriteFile(path, data, mode)
}

var _ firewall.Executor = (*serviceExec)(nil)

type qrSpy struct{ got string }

func (q *qrSpy) Encode(_ context.Context, value string) (string, error) {
	q.got = value
	return "data:image/svg+xml;base64,PHN2Zy8+", nil
}

func newServiceTest(t *testing.T) (*Service, *storage.DB, *secrets.Service, *serviceExec) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sec := secrets.NewService(db, []byte("0123456789abcdef0123456789abcdef"))
	exec := &serviceExec{}
	svc := NewService(db, sec, exec)
	svc.configPath = filepath.Join(dir, "wireguard", "linkguard.conf")
	svc.installExec = exec
	svc.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return svc, db, sec, exec
}

func TestDisabledReconcileDoesNotInstallPackagesOrCreatePrivateKey(t *testing.T) {
	svc, _, sec, exec := newServiceTest(t)
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, call := range exec.calls {
		if strings.Contains(call, "dpkg-query") || strings.Contains(call, "apt-get") {
			t.Fatalf("disabled service touched packages: %s", call)
		}
	}
	if key, err := sec.Get(ServerSecret); err != nil || key != "" {
		t.Fatalf("disabled service created server key: %q, %v", key, err)
	}
}

func TestDisabledReconcileDisablesAnEnabledButInactiveUnit(t *testing.T) {
	svc, _, _, exec := newServiceTest(t)
	exec.enabled = true
	exec.active = false

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if exec.enabled {
		t.Fatal("inactive WireGuard unit remained enabled for the next boot")
	}
	if callsContaining(exec.calls, "systemctl disable --now "+ServiceName) != 1 {
		t.Fatalf("disable --now not called exactly once: %v", exec.calls)
	}
}

func TestEnabledReconcileWritesRootOnlyConfigAndIsIdempotent(t *testing.T) {
	svc, _, sec, exec := newServiceTest(t)
	c := DefaultConfig()
	c.Enabled = true
	c.EndpointHost = "vpn.example.net"
	if err := svc.UpdateConfig(context.Background(), c); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}
	key, err := sec.Get(ServerSecret)
	if err != nil || key == "" {
		t.Fatalf("server key = %q, %v", key, err)
	}
	info, err := os.Stat(svc.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %#o", info.Mode().Perm())
	}
	firstRestarts := callsContaining(exec.calls, "systemctl restart ")
	if firstRestarts != 1 {
		t.Fatalf("restarts after first apply = %d", firstRestarts)
	}
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := callsContaining(exec.calls, "systemctl restart "); got != firstRestarts {
		t.Fatalf("unchanged reconcile restarted service: %d -> %d", firstRestarts, got)
	}
}

func TestEnrollReturnsPrivateConfigAndQRExactlyOnMutation(t *testing.T) {
	svc, db, sec, exec := newServiceTest(t)
	user := &storage.User{Username: "ana"}
	if err := db.CreateUser(user, "hash", nil); err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	c.Enabled = true
	c.EndpointHost = "vpn.example.net"
	if err := svc.UpdateConfig(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	qr := &qrSpy{}
	svc.qr = qr

	enrollment, err := svc.Enroll(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enrollment.ClientConfig == "" || enrollment.QRDataURL == "" || qr.got != enrollment.ClientConfig {
		t.Fatalf("one-time enrollment incomplete: %+v qr=%q", enrollment, qr.got)
	}
	peer, err := db.GetWireGuardPeer(user.ID)
	if err != nil || peer == nil {
		t.Fatalf("peer = %+v, %v", peer, err)
	}
	clientPrivate, err := sec.Get(peer.SecretName)
	if err != nil || clientPrivate == "" {
		t.Fatalf("client secret = %q, %v", clientPrivate, err)
	}
	if !strings.Contains(enrollment.ClientConfig, clientPrivate) {
		t.Fatal("one-time config lacks private key")
	}

	overview, err := svc.Overview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(overview)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), clientPrivate) || strings.Contains(string(body), peer.SecretName) {
		t.Fatalf("GET-shaped overview leaked private material: %s", body)
	}
	serverFile, err := os.ReadFile(svc.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serverFile), clientPrivate) || !strings.Contains(string(serverFile), peer.PublicKey) {
		t.Fatal("server config must contain peer public key only")
	}
	if callsContaining(exec.calls, "systemctl restart ") != 2 {
		t.Fatalf("initial apply plus peer apply should restart twice: %v", exec.calls)
	}
}

func TestApplyRefusesCorruptPersistedConfigBeforeReplacingLiveFile(t *testing.T) {
	svc, db, sec, exec := newServiceTest(t)
	if err := os.MkdirAll(filepath.Dir(svc.configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.configPath, []byte("known-good"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	private, _, _ := GenerateKeypair()
	if err := sec.Set(ServerSecret, private); err != nil {
		t.Fatal(err)
	}
	bad := &storage.WireGuardConfig{Enabled: true, ListenPort: 51820, Address: "10.7.0.1/24\nPostUp = pwn", EndpointHost: "vpn.example.net"}
	if err := db.SaveWireGuardConfig(bad); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("expected sink validation failure")
	}
	got, _ := os.ReadFile(svc.configPath)
	if string(got) != "known-good" {
		t.Fatalf("live config changed to %q", got)
	}
	if len(exec.writes) != 0 {
		t.Fatalf("sink wrote candidate before validation: %v", exec.writes)
	}
}

func TestReconcileRepairsMissingManagedPeerGroup(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	user := &storage.User{Username: "davi"}
	if err := db.CreateUser(user, "hash", nil); err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	c.Enabled = true
	c.EndpointHost = "vpn.example.net"
	if err := svc.UpdateConfig(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	svc.qr = &qrSpy{}
	if _, err := svc.Enroll(context.Background(), user.ID); err != nil {
		t.Fatal(err)
	}
	peer, _ := db.GetWireGuardPeer(user.ID)
	if err := db.DeleteFirewallGroup(peer.FirewallGroupID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	found := false
	for _, g := range mustWireGuardGroups(t, db) {
		if g.ID == peer.FirewallGroupID && g.Kind == "wireguard_peer" && g.CondSaddr == peer.Address {
			found = true
		}
	}
	if !found {
		t.Fatal("reconcile did not recreate the peer firewall group")
	}
}

func mustWireGuardGroups(t *testing.T, db *storage.DB) []storage.FirewallGroup {
	t.Helper()
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatal(err)
	}
	return groups
}

func callsContaining(calls []string, needle string) int {
	n := 0
	for _, call := range calls {
		if strings.Contains(call, needle) {
			n++
		}
	}
	return n
}

func TestParseWgDump(t *testing.T) {
	raw := `server_priv	server_pub	51820	off
XE/R7kdmY3NpY6LukOcM2yUWEuhduCQ9uB86k+OJuig=	(none)	200.188.216.26:49090	10.7.0.2/32	1789432764	1490111592	4528092292	off
h4u9xOzDFoRQnMI6j3d78IRdJ0JK4OK6PZ4v2qjQw2E=	(none)	(none)	10.7.0.3/32	0	0	0	off
`
	res := parseWgDump(raw)
	if len(res) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(res))
	}
	p1 := res["XE/R7kdmY3NpY6LukOcM2yUWEuhduCQ9uB86k+OJuig="]
	if p1.endpoint != "200.188.216.26:49090" {
		t.Errorf("expected endpoint 200.188.216.26:49090, got %s", p1.endpoint)
	}
	if p1.latestHandshake != 1789432764 {
		t.Errorf("expected handshake 1789432764, got %d", p1.latestHandshake)
	}
	if p1.transferRx != 1490111592 || p1.transferTx != 4528092292 {
		t.Errorf("unexpected transfer stats: rx=%d, tx=%d", p1.transferRx, p1.transferTx)
	}

	p2 := res["h4u9xOzDFoRQnMI6j3d78IRdJ0JK4OK6PZ4v2qjQw2E="]
	if p2.endpoint != "" {
		t.Errorf("expected empty endpoint for (none), got %s", p2.endpoint)
	}
	if p2.latestHandshake != 0 {
		t.Errorf("expected handshake 0, got %d", p2.latestHandshake)
	}
}

func TestParsePingOutput(t *testing.T) {
	out1 := `PING 10.7.0.2 (10.7.0.2) 56(84) bytes of data.
64 bytes from 10.7.0.2: icmp_seq=1 ttl=64 time=7.52 ms

--- 10.7.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 7.524/7.524/7.524/0.000 ms`

	lat1 := parsePingOutput(out1)
	if lat1 != 7.52 {
		t.Errorf("expected 7.52, got %f", lat1)
	}

	out2 := `PING 10.7.0.2 (10.7.0.2) 56(84) bytes of data.
--- 10.7.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 12.345/12.345/12.345/0.000 ms`
	lat2 := parsePingOutput(out2)
	if lat2 != 12.345 {
		t.Errorf("expected 12.345, got %f", lat2)
	}

	outErr := `PING 10.7.0.3 (10.7.0.3) 56(84) bytes of data.
--- 10.7.0.3 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms`
	latErr := parsePingOutput(outErr)
	if latErr != 0 {
		t.Errorf("expected 0 for failed ping, got %f", latErr)
	}
}

func TestOverviewEnrichesPeerTelemetry(t *testing.T) {
	svc, db, _, exec := newServiceTest(t)
	nowEpoch := int64(1_700_000_000)
	svc.now = func() time.Time { return time.Unix(nowEpoch, 0) }

	// Enable service and start active
	exec.active = true
	if err := svc.UpdateConfig(context.Background(), Config{Enabled: true, ListenPort: 51820, Address: "10.7.0.1/24", EndpointHost: "1.2.3.4"}); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	user := &storage.User{Username: "testuser"}
	if err := db.CreateUser(user, "hash", nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	enrollment, err := svc.Enroll(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Mock wg show dump output with recent handshake (30s ago)
	handshake := nowEpoch - 30
	exec.wgDump = "server_priv\tserver_pub\t51820\toff\n" +
		enrollment.Peer.PublicKey + "\t(none)\t198.51.100.1:51820\t10.7.0.2/32\t" +
		strconv.FormatInt(handshake, 10) + "\t1000\t2000\toff\n"
	exec.pingOut = "64 bytes from 10.7.0.2: icmp_seq=1 ttl=64 time=8.45 ms\n"

	overview, err := svc.Overview(context.Background())
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if len(overview.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(overview.Peers))
	}
	p := overview.Peers[0]
	if !p.Online {
		t.Errorf("expected peer to be online")
	}
	if p.Endpoint != "198.51.100.1:51820" {
		t.Errorf("expected endpoint 198.51.100.1:51820, got %s", p.Endpoint)
	}
	if p.LatestHandshake != handshake {
		t.Errorf("expected handshake %d, got %d", handshake, p.LatestHandshake)
	}
	if p.TransferRx != 1000 || p.TransferTx != 2000 {
		t.Errorf("unexpected transfer stats: rx=%d, tx=%d", p.TransferRx, p.TransferTx)
	}
	if p.LatencyMs != 8.45 {
		t.Errorf("expected latency 8.45, got %f", p.LatencyMs)
	}
}

