package links

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newDiscoveryTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewService(db)
}

func TestParseDefaultRoutes(t *testing.T) {
	routeTable := strings.Join([]string{
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0",
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0",
		"ppp0\t00000000\t0100000A\t0003\t0\t0\t50\t00000000\t0\t0\t0",
	}, "\n")

	routes, err := parseDefaultRoutes(routeTable)
	if err != nil {
		t.Fatalf("parseDefaultRoutes: %v", err)
	}

	if routes["eth0"] != "192.168.1.1" {
		t.Fatalf("expected eth0 gateway 192.168.1.1, got %q", routes["eth0"])
	}
	if routes["ppp0"] != "10.0.0.1" {
		t.Fatalf("expected ppp0 gateway 10.0.0.1, got %q", routes["ppp0"])
	}
}

func TestDiscoverAndSyncWANLinksCreatesAndUpdates(t *testing.T) {
	svc := newDiscoveryTestService(t)

	oldReadProc := readProcNetRoute
	oldListIfaces := listInterfaces
	t.Cleanup(func() {
		readProcNetRoute = oldReadProc
		listInterfaces = oldListIfaces
	})

	readProcNetRoute = func() ([]byte, error) {
		return []byte(strings.Join([]string{
			"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
			"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0",
			"eth1\t00000000\t0100000A\t0003\t0\t0\t50\t00000000\t0\t0\t0",
		}, "\n")), nil
	}
	listInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "eth0", Flags: net.FlagUp},
			{Name: "eth1", Flags: net.FlagUp},
			{Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
		}, nil
	}

	if err := svc.Create(&storage.Link{
		Name:      "WAN eth0",
		Interface: "eth0",
		IPAddress: "192.168.1.100",
		Gateway:   "192.168.1.254",
		Weight:    100,
		DNSTest:   "8.8.8.8",
		Enabled:   true,
	}); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	res, err := svc.DiscoverAndSyncWANLinks()
	if err != nil {
		t.Fatalf("DiscoverAndSyncWANLinks: %v", err)
	}

	if len(res.Detected) != 2 {
		t.Fatalf("expected 2 detected links, got %d", len(res.Detected))
	}
	if len(res.Updated) != 1 {
		t.Fatalf("expected 1 updated link, got %d", len(res.Updated))
	}
	if len(res.Created) != 1 {
		t.Fatalf("expected 1 created link, got %d", len(res.Created))
	}

	all, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 links in DB, got %d", len(all))
	}

	byInterface := map[string]storage.Link{}
	for _, l := range all {
		byInterface[l.Interface] = l
	}
	if byInterface["eth0"].Gateway != "192.168.1.1" {
		t.Fatalf("expected eth0 gateway updated to 192.168.1.1, got %q", byInterface["eth0"].Gateway)
	}
	if byInterface["eth1"].Gateway != "10.0.0.1" {
		t.Fatalf("expected eth1 gateway 10.0.0.1, got %q", byInterface["eth1"].Gateway)
	}
	if byInterface["eth1"].Name != "WAN eth1" {
		t.Fatalf("expected eth1 name WAN eth1, got %q", byInterface["eth1"].Name)
	}
}

func TestDiscoverAndSyncWANLinksReadRouteError(t *testing.T) {
	svc := newDiscoveryTestService(t)

	oldReadProc := readProcNetRoute
	t.Cleanup(func() {
		readProcNetRoute = oldReadProc
	})

	readProcNetRoute = func() ([]byte, error) {
		return nil, fmt.Errorf("boom")
	}

	if _, err := svc.DiscoverAndSyncWANLinks(); err == nil {
		t.Fatal("expected error when route table read fails")
	}
}
