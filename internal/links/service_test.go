package links_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newTestService(t *testing.T) *links.Service {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return links.NewService(db)
}

func TestCreateLink(t *testing.T) {
	svc := newTestService(t)

	l := &storage.Link{
		Name:      "WAN1",
		Interface: "eth0",
		Gateway:   "192.168.1.1",
		Enabled:   true,
	}
	if err := svc.Create(l); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if l.ID == "" {
		t.Error("expected ID after create")
	}
}

func TestCreateLinkValidation(t *testing.T) {
	svc := newTestService(t)

	cases := []struct {
		name string
		link storage.Link
	}{
		{"empty name", storage.Link{Interface: "eth0", Gateway: "10.0.0.1"}},
		{"empty interface", storage.Link{Name: "WAN1", Gateway: "10.0.0.1"}},
		{"invalid ip", storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", IPAddress: "not-an-ip"}},
		{"invalid gateway", storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "not-a-gateway"}},
		{"invalid interface", storage.Link{Name: "WAN1", Interface: "eth0;bad", Gateway: "10.0.0.1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := tc.link
			if err := svc.Create(&l); err == nil {
				t.Errorf("expected validation error for %q, got nil", tc.name)
			}
		})
	}
}

func TestListLinks(t *testing.T) {
	svc := newTestService(t)

	ls, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ls) != 0 {
		t.Errorf("expected empty list, got %d", len(ls))
	}

	for i, name := range []string{"WAN1", "WAN2"} {
		l := &storage.Link{
			Name:      name,
			Interface: "eth" + string(rune('0'+i)),
			Gateway:   "10.0.0.1",
			Enabled:   true,
		}
		if err := svc.Create(l); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}

	ls, err = svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ls) != 2 {
		t.Errorf("expected 2 links, got %d", len(ls))
	}
}

func TestGetLink(t *testing.T) {
	svc := newTestService(t)

	l := &storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", Enabled: true}
	if err := svc.Create(l); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := svc.Get(l.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "WAN1" {
		t.Errorf("expected Name=WAN1, got %s", got.Name)
	}
}

func TestGetLinkNotFound(t *testing.T) {
	svc := newTestService(t)

	_, err := svc.Get("nonexistent-id")
	if !errors.Is(err, links.ErrNotFound) {
		t.Fatalf("Get() error = %v; want links.ErrNotFound", err)
	}
}

func TestUpdateLink(t *testing.T) {
	svc := newTestService(t)

	l := &storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", Enabled: true}
	if err := svc.Create(l); err != nil {
		t.Fatalf("Create: %v", err)
	}

	l.Name = "WAN1-updated"
	l.Weight = 200
	if err := svc.Update(l); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := svc.Get(l.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "WAN1-updated" {
		t.Errorf("expected Name=WAN1-updated, got %s", got.Name)
	}
}

func TestUpdateLinkDoesNotOverwriteQoSFieldsFromStaleSnapshot(t *testing.T) {
	svc := newTestService(t)

	l := &storage.Link{
		Name:            "WAN1",
		Interface:       "eth0",
		Gateway:         "10.0.0.1",
		Enabled:         true,
		QoSEnabled:      true,
		QoSUploadMbps:   50,
		QoSDownloadMbps: 200,
	}
	if err := svc.Create(l); err != nil {
		t.Fatalf("Create: %v", err)
	}

	stale := *l
	stale.Name = "WAN1-updated"
	stale.QoSEnabled = false
	stale.QoSUploadMbps = 0
	stale.QoSDownloadMbps = 0
	if err := svc.Update(&stale); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := svc.Get(l.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.QoSEnabled || got.QoSUploadMbps != 50 || got.QoSDownloadMbps != 200 {
		t.Fatalf("stale non-QoS update overwrote QoS: %+v", got)
	}
}

func TestDeleteLink(t *testing.T) {
	svc := newTestService(t)

	l := &storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", Enabled: true}
	if err := svc.Create(l); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Delete(l.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := svc.Get(l.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestUpdateStatus(t *testing.T) {
	svc := newTestService(t)

	l := &storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", Enabled: true}
	if err := svc.Create(l); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.UpdateStatus(l.ID, "online", 15.0, 0.5); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := svc.Get(l.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != "online" {
		t.Errorf("expected status=online, got %s", got.Status)
	}
	if got.LatencyMs != 15.0 {
		t.Errorf("expected LatencyMs=15.0, got %f", got.LatencyMs)
	}
	if got.PacketLoss != 0.5 {
		t.Errorf("expected packet_loss=0.5, got %f", got.PacketLoss)
	}
}
