package handlers

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestReconcileQosUsesFreshCurrentConfigurationPerInterface(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	link := storage.Link{
		ID: "wan-1", Name: "WAN 1", Interface: "wan0", Gateway: "192.0.2.1",
		Enabled: true, QoSEnabled: true, QoSUploadMbps: 10, QoSDownloadMbps: 20,
	}
	if err := db.CreateLink(&link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	service := &freshReconcileStub{db: db, uploadMbps: 30, downloadMbps: 40}
	h := NewLinksHandler(nil, db, nil, nil)
	h.SetQosService(service)

	h.reconcileQos(context.Background())

	if len(service.applied) != 1 {
		t.Fatalf("ApplyCurrent calls = %d, want 1; applied=%v", len(service.applied), service.applied)
	}
	if service.applied[0].UploadMbps != 30 || service.applied[0].DownloadMbps != 40 {
		t.Fatalf("runtime reconciliation used stale config: %+v", service.applied[0])
	}
}

type freshReconcileStub struct {
	db           *storage.DB
	uploadMbps   int
	downloadMbps int
	applied      []qos.Config
}

func (s *freshReconcileStub) Apply(context.Context, qos.Config) (qos.State, error) {
	return qos.State{}, nil
}

func (s *freshReconcileStub) ApplyAndPersist(context.Context, qos.Config, qos.Config, func(string) error) (qos.State, error) {
	return qos.State{}, nil
}

func (s *freshReconcileStub) ApplyCurrentAndPersist(context.Context, string, func() (qos.ApplyPlan, error)) (qos.State, error) {
	return qos.State{}, nil
}

func (s *freshReconcileStub) ApplyCurrent(ctx context.Context, iface string, load func() (qos.Config, error)) (qos.State, error) {
	link, err := s.db.GetLink("wan-1")
	if err != nil {
		return qos.State{}, err
	}
	link.QoSUploadMbps = s.uploadMbps
	link.QoSDownloadMbps = s.downloadMbps
	if err := s.db.UpdateLinkQoS(link.ID, link.Interface, true, link.QoSUploadMbps, link.QoSDownloadMbps, link.QoSInteractive); err != nil {
		return qos.State{}, err
	}
	cfg, err := load()
	if err != nil {
		return qos.State{}, err
	}
	if cfg.Interface != iface {
		return qos.State{}, fmt.Errorf("loader returned interface %q, want %q", cfg.Interface, iface)
	}
	s.applied = append(s.applied, cfg)
	return qos.State{Enabled: cfg.Enabled, Interface: cfg.Interface}, nil
}

func (*freshReconcileStub) Observe(context.Context, string) (qos.State, error) {
	return qos.State{}, nil
}

func (*freshReconcileStub) MeasureBeforeAfter(context.Context, qos.Config) (qos.Comparison, error) {
	return qos.Comparison{}, nil
}

func (*freshReconcileStub) MeasureCurrentBeforeAfter(context.Context, string, func() (qos.Config, error)) (qos.Comparison, error) {
	return qos.Comparison{}, nil
}
