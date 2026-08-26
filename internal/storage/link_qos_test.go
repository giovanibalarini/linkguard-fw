package storage_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestLinkQoSJSONShape(t *testing.T) {
	raw, err := json.Marshal(storage.Link{
		QoSEnabled:      true,
		QoSUploadMbps:   40,
		QoSDownloadMbps: 300,
		QoSInteractive:  true,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := map[string]any{
		"qos_enabled":       true,
		"qos_upload_mbps":   float64(40),
		"qos_download_mbps": float64(300),
		"qos_interactive":   true,
	}
	for key, wantValue := range want {
		if gotValue, ok := got[key]; !ok || gotValue != wantValue {
			t.Errorf("JSON field %q = %#v, present=%v; want %#v", key, gotValue, ok, wantValue)
		}
	}
}

func TestLinkQoSFieldsRoundTripThroughRepository(t *testing.T) {
	db := newTestDB(t)

	link := &storage.Link{
		Name:            "WAN QoS",
		Interface:       "eth0",
		QoSEnabled:      true,
		QoSUploadMbps:   40,
		QoSDownloadMbps: 300,
		QoSInteractive:  true,
	}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	created, err := db.GetLink(link.ID)
	if err != nil {
		t.Fatalf("GetLink after create: %v", err)
	}
	assertLinkQoS(t, created, true, 40, 300, true)

	link.QoSEnabled = false
	link.QoSUploadMbps = 75
	link.QoSDownloadMbps = 500
	link.QoSInteractive = false
	if err := db.UpdateLink(link); err != nil {
		t.Fatalf("UpdateLink: %v", err)
	}

	links, err := db.GetLinks()
	if err != nil {
		t.Fatalf("GetLinks after update: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("GetLinks returned %d links; want 1", len(links))
	}
	assertLinkQoS(t, &links[0], false, 75, 500, false)
}

func TestUpdateLinkQoSIfCurrentUsesLifecycleAndVersionGuards(t *testing.T) {
	db := newTestDB(t)
	link := &storage.Link{Name: "WAN guarded", Interface: "eth0", Enabled: true}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	current, err := db.GetLink(link.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if err := db.UpdateLinkQoSIfCurrent(current.ID, current.Interface, current.Enabled,
		current.QoSEnabled, current.QoSUploadMbps, current.QoSDownloadMbps, current.QoSInteractive,
		true, 40, 300, true); err != nil {
		t.Fatalf("UpdateLinkQoSIfCurrent: %v", err)
	}

	if err := db.UpdateLinkQoSIfCurrent(current.ID, current.Interface, current.Enabled,
		current.QoSEnabled, current.QoSUploadMbps, current.QoSDownloadMbps, current.QoSInteractive,
		false, 1, 1, false); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stale UpdateLinkQoSIfCurrent error = %v; want sql.ErrNoRows", err)
	}
	updated, err := db.GetLink(link.ID)
	if err != nil {
		t.Fatalf("GetLink after stale update: %v", err)
	}
	assertLinkQoS(t, updated, true, 40, 300, true)
}

func TestUpdateLinkQoSIfCurrentRejectsLifecycleChanges(t *testing.T) {
	db := newTestDB(t)
	link := &storage.Link{Name: "WAN lifecycle", Interface: "eth0", Enabled: true}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	current, err := db.GetLink(link.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	current.Interface = "eth1"
	if err := db.UpdateLinkNonQoS(current); err != nil {
		t.Fatalf("UpdateLinkNonQoS: %v", err)
	}

	err = db.UpdateLinkQoSIfCurrent(link.ID, "eth0", true, false, 0, 0, false, true, 40, 300, true)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("UpdateLinkQoSIfCurrent after interface move error = %v; want sql.ErrNoRows", err)
	}
}

func TestUpdateLinkQoSIfCurrentIgnoresMonitorUpdatedAtChanges(t *testing.T) {
	db := newTestDB(t)
	link := &storage.Link{Name: "WAN monitor", Interface: "eth0", Enabled: true}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	current, err := db.GetLink(link.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	statusAt := time.Now()
	if err := db.UpdateLinkStatus(link.ID, "online", 12, 0, &statusAt); err != nil {
		t.Fatalf("UpdateLinkStatus: %v", err)
	}
	if err := db.UpdateLinkQoSIfCurrent(current.ID, current.Interface, current.Enabled,
		current.QoSEnabled, current.QoSUploadMbps, current.QoSDownloadMbps, current.QoSInteractive,
		true, 40, 300, true); err != nil {
		t.Fatalf("UpdateLinkQoSIfCurrent after monitor update: %v; monitor metadata must not conflict", err)
	}
}

func assertLinkQoS(t *testing.T, got *storage.Link, enabled bool, upload, download int, interactive bool) {
	t.Helper()
	if got == nil {
		t.Fatal("link is nil")
	}
	if got.QoSEnabled != enabled {
		t.Errorf("QoSEnabled = %v; want %v", got.QoSEnabled, enabled)
	}
	if got.QoSUploadMbps != upload {
		t.Errorf("QoSUploadMbps = %d; want %d", got.QoSUploadMbps, upload)
	}
	if got.QoSDownloadMbps != download {
		t.Errorf("QoSDownloadMbps = %d; want %d", got.QoSDownloadMbps, download)
	}
	if got.QoSInteractive != interactive {
		t.Errorf("QoSInteractive = %v; want %v", got.QoSInteractive, interactive)
	}
}
