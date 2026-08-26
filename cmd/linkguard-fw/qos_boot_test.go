package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type bootQosExec struct {
	failOn      string
	events      []string
	readOutputs map[string]string
}

func (e *bootQosExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	event := cmd + " " + strings.Join(args, " ")
	e.events = append(e.events, event)
	if e.failOn != "" && strings.Contains(event, e.failOn) {
		return "", errors.New("simulated QoS failure")
	}
	return "", nil
}

func (e *bootQosExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	key := cmd + " " + strings.Join(args, " ")
	if output, ok := e.readOutputs[key]; ok {
		return output, nil
	}
	return "", nil
}

func (*bootQosExec) IsDryRun() bool { return true }

func (*bootQosExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestReconcileQoSOnBootAppliesOnlyEnabledQoSAndDisablesStale(t *testing.T) {
	exec := &bootQosExec{}
	configureBootManagedObjects(exec, "wan1", "wan2")
	service := qos.NewService(exec)
	links := []storage.Link{
		{ID: "enabled", Interface: "wan0", Enabled: true, QoSEnabled: true, QoSUploadMbps: 50, QoSDownloadMbps: 200},
		{ID: "qos-off", Interface: "wan1", Enabled: true, QoSEnabled: false, QoSUploadMbps: -99, QoSDownloadMbps: -99},
		{ID: "link-off", Interface: "wan2", Enabled: false, QoSEnabled: true, QoSUploadMbps: 50, QoSDownloadMbps: 200},
	}

	reconcileQoSOnBoot(context.Background(), service, func() ([]storage.Link, error) { return links, nil })

	if !containsBootQosEvent(exec.events, "tc qdisc replace dev wan0 root handle 1: cake bandwidth 50mbit") {
		t.Errorf("enabled QoS link was not applied: %v", exec.events)
	}
	for _, iface := range []string{"wan1", "wan2"} {
		if !containsBootQosEvent(exec.events, "tc filter del dev "+iface+" ingress pref 49152") {
			t.Errorf("stale QoS for %s was not disabled: %v", iface, exec.events)
		}
		if containsBootQosEvent(exec.events, "tc qdisc replace dev "+iface+" root handle 1: cake") {
			t.Errorf("disabled QoS for %s was applied: %v", iface, exec.events)
		}
	}
}

func TestReconcileQoSOnBootLogsAndContinuesAfterApplyFailure(t *testing.T) {
	exec := &bootQosExec{failOn: "dev wan-fail"}
	service := qos.NewService(exec)
	links := []storage.Link{
		{ID: "fail", Interface: "wan-fail", Enabled: true, QoSEnabled: true, QoSUploadMbps: 10, QoSDownloadMbps: 20},
		{ID: "ok", Interface: "wan-ok", Enabled: true, QoSEnabled: true, QoSUploadMbps: 30, QoSDownloadMbps: 40},
	}

	reconcileQoSOnBoot(context.Background(), service, func() ([]storage.Link, error) { return links, nil })

	if !containsBootQosEvent(exec.events, "tc qdisc replace dev wan-ok root handle 1: cake bandwidth 30mbit") {
		t.Errorf("boot reconciliation stopped after one failure: %v", exec.events)
	}
}

func TestReconcileQoSOnBootUsesFreshPersistedSnapshotBeforeApply(t *testing.T) {
	exec := &bootQosExec{}
	service := qos.NewService(exec)
	initial := []storage.Link{{ID: "wan-1", Interface: "wan0", Enabled: true, QoSEnabled: true, QoSUploadMbps: 10, QoSDownloadMbps: 20}}
	fresh := []storage.Link{{ID: "wan-1", Interface: "wan0", Enabled: true, QoSEnabled: true, QoSUploadMbps: 30, QoSDownloadMbps: 40}}
	loads := 0
	load := func() ([]storage.Link, error) {
		loads++
		if loads == 1 {
			return initial, nil
		}
		return fresh, nil
	}

	reconcileQoSOnBoot(context.Background(), service, load)

	if !containsBootQosEvent(exec.events, "tc qdisc replace dev wan0 root handle 1: cake bandwidth 30mbit") {
		t.Fatalf("boot applied stale snapshot instead of fresh persisted QoS: %v", exec.events)
	}
}

func configureBootManagedObjects(exec *bootQosExec, interfaces ...string) {
	if exec.readOutputs == nil {
		exec.readOutputs = make(map[string]string)
	}
	for _, iface := range interfaces {
		ifb := qos.IFBName(iface)
		exec.readOutputs["ip link show dev "+ifb] = "6: " + ifb + ": <BROADCAST>"
		exec.readOutputs["tc qdisc show dev "+iface] = "qdisc cake 1: root bandwidth 50mbit"
		exec.readOutputs["tc qdisc show dev "+ifb] = "qdisc cake 1: root bandwidth 200mbit"
		exec.readOutputs["tc filter show dev "+iface+" ingress pref 49152"] = "filter protocol all pref 49152 matchall\n action order 1: mirred egress redirect dev " + ifb
	}
}

func containsBootQosEvent(events []string, want string) bool {
	for _, event := range events {
		if strings.Contains(event, want) {
			return true
		}
	}
	return false
}
