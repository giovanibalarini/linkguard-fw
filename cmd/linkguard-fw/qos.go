package main

import (
	"context"
	"log/slog"

	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/stresstest"
)

func recoverStressTestOnBoot(ctx context.Context, svc *stresstest.Service) {
	if svc == nil {
		return
	}
	if err := svc.RecoverInterrupted(ctx); err != nil {
		slog.Error("não foi possível recuperar stress test interrompido no boot", "err", err)
	}
}

func recoverQoSOnBoot(ctx context.Context, svc *qos.Service) {
	if svc == nil {
		return
	}
	if err := svc.RecoverInterrupted(ctx); err != nil {
		slog.Error("não foi possível recuperar operação QoS interrompida no boot", "err", err)
	}
}

// reconcileQoSOnBoot reapplies enabled QoS and removes stale objects for every
// persisted link. The loader is called while each interface is locked by
// ApplyCurrent, so an API mutation cannot be followed by a stale boot apply.
// Each link is independent: a failed command is logged and does not prevent
// the remaining links from being reconciled.
func reconcileQoSOnBoot(ctx context.Context, svc *qos.Service, load func() ([]storage.Link, error)) {
	if svc == nil {
		return
	}
	configuredLinks, err := load()
	if err != nil {
		slog.Warn("não foi possível carregar links para reconciliar QoS no boot", "err", err)
		return
	}

	for pass := 0; pass < 2; pass++ {
		staleInterface := false
		for _, snapshot := range configuredLinks {
			changedInterface := false
			_, err := svc.ApplyCurrent(ctx, snapshot.Interface, func() (qos.Config, error) {
				freshLinks, err := load()
				if err != nil {
					return qos.Config{}, err
				}
				for _, link := range freshLinks {
					if link.ID != snapshot.ID {
						continue
					}
					if link.Interface != snapshot.Interface {
						changedInterface = true
						return qos.Config{Interface: snapshot.Interface}, nil
					}
					return bootQoSConfig(link), nil
				}
				return qos.Config{Interface: snapshot.Interface}, nil
			})
			if changedInterface {
				staleInterface = true
			}
			if err != nil {
				slog.Warn("não foi possível reconciliar QoS no boot", "link_id", snapshot.ID, "interface", snapshot.Interface, "err", err)
			}
		}
		if !staleInterface {
			return
		}
		configuredLinks, err = load()
		if err != nil {
			slog.Warn("não foi possível recarregar links para reconciliar QoS no boot", "err", err)
			return
		}
	}
}

func bootQoSConfig(link storage.Link) qos.Config {
	if !link.Enabled || !link.QoSEnabled {
		return qos.Config{Interface: link.Interface}
	}
	return qos.Config{
		Interface:    link.Interface,
		Enabled:      true,
		UploadMbps:   link.QoSUploadMbps,
		DownloadMbps: link.QoSDownloadMbps,
		Interactive:  link.QoSInteractive,
	}
}
