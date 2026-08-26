package main

import (
	"context"
	"log/slog"

	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// reconcileQoSOnBoot reapplies enabled QoS and removes stale objects for every
// persisted link. Each link is independent: a failed command is logged and
// does not prevent the remaining links from being reconciled.
func reconcileQoSOnBoot(ctx context.Context, svc *qos.Service, configuredLinks []storage.Link) {
	if svc == nil {
		return
	}
	for _, link := range configuredLinks {
		var err error
		if link.Enabled && link.QoSEnabled {
			_, err = svc.Apply(ctx, qos.Config{
				Interface:    link.Interface,
				Enabled:      true,
				UploadMbps:   link.QoSUploadMbps,
				DownloadMbps: link.QoSDownloadMbps,
				Interactive:  link.QoSInteractive,
			})
		} else {
			_, err = svc.Apply(ctx, qos.Config{Interface: link.Interface})
		}
		if err != nil {
			slog.Warn("não foi possível reconciliar QoS no boot", "link_id", link.ID, "interface", link.Interface, "err", err)
		}
	}
}
