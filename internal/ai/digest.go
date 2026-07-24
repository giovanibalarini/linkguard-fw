package ai

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// RunDigest runs the once-a-day analysis loop. Blocks until ctx is done.
// linkNames is called fresh each day so newly-added WAN links are included
// without a restart.
func RunDigest(ctx context.Context, client *Client, tsdbSvc *tsdb.Service, alertSvc *alerts.Service, db *storage.DB, linkNames func() []string) {
	slog.Info("ai digest loop started")
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	consecutiveFailures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg := LoadConfig(db)
			if !cfg.Enabled {
				continue
			}
			if time.Now().Hour() != cfg.DigestHour {
				continue
			}
			if err := runOneDigest(ctx, client, tsdbSvc, alertSvc, db, linkNames()); err != nil {
				consecutiveFailures++
				slog.Warn("ai: digest failed", "err", err, "consecutive_failures", consecutiveFailures)
				if consecutiveFailures >= 2 {
					_ = alertSvc.Create("ai_digest_failing", "warning", "Resumo diário de IA não está funcionando",
						"O resumo diário do assistente de IA falhou por 2 dias seguidos. Verifique o token e o orçamento em Configurações → Assistente de IA.", "")
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
}

func runOneDigest(ctx context.Context, client *Client, tsdbSvc *tsdb.Service, alertSvc *alerts.Service, db *storage.DB, names []string) error {
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	now := time.Now().Unix()
	ev, err := BuildEvidence(tsdbSvc, alertSvc, names, now-86400, now)
	if err != nil {
		return err
	}

	report, err := client.Analyze(callCtx, ev)
	if err != nil {
		return err
	}

	findingsJSON, _ := json.Marshal(report.Findings)
	return db.CreateAIReport(&storage.AIReport{
		Kind: "digest", Summary: report.Summary, Findings: string(findingsJSON),
		Recommendation: report.Recommendation, Confidence: report.Confidence,
	})
}
