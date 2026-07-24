package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
)

// ErrBudgetExceeded is returned by Analyze when the monthly spend cap has
// been reached — checked before any network call.
var ErrBudgetExceeded = errors.New("ai: monthly budget exceeded")

// ErrTokenNotConfigured is returned by Analyze when no API token is set.
var ErrTokenNotConfigured = errors.New("ai: no API token configured")

const tokenSecretName = "ai_api_token"

// Report is the model's structured answer. Recommendation is ALWAYS plain
// text for a human to read — see TestReportRecommendationIsPlainStringField
// and the Global Constraints in this plan's document. Nothing in this
// package, or any caller, may treat it as an executable instruction.
type Report struct {
	Summary        string   `json:"summary"`
	Findings       []string `json:"findings"`
	Recommendation string   `json:"recommendation"`
	Confidence     string   `json:"confidence"`
}

// Client is the thin wrapper around the Claude API used by both triggers
// (immediate.go, digest.go).
type Client struct {
	sec    secrets.Secrets
	budget *BudgetGuard
	cfg    func() Config
}

// NewClient creates a Client. cfg is called fresh on every Analyze so a
// config change in the UI (model, effort) takes effect without a restart —
// same pattern as balancer.Monitor.SustainThreshold.
func NewClient(sec secrets.Secrets, budget *BudgetGuard, cfg func() Config) *Client {
	return &Client{sec: sec, budget: budget, cfg: cfg}
}

const systemPrompt = `Você analisa a saúde de links de internet (WAN) de um firewall multi-WAN a
partir de fatos já resumidos — nunca dados brutos. Responda ESTRITAMENTE com um
objeto JSON, sem nenhum texto antes ou depois, no formato:
{"summary": "1-2 frases", "findings": ["achado específico com número", ...],
"recommendation": "texto livre para um humano ler e decidir — nunca um
comando", "confidence": "alta|média|baixa"}
Sua recomendação NUNCA é executada automaticamente — é sempre lida por um
administrador humano, que decide o que fazer.`

// Analyze sends the evidence to the model and returns its structured Report.
// Checks the budget guard and token presence before any network call.
func (c *Client) Analyze(ctx context.Context, ev Evidence) (Report, error) {
	if err := c.budget.Check(); err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrBudgetExceeded, err)
	}

	token, err := c.sec.Get(tokenSecretName)
	if err != nil {
		return Report{}, fmt.Errorf("read AI token: %w", err)
	}
	if strings.TrimSpace(token) == "" {
		return Report{}, ErrTokenNotConfigured
	}

	evJSON, err := json.Marshal(ev)
	if err != nil {
		return Report{}, fmt.Errorf("marshal evidence: %w", err)
	}

	cfg := c.cfg()
	client := anthropic.NewClient(option.WithAPIKey(token))

	resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(cfg.Model),
		MaxTokens: 1024,
		Thinking:  anthropic.ThinkingConfigParamUnion{OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{}},
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(string(evJSON))),
		},
	})
	if err != nil {
		return Report{}, fmt.Errorf("anthropic API call: %w", err)
	}

	// resp.Usage carries InputTokens/OutputTokens on every Messages response
	// (confirmed via `go doc` against the installed SDK version, v1.60.0).
	cost := estimateCostUSD(cfg.Model, resp.Usage.InputTokens, resp.Usage.OutputTokens)
	if err := c.budget.RecordSpend(cost); err != nil {
		// The call already succeeded and cost real money — a bookkeeping
		// failure here must not discard the report the caller is about to
		// use, so this is logged (not returned/fatal): losing this warning
		// would mean spend silently drifts from the real total charged by
		// the API, undermining the budget guard's whole purpose.
		slog.Warn("ai: record spend failed — budget tracking may drift from actual spend", "cost_usd", cost, "err", err)
	}

	// resp.Content may interleave ThinkingBlock and TextBlock entries (adaptive
	// thinking is enabled above). ThinkingBlock is a distinct Go type from
	// TextBlock (confirmed via `go doc anthropic ContentBlockUnion.AsAny`), so
	// the type assertion below only ever matches actual TextBlock variants —
	// a thinking block fails the assertion and is skipped, never fed to
	// json.Unmarshal. This loop cannot silently swallow the real answer by
	// mistaking thinking prose for the JSON-bearing block.
	var report Report
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			if uerr := json.Unmarshal([]byte(tb.Text), &report); uerr == nil {
				return report, nil
			}
		}
	}
	return Report{}, fmt.Errorf("no parseable JSON report in the model's response")
}

// estimateCostUSD prices a call at the per-model rates the admin sees in the
// UI (see the spec's model table). Prices are per-million-token; keep this in
// sync with docs/superpowers/specs/2026-07-24-camada-de-ia-byok-design.md §5
// if pricing changes. Unknown/future model names deliberately default to the
// Opus (most expensive) rate — an unrecognized model must never be
// under-priced against the budget guard, so the safe direction on a mismatch
// is to overestimate cost, not guess low.
func estimateCostUSD(model string, inputTokens, outputTokens int64) float64 {
	var inPer1M, outPer1M float64
	switch model {
	case "claude-opus-4-8":
		inPer1M, outPer1M = 5.0, 25.0
	case "claude-sonnet-5":
		inPer1M, outPer1M = 3.0, 15.0
	case "claude-haiku-4-5":
		inPer1M, outPer1M = 1.0, 5.0
	default:
		inPer1M, outPer1M = 5.0, 25.0 // conservative default: price as Opus
	}
	return float64(inputTokens)/1_000_000*inPer1M + float64(outputTokens)/1_000_000*outPer1M
}
