// Package notify delivers alerts to external channels (webhook, Telegram,
// e-mail). It is wired into the alerts service as a best-effort observer: every
// alert that meets the configured minimum severity is dispatched asynchronously,
// so notification latency or failures never block alert creation.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const settingKey = "notifications"

// WebhookCfg posts a JSON payload to an arbitrary URL.
type WebhookCfg struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

// TelegramCfg sends via a Telegram bot.
type TelegramCfg struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
	ChatID  string `json:"chat_id"`
}

// EmailCfg sends via SMTP (STARTTLS, e.g. port 587).
type EmailCfg struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	To       string `json:"to"`
}

// Config is the persisted notification configuration.
type Config struct {
	MinSeverity string      `json:"min_severity"` // info | warning | critical
	Webhook     WebhookCfg  `json:"webhook"`
	Telegram    TelegramCfg `json:"telegram"`
	Email       EmailCfg    `json:"email"`
}

// Service loads config from settings and dispatches notifications.
type Service struct {
	db     *storage.DB
	client *http.Client
}

// NewService creates a notify Service.
func NewService(db *storage.DB) *Service {
	return &Service{db: db, client: &http.Client{Timeout: 10 * time.Second}}
}

// LoadConfig reads the persisted configuration (with defaults).
func (s *Service) LoadConfig() Config {
	c := Config{MinSeverity: "warning"}
	if raw, _ := s.db.GetSetting(settingKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	if c.MinSeverity == "" {
		c.MinSeverity = "warning"
	}
	return c
}

// SaveConfig persists the configuration.
func (s *Service) SaveConfig(c Config) error {
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.db.SetSetting(settingKey, string(out))
}

var severityRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

// Notify implements the alerts observer. It dispatches asynchronously and never
// blocks the caller.
func (s *Service) Notify(severity, title, message string) {
	cfg := s.LoadConfig()
	if severityRank[severity] < severityRank[cfg.MinSeverity] {
		return
	}
	go s.dispatch(cfg, severity, title, message)
}

func (s *Service) dispatch(cfg Config, severity, title, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, err := range s.send(ctx, cfg, severity, title, message) {
		if err != nil {
			slog.Warn("notify: delivery failed", "err", err)
		}
	}
}

// send delivers to every enabled channel and returns per-channel errors.
func (s *Service) send(ctx context.Context, cfg Config, severity, title, message string) []error {
	var errs []error
	if cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
		errs = append(errs, s.sendWebhook(ctx, cfg.Webhook, severity, title, message))
	}
	if cfg.Telegram.Enabled && cfg.Telegram.Token != "" && cfg.Telegram.ChatID != "" {
		errs = append(errs, s.sendTelegram(ctx, cfg.Telegram, severity, title, message))
	}
	if cfg.Email.Enabled && cfg.Email.Host != "" && cfg.Email.To != "" {
		errs = append(errs, s.sendEmail(cfg.Email, severity, title, message))
	}
	return errs
}

// Test sends a sample notification to one channel ("webhook"|"telegram"|"email")
// using the provided config, returning the channel error (nil on success).
func (s *Service) Test(ctx context.Context, channel string, cfg Config) error {
	const t = "LinkGuard FW — teste de notificação"
	const m = "Se você recebeu esta mensagem, o canal está configurado corretamente. ✅"
	switch channel {
	case "webhook":
		return s.sendWebhook(ctx, cfg.Webhook, "info", t, m)
	case "telegram":
		return s.sendTelegram(ctx, cfg.Telegram, "info", t, m)
	case "email":
		return s.sendEmail(cfg.Email, "info", t, m)
	default:
		return fmt.Errorf("canal desconhecido: %q", channel)
	}
}

func (s *Service) sendWebhook(ctx context.Context, c WebhookCfg, severity, title, message string) error {
	payload, _ := json.Marshal(map[string]string{
		"severity":  severity,
		"title":     title,
		"message":   message,
		"source":    "linkguard-fw",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: status %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) sendTelegram(ctx context.Context, c TelegramCfg, severity, title, message string) error {
	text := fmt.Sprintf("%s *%s*\n%s", severityEmoji(severity), title, message)
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.Token)
	form := url.Values{}
	form.Set("chat_id", c.ChatID)
	form.Set("text", text)
	form.Set("parse_mode", "Markdown")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram: status %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) sendEmail(c EmailCfg, severity, title, message string) error {
	port := c.Port
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", c.Host, port)
	from := c.From
	if from == "" {
		from = c.Username
	}
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: [%s] %s\r\n\r\n%s\r\n",
		from, c.To, strings.ToUpper(severity), title, message)
	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}
	if err := smtp.SendMail(addr, auth, from, strings.Split(c.To, ","), []byte(body)); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return nil
}

func severityEmoji(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "warning":
		return "🟠"
	default:
		return "🔵"
	}
}
