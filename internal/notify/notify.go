// Package notify delivers alerts to external channels (webhook, Telegram,
// e-mail). It is wired into the alerts service as a best-effort observer: every
// alert that meets the configured minimum severity is dispatched asynchronously,
// so notification latency or failures never block alert creation.
package notify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const settingKey = "notifications"

// defaultWhatsAppURL is the zapvite messages endpoint used when none is set.
const defaultWhatsAppURL = "https://api.zapvite.com.br/api/v1/messages"

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

// WhatsAppCfg sends via the zapvite WhatsApp API (Bearer token; the token
// expires, so it is meant to be updated from the UI). The destination host is
// NOT configurable (see defaultWhatsAppURL) — unlike a generic webhook, this
// channel always attaches a real secret (the Bearer token), so letting an
// admin-editable URL field redirect it would let a system.write-scoped
// account exfiltrate the token to an attacker-controlled host.
type WhatsAppCfg struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
	Phone   string `json:"phone"`
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
	WhatsApp    WhatsAppCfg `json:"whatsapp"`
	Email       EmailCfg    `json:"email"`
}

// Service loads config from the secrets vault and dispatches notifications.
type Service struct {
	db     *storage.DB
	sec    secrets.Secrets
	client *http.Client
}

// NewService creates a notify Service. sec is where channel credentials
// (SMTP password, Telegram/WhatsApp tokens) are stored.
func NewService(db *storage.DB, sec secrets.Secrets) *Service {
	return &Service{db: db, sec: sec, client: &http.Client{Timeout: 10 * time.Second}}
}

// LoadConfig reads the persisted configuration (with defaults).
func (s *Service) LoadConfig() Config {
	c := Config{MinSeverity: "warning"}
	raw, err := s.sec.Get(settingKey)
	if err != nil {
		slog.Warn("notify: failed to read config from secrets vault", "err", err)
	}
	if raw != "" {
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
	return s.sec.Set(settingKey, string(out))
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

// NotifyRecovery delivers a "recovered" notice asynchronously, bypassing the
// min-severity gate: a recovery only fires after a matching outage already
// notified, so the user must always get the "voltou" even at min_severity=warning.
func (s *Service) NotifyRecovery(title, message string) {
	cfg := s.LoadConfig()
	go s.dispatch(cfg, "info", title, message)
}

// SendNow delivers synchronously and returns per-channel errors. Use it from
// short-lived contexts (CLI / systemd OnFailure) where the process exits before
// an async goroutine could run.
func (s *Service) SendNow(severity, title, message string) []error {
	cfg := s.LoadConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.send(ctx, cfg, severity, title, message)
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
	if cfg.WhatsApp.Enabled && cfg.WhatsApp.Token != "" && cfg.WhatsApp.Phone != "" {
		errs = append(errs, s.sendWhatsApp(ctx, cfg.WhatsApp, severity, title, message))
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
	case "whatsapp":
		return s.sendWhatsApp(ctx, cfg.WhatsApp, "info", t, m)
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
	// O esquema é conferido antes de a URL virar requisição (alerta
	// go/request-forgery do CodeQL).
	//
	// PARA QUE ISTO SERVE, E PARA QUE NÃO SERVE. Quem grava esta URL é um
	// admin com system.write, e mandar notificação para onde ele escolher é o
	// propósito do campo — bloquear destino interno seria quebrar o caso de uso
	// mais comum, que é um webhook num servidor da própria LAN. Isto NÃO é uma
	// defesa contra SSRF, e fingir que é seria pior do que não ter.
	//
	// O que ele fecha é outra coisa: sem checagem, o http.Client aceita
	// esquemas que não são requisição de rede. Um "file:///etc/linkguard-fw/
	// secret.key" gravado aí — por engano, por um script de provisionamento ou
	// por um backup restaurado de outra máquina — faria o processo LER UM
	// ARQUIVO LOCAL como root e mandar o conteúdo no corpo da resposta de teste
	// que o painel exibe. Exigir http/https elimina a classe.
	if err := checkWebhookURL(c.URL); err != nil {
		return err
	}
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

func (s *Service) sendWhatsApp(ctx context.Context, c WhatsAppCfg, severity, title, message string) error {
	body := fmt.Sprintf("%s *%s*\n%s", severityEmoji(severity), title, message)
	payload, _ := json.Marshal(map[string]string{"phone": c.Phone, "body": body})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, defaultWhatsAppURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("whatsapp: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("whatsapp: status %d", resp.StatusCode)
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
	// Os campos que entram em CABEÇALHO passam por headerSafe.
	//
	// Sem isso, um "\r\n" em qualquer um deles encerra o cabeçalho e o que vem
	// depois é interpretado pelo servidor SMTP como uma diretiva nova — um
	// "Bcc:" para um terceiro, ou o começo do corpo, escondendo o resto da
	// mensagem. É o alerta go/email-injection do CodeQL.
	//
	// `message` NÃO é sanitizado, e isso é deliberado: ele vai depois da linha
	// em branco, ou seja, no corpo, onde quebra de linha é o formato e não uma
	// injeção. Limpá-lo destruiria a única parte da notificação em que uma
	// mensagem de erro de várias linhas é legível.
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: [%s] %s\r\n\r\n%s\r\n",
		headerSafe(from), headerSafe(c.To), headerSafe(strings.ToUpper(severity)),
		headerSafe(title), message)
	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}
	if err := smtp.SendMail(addr, auth, from, strings.Split(c.To, ","), []byte(body)); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return nil
}

// checkWebhookURL exige que a URL do webhook seja uma requisição HTTP de
// verdade — nada de file://, gopher:// ou de um endereço vazio.
//
// A mensagem nomeia o esquema recusado porque quem vai ler é o admin corrigindo
// a própria configuração, e "URL inválida" não diz o que arrumar.
func checkWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("webhook: URL inválida: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook: a URL precisa começar com http:// ou https:// (veio %q)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook: a URL não tem endereço de destino")
	}
	return nil
}

// headerSafe deixa um valor seguro para ir num cabeçalho de e-mail.
//
// Troca CR, LF e NUL por espaço em vez de recusar a mensagem inteira: a
// notificação existe para AVISAR que algo deu errado, e é justamente o texto de
// um erro que tem chance de trazer uma quebra de linha. Recusar aqui faria o
// aviso não sair — que é o pior desfecho possível para este caminho, e o mesmo
// raciocínio da issue #60 sobre o --notify-down.
//
// O corte é feito nos três bytes que terminam ou truncam um cabeçalho; o resto
// do texto passa intacto, inclusive acentuação.
func headerSafe(v string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', 0:
			return ' '
		}
		return r
	}, v)
}

// buildMultipartMessage assembles a MIME multipart/mixed e-mail (RFC822
// headers + a text part + one base64 attachment part), ready to hand to
// smtp.SendMail. Split out from SendEmailAttachment so the message format is
// testable without a real SMTP connection.
func buildMultipartMessage(from, to, subject, body string, attachment []byte, filename string) ([]byte, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// Mesma proteção de sendEmail: os três campos vão para CABEÇALHO, e um
	// "\r\n" em qualquer um deles encerraria o bloco — aqui com um agravante,
	// porque a linha seguinte declara o boundary do multipart, e quebrá-la
	// desmonta o anexo inteiro. O `body` continua cru: ele é uma PARTE MIME,
	// escrita depois, onde quebra de linha é o formato.
	if _, err := fmt.Fprintf(&buf, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n",
		headerSafe(from), headerSafe(to), headerSafe(subject), w.Boundary()); err != nil {
		return nil, err
	}

	textPart, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}})
	if err != nil {
		return nil, fmt.Errorf("criar parte de texto: %w", err)
	}
	if _, err := textPart.Write([]byte(body)); err != nil {
		return nil, fmt.Errorf("escrever texto: %w", err)
	}

	attachPart, err := w.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"application/octet-stream"},
		"Content-Transfer-Encoding": {"base64"},
		"Content-Disposition":       {fmt.Sprintf(`attachment; filename=%q`, filename)},
	})
	if err != nil {
		return nil, fmt.Errorf("criar parte do anexo: %w", err)
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(attachment)))
	base64.StdEncoding.Encode(encoded, attachment)
	// RFC 2045 §6.8: base64 body content must be wrapped at 76 characters per
	// line. Without this, strict SMTP servers may reject or corrupt the
	// message — the small (26-byte) fixture in the existing test never
	// crossed one line, so this went unnoticed until a real-size attachment.
	const lineLen = 76
	for i := 0; i < len(encoded); i += lineLen {
		end := i + lineLen
		if end > len(encoded) {
			end = len(encoded)
		}
		if _, err := attachPart.Write(encoded[i:end]); err != nil {
			return nil, fmt.Errorf("escrever anexo: %w", err)
		}
		if _, err := attachPart.Write([]byte("\r\n")); err != nil {
			return nil, fmt.Errorf("escrever anexo: %w", err)
		}
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("fechar multipart: %w", err)
	}
	return buf.Bytes(), nil
}

// SendEmailAttachment sends an e-mail with a single binary attachment via the
// same SMTP config sendEmail uses. Alerts stay text-only via sendEmail — this
// is the one case (the periodic encrypted backup) that needs a real
// attachment.
func (s *Service) SendEmailAttachment(subject, body string, attachment []byte, filename string) error {
	cfg := s.LoadConfig().Email
	if !cfg.Enabled {
		return fmt.Errorf("e-mail não está habilitado em Notificações")
	}
	port := cfg.Port
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", cfg.Host, port)
	from := cfg.From
	if from == "" {
		from = cfg.Username
	}
	msg, err := buildMultipartMessage(from, cfg.To, subject, body, attachment, filename)
	if err != nil {
		return fmt.Errorf("montar e-mail: %w", err)
	}
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	if err := smtp.SendMail(addr, auth, from, strings.Split(cfg.To, ","), msg); err != nil {
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
