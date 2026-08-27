package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-fw/internal/bootstrapdeps"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const (
	wireGuardPackage = "wireguard-tools"
	qrencodePackage  = "qrencode"
)

// EndpointResolver chooses the client-facing endpoint. Main wires this to the
// selected link's enabled DDNS hostname and falls back to the validated
// explicit host.
type EndpointResolver func(linkID, explicitHost string) (string, error)

type QREncoder interface {
	Encode(ctx context.Context, value string) (dataURL string, err error)
}

type commandQREncoder struct{}

func (commandQREncoder) Encode(ctx context.Context, value string) (string, error) {
	cmd := exec.CommandContext(ctx, "qrencode", "-t", "SVG", "-o", "-", "-m", "1")
	cmd.Stdin = strings.NewReader(value) // secret never enters argv or process logs
	var out bytes.Buffer
	cmd.Stdout = &out
	// Deliberately discard stderr: a helper error must never echo the client
	// config (and private key) into an HTTP response or journal entry.
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("não foi possível gerar o QR code")
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(out.Bytes()), nil
}

type Overview struct {
	Config         Config `json:"config"`
	PublicKey      string `json:"public_key,omitempty"`
	Peers          []Peer `json:"peers"`
	Running        bool   `json:"running"`
	LastApplyOK    bool   `json:"last_apply_ok"`
	LastApplyError string `json:"last_apply_error,omitempty"`
	LastAppliedAt  int64  `json:"last_applied_at,omitempty"`
}

type Enrollment struct {
	Peer         Peer   `json:"peer"`
	ClientConfig string `json:"client_config"`
	QRDataURL    string `json:"qr_data_url,omitempty"`
	ApplyError   string `json:"apply_error,omitempty"`
	Warning      string `json:"warning,omitempty"`
}

type Service struct {
	db          *storage.DB
	secrets     secrets.Secrets
	exec        firewall.Executor
	installExec firewall.Executor
	configPath  string
	resolve     EndpointResolver
	qr          QREncoder
	now         func() time.Time
	mu          sync.Mutex
}

func NewService(db *storage.DB, sec secrets.Secrets, executor firewall.Executor) *Service {
	return &Service{
		db: db, secrets: sec, exec: executor, installExec: executor,
		configPath: ConfigPath, qr: commandQREncoder{}, now: time.Now,
	}
}

func (s *Service) SetInstallExecutor(executor firewall.Executor) {
	if executor != nil {
		s.installExec = executor
	}
}

func (s *Service) SetEndpointResolver(resolve EndpointResolver) { s.resolve = resolve }

func (s *Service) Config() (Config, error) {
	row, err := s.db.GetWireGuardConfig()
	if err != nil {
		return Config{}, err
	}
	if row == nil {
		return DefaultConfig(), nil
	}
	return configFromStorage(row), nil
}

func configFromStorage(row *storage.WireGuardConfig) Config {
	return Config{Enabled: row.Enabled, ListenPort: row.ListenPort, Address: row.Address,
		EndpointHost: row.EndpointHost, EndpointLinkID: row.EndpointLinkID}
}

func (s *Service) UpdateConfig(ctx context.Context, c Config) error {
	if err := ValidateConfig(c); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, err := s.db.GetWireGuardConfig()
	if err != nil {
		return err
	}
	row := storage.WireGuardConfig{Enabled: c.Enabled, ListenPort: c.ListenPort,
		Address: c.Address, EndpointHost: c.EndpointHost, EndpointLinkID: c.EndpointLinkID}
	if prior != nil {
		row.LastApplyOK, row.LastApplyError, row.LastAppliedAt = prior.LastApplyOK, prior.LastApplyError, prior.LastAppliedAt
	}
	if err := s.db.SaveWireGuardConfig(&row); err != nil {
		return err
	}
	return s.reconcileLocked(ctx)
}

func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconcileLocked(ctx)
}

func (s *Service) reconcileLocked(ctx context.Context) error {
	c, err := s.Config()
	if err == nil {
		// Sink validation is intentionally repeated for DB rows restored or
		// written by an older build. It runs before package/secret/file changes.
		err = ValidateConfig(c)
	}
	if err == nil {
		if c.Enabled {
			err = s.applyEnabled(ctx, c)
		} else {
			err = s.applyDisabled(ctx)
		}
	}
	s.recordApply(c, err)
	return err
}

func (s *Service) recordApply(c Config, applyErr error) {
	row, err := s.db.GetWireGuardConfig()
	if err != nil || row == nil {
		row = &storage.WireGuardConfig{Enabled: c.Enabled, ListenPort: c.ListenPort,
			Address: c.Address, EndpointHost: c.EndpointHost, EndpointLinkID: c.EndpointLinkID}
	}
	row.LastApplyOK = applyErr == nil
	row.LastAppliedAt = s.now().Unix()
	row.LastApplyError = ""
	if applyErr != nil {
		row.LastApplyError = applyErr.Error()
	}
	_ = s.db.SaveWireGuardConfig(row)
}

func (s *Service) applyDisabled(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	if active := s.isActive(ctx); active {
		if _, err := s.exec.Execute(ctx, "systemctl", "disable", "--now", ServiceName); err != nil {
			return fmt.Errorf("não foi possível parar o serviço WireGuard")
		}
	}
	if _, err := os.Lstat(s.configPath); err == nil {
		if _, err := s.exec.Execute(ctx, "rm", "-f", "--", s.configPath); err != nil {
			return fmt.Errorf("não foi possível remover a configuração WireGuard desativada")
		}
	}
	return nil
}

func (s *Service) applyEnabled(ctx context.Context, c Config) error {
	if s.exec.IsDryRun() {
		return nil
	}
	if _, err := bootstrapdeps.EnsureInstalled(ctx, s.installExec, wireGuardPackage, qrencodePackage); err != nil {
		return err
	}
	private, _, err := s.ensureServerKey()
	if err != nil {
		return fmt.Errorf("não foi possível preparar a identidade do servidor: %w", err)
	}
	storedPeers, err := s.db.ListWireGuardPeers()
	if err != nil {
		return err
	}
	for _, p := range storedPeers {
		group := storage.FirewallGroup{ID: p.FirewallGroupID, Name: "VPN — " + p.Username,
			ChainName: nftables.GroupChainName(p.FirewallGroupID), Enabled: true,
			CondSaddr: p.Address, Fallthrough: nftables.FallthroughContinue,
			Kind: nftables.GroupKindWireGuardPeer, Scope: nftables.ScopeForward,
			ConnState: nftables.ConnStateAny}
		if err := s.db.EnsureWireGuardPeerGroup(&group); err != nil {
			return fmt.Errorf("não foi possível reconciliar o grupo do peer %s: %w", p.UserID, err)
		}
	}
	peers := peersFromStorage(storedPeers)
	content, err := RenderServerConfig(c, private, peers)
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.configPath)
	if _, err := s.exec.Execute(ctx, "install", "-d", "-m", "0700", "-o", "root", "-g", "root", dir); err != nil {
		return fmt.Errorf("não foi possível proteger o diretório do WireGuard")
	}
	old, _ := os.ReadFile(s.configPath)
	changed := string(old) != content
	if changed {
		tmp := s.configPath + ".tmp-" + uuid.NewString()
		cleanup := true
		defer func() {
			if cleanup {
				_, _ = s.exec.Execute(context.Background(), "rm", "-f", "--", tmp)
			}
		}()
		if err := s.exec.WriteFile(tmp, []byte(content), 0o600); err != nil {
			return fmt.Errorf("não foi possível gravar a configuração WireGuard")
		}
		if _, err := s.exec.Execute(ctx, "chmod", "0600", tmp); err != nil {
			return fmt.Errorf("não foi possível proteger a configuração WireGuard")
		}
		if _, err := s.exec.Execute(ctx, "chown", "root:root", tmp); err != nil {
			return fmt.Errorf("não foi possível definir o dono da configuração WireGuard")
		}
		if _, err := s.exec.ExecuteRead(ctx, "wg-quick", "strip", tmp); err != nil {
			return fmt.Errorf("a configuração WireGuard foi recusada pelo validador; nada foi aplicado")
		}
		if _, err := s.exec.Execute(ctx, "mv", "--", tmp, s.configPath); err != nil {
			return fmt.Errorf("não foi possível ativar a configuração WireGuard validada")
		}
		cleanup = false
	}
	// Reassert ownership even when bytes are unchanged: package upgrades or a
	// manual chmod must not make the private server key world-readable.
	if _, err := s.exec.Execute(ctx, "chmod", "0600", s.configPath); err != nil {
		return fmt.Errorf("não foi possível proteger a configuração WireGuard")
	}
	if _, err := s.exec.Execute(ctx, "chown", "root:root", s.configPath); err != nil {
		return fmt.Errorf("não foi possível definir o dono da configuração WireGuard")
	}
	if _, err := s.exec.Execute(ctx, "systemctl", "enable", ServiceName); err != nil {
		return fmt.Errorf("não foi possível habilitar o serviço WireGuard")
	}
	if changed {
		if _, err := s.exec.Execute(ctx, "systemctl", "restart", ServiceName); err != nil {
			return fmt.Errorf("não foi possível iniciar o serviço WireGuard")
		}
	} else if !s.isActive(ctx) {
		if _, err := s.exec.Execute(ctx, "systemctl", "start", ServiceName); err != nil {
			return fmt.Errorf("não foi possível iniciar o serviço WireGuard")
		}
	}
	return nil
}

func (s *Service) ensureServerKey() (private, public string, err error) {
	private, err = s.secrets.Get(ServerSecret)
	if err != nil {
		return "", "", err
	}
	if private == "" {
		private, public, err = GenerateKeypair()
		if err != nil {
			return "", "", err
		}
		if err := s.secrets.Set(ServerSecret, private); err != nil {
			return "", "", err
		}
		return private, public, nil
	}
	public, err = PublicKey(private)
	return private, public, err
}

func peersFromStorage(rows []storage.WireGuardPeer) []Peer {
	out := make([]Peer, 0, len(rows))
	for _, p := range rows {
		out = append(out, Peer{UserID: p.UserID, Username: p.Username, PublicKey: p.PublicKey,
			Address: p.Address, FirewallGroupID: p.FirewallGroupID,
			CreatedAt: p.CreatedAt.Unix(), RotatedAt: p.RotatedAt.Unix()})
	}
	return out
}

func (s *Service) resolveEndpoint(c Config) (string, error) {
	host := c.EndpointHost
	if s.resolve != nil {
		var err error
		host, err = s.resolve(c.EndpointLinkID, c.EndpointHost)
		if err != nil {
			return "", err
		}
	}
	if !validEndpointHost(host) {
		return "", fmt.Errorf("configure um hostname/IP público ou selecione um link com DDNS habilitado")
	}
	return host, nil
}

func (s *Service) Enroll(ctx context.Context, userID string) (Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.Config()
	if err != nil {
		return Enrollment{}, err
	}
	if err := ValidateConfig(c); err != nil {
		return Enrollment{}, err
	}
	if !c.Enabled {
		return Enrollment{}, fmt.Errorf("ative o WireGuard antes de enrolar um usuário")
	}
	endpoint, err := s.resolveEndpoint(c)
	if err != nil {
		return Enrollment{}, err
	}
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return Enrollment{}, err
	}
	if user == nil {
		return Enrollment{}, fmt.Errorf("usuário local não encontrado")
	}
	stored, err := s.db.ListWireGuardPeers()
	if err != nil {
		return Enrollment{}, err
	}
	current, err := s.db.GetWireGuardPeer(userID)
	if err != nil {
		return Enrollment{}, err
	}
	address := ""
	groupID := ""
	if current != nil {
		address, groupID = current.Address, current.FirewallGroupID
	} else {
		address, err = NextAddress(c, peersFromStorage(stored))
		if err != nil {
			return Enrollment{}, err
		}
		groupID = uuid.NewString()
	}
	clientPrivate, clientPublic, err := GenerateKeypair()
	if err != nil {
		return Enrollment{}, err
	}
	serverPrivate, serverPublic, err := s.ensureServerKey()
	if err != nil {
		return Enrollment{}, err
	}
	_ = serverPrivate // never leaves this method; public is all clients need
	peer := Peer{UserID: userID, Username: user.Username, PublicKey: clientPublic,
		Address: address, FirewallGroupID: groupID}
	clientConfig, err := RenderClientConfig(c, serverPublic, peer, clientPrivate, endpoint)
	if err != nil {
		return Enrollment{}, err
	}
	secretName := "wireguard_peer_private_" + uuid.NewString()
	if err := s.secrets.Set(secretName, clientPrivate); err != nil {
		return Enrollment{}, err
	}
	row := storage.WireGuardPeer{UserID: userID, PublicKey: clientPublic, Address: address,
		SecretName: secretName, FirewallGroupID: groupID}
	group := storage.FirewallGroup{ID: groupID, Name: "VPN — " + user.Username,
		ChainName: nftables.GroupChainName(groupID), Enabled: true, CondSaddr: address,
		Fallthrough: nftables.FallthroughContinue, Kind: nftables.GroupKindWireGuardPeer,
		Scope: nftables.ScopeForward, ConnState: nftables.ConnStateAny}
	old, err := s.db.UpsertWireGuardPeer(&row, &group)
	if err != nil {
		_ = s.secrets.Delete(secretName)
		return Enrollment{}, err
	}
	if old != nil {
		_ = s.secrets.Delete(old.SecretName)
	}
	peer.CreatedAt, peer.RotatedAt = row.CreatedAt.Unix(), row.RotatedAt.Unix()
	result := Enrollment{Peer: peer, ClientConfig: clientConfig}
	if applyErr := s.reconcileLocked(ctx); applyErr != nil {
		// Persistence succeeded and this is the only delivery of the private
		// config. Return it with an honest runtime error instead of losing it.
		result.ApplyError = applyErr.Error()
	}
	if s.qr != nil {
		qr, qrErr := s.qr.Encode(ctx, clientConfig)
		if qrErr != nil {
			result.Warning = qrErr.Error()
		} else {
			result.QRDataURL = qr
		}
	}
	return result, nil
}

func (s *Service) Revoke(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed, err := s.db.DeleteWireGuardPeer(userID)
	if err != nil || removed == nil {
		return err
	}
	secretErr := s.secrets.Delete(removed.SecretName)
	applyErr := s.reconcileLocked(ctx)
	if secretErr != nil {
		return secretErr
	}
	return applyErr
}

func (s *Service) Overview(ctx context.Context) (Overview, error) {
	c, err := s.Config()
	if err != nil {
		return Overview{}, err
	}
	rows, err := s.db.ListWireGuardPeers()
	if err != nil {
		return Overview{}, err
	}
	row, err := s.db.GetWireGuardConfig()
	if err != nil {
		return Overview{}, err
	}
	public := ""
	if private, err := s.secrets.Get(ServerSecret); err == nil && private != "" {
		public, _ = PublicKey(private)
	}
	out := Overview{Config: c, PublicKey: public, Peers: peersFromStorage(rows), Running: s.isActive(ctx)}
	if row != nil {
		out.LastApplyOK, out.LastApplyError, out.LastAppliedAt = row.LastApplyOK, row.LastApplyError, row.LastAppliedAt
	}
	return out, nil
}

func (s *Service) isActive(ctx context.Context) bool {
	out, err := s.exec.ExecuteRead(ctx, "systemctl", "is-active", ServiceName)
	return err == nil && strings.TrimSpace(out) == "active"
}

func (s *Service) InputPort() (bool, int, error) {
	c, err := s.Config()
	if err != nil {
		return false, 0, err
	}
	if err := ValidateConfig(c); err != nil {
		return false, 0, err
	}
	return c.Enabled, c.ListenPort, nil
}

// DNSBinding returns the tunnel address/network unbound must listen on and
// authorize. Both are derived from one validated prefix, so they cannot drift.
func (s *Service) DNSBinding() (address, network string, enabled bool, err error) {
	c, err := s.Config()
	if err != nil {
		return "", "", false, err
	}
	if err := ValidateConfig(c); err != nil {
		return "", "", false, err
	}
	if !c.Enabled {
		return "", "", false, nil
	}
	prefix, _ := netip.ParsePrefix(c.Address)
	return prefix.Addr().String(), prefix.Masked().String(), true, nil
}
