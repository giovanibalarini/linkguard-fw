package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/wireguard"
)

const vpnKey = "wireguard"

// VPNHandler manages the WireGuard road-warrior VPN (server config + clients).
type VPNHandler struct {
	db  *storage.DB
	sec secrets.Secrets
	svc *wireguard.Service
}

// NewVPNHandler creates a VPNHandler. sec is where the server and peer private
// keys are stored — the config JSON (including private keys) lives in the
// secrets vault, never in the plaintext settings table, so it can never leak
// through ExportSettings()/backups.
func NewVPNHandler(db *storage.DB, svc *wireguard.Service, sec secrets.Secrets) *VPNHandler {
	return &VPNHandler{db: db, sec: sec, svc: svc}
}

func (h *VPNHandler) load() wireguard.Config {
	c := wireguard.Defaults()
	raw, err := h.sec.Get(vpnKey)
	if err != nil {
		slog.Warn("vpn: failed to read config from secrets vault", "err", err)
	}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	if c.Peers == nil {
		c.Peers = []wireguard.Peer{}
	}
	return c
}

func (h *VPNHandler) save(c wireguard.Config) error {
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return h.sec.Set(vpnKey, string(out))
}

// vpnView is the API response: config with peer private keys redacted, plus the
// live `wg show` status.
type vpnView struct {
	Config wireguard.Config `json:"config"`
	Status string           `json:"status"`
}

func redact(c wireguard.Config) wireguard.Config {
	c.PrivateKey = ""
	peers := make([]wireguard.Peer, len(c.Peers))
	for i, p := range c.Peers {
		p.PrivateKey = ""
		peers[i] = p
	}
	c.Peers = peers
	return c
}

// Get returns the VPN config (secrets redacted) and live status.
func (h *VPNHandler) Get(w http.ResponseWriter, r *http.Request) {
	c := h.load()
	writeJSON(w, http.StatusOK, vpnView{Config: redact(c), Status: h.svc.Status(r.Context())})
}

// UpdateConfig updates server settings and enables/disables the tunnel. Server
// keys are generated on first use.
func (h *VPNHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled    bool   `json:"enabled"`
		ListenPort int    `json:"listen_port"`
		Subnet     string `json:"subnet"`
		Address    string `json:"address"`
		Endpoint   string `json:"endpoint"`
		DNS        string `json:"dns"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	c := h.load()
	if in.ListenPort > 0 {
		c.ListenPort = in.ListenPort
	}
	if s := strings.TrimSpace(in.Subnet); s != "" {
		c.Subnet = s
	}
	if a := strings.TrimSpace(in.Address); a != "" {
		c.Address = a
	}
	c.Endpoint = strings.TrimSpace(in.Endpoint)
	c.DNS = strings.TrimSpace(in.DNS)
	c.Enabled = in.Enabled

	if err := wireguard.ValidateConfig(c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Generate the server keypair the first time it is needed.
	if c.PrivateKey == "" || c.PublicKey == "" {
		priv, pub, err := wireguard.GenerateKeypair()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "gerar chave do servidor: "+err.Error())
			return
		}
		c.PrivateKey, c.PublicKey = priv, pub
	}

	if _, err := h.svc.Apply(r.Context(), c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.save(c); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "update", "vpn/config", "enabled="+boolStr(c.Enabled))
	writeJSON(w, http.StatusOK, vpnView{Config: redact(c), Status: h.svc.Status(r.Context())})
}

// AddPeer creates a client (keypair + next free IP) and re-applies the server.
func (h *VPNHandler) AddPeer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	name := strings.TrimSpace(in.Name)
	if err := wireguard.ValidatePeerName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c := h.load()
	ip, err := wireguard.NextAllowedIP(c)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	priv, pub, err := wireguard.GenerateKeypair()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	peer := wireguard.Peer{
		ID:         uuid.NewString(),
		Name:       name,
		PublicKey:  pub,
		PrivateKey: priv,
		AllowedIP:  ip,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	c.Peers = append(c.Peers, peer)

	if c.Enabled {
		if _, err := h.svc.Apply(r.Context(), c); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := h.save(c); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "add", "vpn/peer", peer.Name)
	// Return the freshly created peer WITH its config so the client can be set
	// up immediately (this is the only time the private key is exposed in the UI).
	writeJSON(w, http.StatusOK, map[string]any{
		"peer":   peer,
		"config": wireguard.ClientConfig(c, peer),
	})
}

// DeletePeer removes a client and re-applies the server.
func (h *VPNHandler) DeletePeer(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c := h.load()
	out := make([]wireguard.Peer, 0, len(c.Peers))
	var name string
	for _, p := range c.Peers {
		if p.ID == id {
			name = p.Name
			continue
		}
		out = append(out, p)
	}
	c.Peers = out
	if c.Enabled {
		if _, err := h.svc.Apply(r.Context(), c); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := h.save(c); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "delete", "vpn/peer", name)
	writeJSON(w, http.StatusOK, vpnView{Config: redact(c), Status: h.svc.Status(r.Context())})
}

// PeerConfig returns the importable client .conf for a peer.
func (h *VPNHandler) PeerConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c := h.load()
	for _, p := range c.Peers {
		if p.ID == id {
			writeJSON(w, http.StatusOK, map[string]string{"config": wireguard.ClientConfig(c, p)})
			return
		}
	}
	writeError(w, http.StatusNotFound, "cliente não encontrado")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
