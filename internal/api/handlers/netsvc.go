package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// Os validadores estritos para valores renderizados em configs de unbound/Kea
// (validate.Domain, validate.Iface, validate.NormalizeMAC) moraram aqui até
// 2026-08-17. Foram para internal/validate porque a restauração de backup
// aplica exatamente as mesmas regras sem passar por handler nenhum, e não pode
// importar este pacote (seria ciclo). Ver o doc de internal/validate.

// NetsvcHandler manages DHCP + DNS through the configured backend provider
// (Kea + unbound). Config and lists live in the DB; the provider renders the
// engine configs and applies them.
type NetsvcHandler struct {
	db       *storage.DB
	provider netsvc.Provider
	alertSvc *alerts.Service
	applier  *autoApplier
	// nftSvc aplica a parte de firewall da tela de DNS (#124). Opcional: um
	// handler sem ele continua aplicando DHCP/DNS normalmente.
	nftSvc *nftables.Service
}

// autoApplyDelay is how long the handler waits for edits to settle before
// applying — long enough to coalesce a burst of saves, short enough to feel
// instant.
const autoApplyDelay = 1500 * time.Millisecond

// applyBudget is how long an apply may take end to end, and it is
// deliberately measured from a package download, not from an HTTP request.
//
// The context is also detached from the client's (context.WithoutCancel):
// when the admin's browser gives up, the apt LinkGuard started does NOT die
// with it — systemd-run's transient unit finishes the transaction — so
// cancelling here would only make LinkGuard report a failure that is not
// happening (503 "não conseguiu instalar", CRITICAL alert, and the single
// dpkg-lock retry burned) while the install completes successfully. Better
// to keep the work alive and record its true outcome in netsvc_last_apply,
// which the panel reads back even if this response never reaches anyone.
const applyBudget = 15 * time.Minute

// NewNetsvcHandler creates a NetsvcHandler. Saving any DHCP/DNS change now
// auto-applies (debounced), so the admin no longer needs a separate "Aplicar".
func NewNetsvcHandler(db *storage.DB, provider netsvc.Provider, alertSvc *alerts.Service, nftSvc *nftables.Service) *NetsvcHandler {
	h := &NetsvcHandler{db: db, provider: provider, alertSvc: alertSvc, nftSvc: nftSvc}
	h.applier = newAutoApplier(autoApplyDelay, func() {
		// Mesmo orçamento do "Aplicar agora": o auto-apply também pode cair
		// no caminho que instala kea/unbound.
		ctx, cancel := context.WithTimeout(context.Background(), applyBudget)
		defer cancel()
		_ = h.doReload(ctx)
	})
	return h
}

const netsvcCfgKey = "netsvc_config"
const netsvcApplyStatusKey = "netsvc_last_apply"

// applyStatus is the persisted result of the most recent (auto or manual) apply,
// surfaced in the UI so an async failure isn't silent.
//
// Warning is the third state between "failed" and "everything you
// configured is in effect" (I-7): the apply itself worked, but the backend
// had to drop list entries it could not render (an invalid blocklist
// domain, a malformed upstream, an NTP server that doesn't parse). Keeping
// that in the journal only meant the panel went on displaying values the
// daemon never received, with an "ok" badge over them.
type applyStatus struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Warning string `json:"warning,omitempty"`
	At      int64  `json:"at"` // unix seconds
}

// doReload regenerates and gracefully reloads the backend, records the result,
// and alerts on failure. Shared by the debounced auto-apply and the manual
// "Aplicar agora" button.
func (h *NetsvcHandler) doReload(ctx context.Context) error {
	bl, _ := h.db.ListDNSBlocklist()
	res, err := h.provider.ReloadConfigs(ctx, h.getConfig(), h.reservationsForProvider(), bl, h.ntpServerOption())
	st := applyStatus{OK: err == nil, At: time.Now().Unix()}
	if len(res.Warnings) > 0 {
		// Applied, but not everything the admin configured got through —
		// see applyStatus.Warning (I-7).
		st.Warning = strings.Join(res.Warnings, " ")
		// "com ressalvas", e não "com entradas descartadas": desde que o
		// dns-root-data ausente virou aviso em vez de aborto (I-2), nem todo
		// aviso é uma entrada que o backend teve de largar.
		slog.Warn("DHCP/DNS aplicado com ressalvas", "avisos", res.Warnings)
	}
	if err != nil {
		st.Error = err.Error()
		if h.alertSvc != nil {
			// A missing/uninstallable package is its own condition, with its
			// own recovery — not a "Firewall Rule Error" (see
			// alerts.NetsvcDepsMissing).
			var prereq *netsvc.PrereqError
			if errors.As(err, &prereq) {
				_ = h.alertSvc.NetsvcDepsMissing(prereq.Error())
			} else {
				_ = h.alertSvc.RuleError("Falha ao aplicar DHCP/DNS: " + err.Error())
			}
		}
	} else if h.alertSvc != nil {
		switch {
		case len(res.Installed) > 0:
			// The transition: LinkGuard brought in what the admin's feature
			// needed. Recorded (and the missing-deps alert closed) exactly
			// once, on the apply that installed it.
			_ = h.alertSvc.NetsvcDepsOK(strings.Join(res.Installed, ", "))
		default:
			// Nothing was installed and the apply worked — including the case
			// where the admin fixed it by hand over SSH. Close a stale
			// missing-deps alert silently: no recovery row, no notification,
			// just an alert that stops being red for a problem that no longer
			// exists.
			h.alertSvc.AutoResolve(alerts.TypeNetsvcDepsMissing, "")
		}
	}
	if b, mErr := json.Marshal(st); mErr == nil {
		_ = h.db.SetSetting(netsvcApplyStatusKey, string(b))
	}

	// O controle de fuga de DNS (#124) é firewall, não configuração de daemon,
	// mas nasce da MESMA tela e da mesma configuração — então é reconciliado
	// aqui, junto. Aplicado mesmo quando o reload do Kea/unbound falhou: as
	// regras não dependem do daemon ter subido, e deixar o redirecionamento
	// para trás porque o unbound reclamou de outra coisa seria surpresa.
	h.reconcileDNSGuard(ctx)
	return err
}

// reconcileDNSGuard traduz a configuração da tela de DNS para o firewall.
//
// O resolver é o próprio endereço que o DHCP anuncia aos clientes: se a caixa
// diz "use este resolver", é para ele que a consulta capturada tem de ir.
func (h *NetsvcHandler) reconcileDNSGuard(ctx context.Context) {
	if h.nftSvc == nil {
		return
	}
	cfg := h.getConfig()
	resolver := ""
	if len(cfg.DNSToClients) > 0 {
		resolver = cfg.DNSToClients[0]
	}
	if resolver == "" {
		resolver = cfg.Gateway
	}
	if err := h.nftSvc.EnsureDNSGuard(ctx, nftables.DNSGuardConfig{
		ForceLocal:   cfg.ForceLocalDNS,
		BlockDoT:     cfg.BlockDoT,
		LANInterface: cfg.Interface,
		Resolver:     resolver,
		ExceptIPs:    cfg.DNSExceptIPs,
	}); err != nil {
		slog.Warn("não foi possível reconciliar o controle de fuga de DNS", "err", err)
	}
}

// scheduleApply arms the debounced auto-apply after a mutation.
func (h *NetsvcHandler) scheduleApply() {
	if h.applier != nil {
		h.applier.schedule()
	}
}

// lastApplyStatus returns the persisted result of the most recent apply, or
// nil if nothing has been applied yet. A fresh install must not report this
// as a failure — "never attempted" and "attempted and failed" are different
// states, and collapsing them (via the Go zero value, OK: false) previously
// showed a false "última aplicação falhou" banner on every new install.
func (h *NetsvcHandler) lastApplyStatus() *applyStatus {
	raw, _ := h.db.GetSetting(netsvcApplyStatusKey)
	if raw == "" {
		return nil
	}
	var st applyStatus
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil
	}
	return &st
}

// netsvcConfigFromDB reads the persisted DHCP/DNS config, defaulting when
// unset. Package-level (not solely a NetsvcHandler method) so NTPHandler
// can reuse it too — e.g. to read the LAN CIDR for the chrony `allow` line
// and the firewall's Gateway for the DHCP ntp-servers option — without
// either handler owning the other's settings key or duplicating the
// unmarshal logic.
func netsvcConfigFromDB(db *storage.DB) netsvc.Config {
	cfg := netsvc.DefaultConfig()
	if raw, _ := db.GetSetting(netsvcCfgKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

func (h *NetsvcHandler) getConfig() netsvc.Config {
	return netsvcConfigFromDB(h.db)
}

func (h *NetsvcHandler) saveConfig(c netsvc.Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return h.db.SetSetting(netsvcCfgKey, string(b))
}

// ntpServerOption returns the firewall's LAN IP to advertise as DHCP
// option 42 (ntp-servers) when "serve NTP to the LAN" is genuinely in
// effect — ServeLAN on AND at least one network actually allowed — or ""
// otherwise. The exact input keaunbound.GenerateKeaConfig expects. Reads
// internal/timesync's persisted config directly (same package as ntp.go,
// which owns ntpCfgKey) rather than either package importing the other's
// Config type: the generator stays a pure function of its inputs, and
// neither handler owns the other's settings key — see
// docs/superpowers/specs/2026-08-11-ntp-server-for-lan-design.md §5.
//
// Checking AllowedNetworks too (not just ServeLAN) matters: the spec's
// explicit "serving on, allowed list empty" state means chrony's own
// `allow` directives are empty and chronyd refuses every client. Handing
// that dead address to a DHCP client via option 42 is worse than not
// advertising at all — a client that feeds it straight to
// systemd-timesyncd (which, unlike chrony, has no separate pool fallback)
// ends up with exactly one permanently unreachable time source.
func (h *NetsvcHandler) ntpServerOption() string {
	var ntpCfg timesync.Config
	if raw, _ := h.db.GetSetting(ntpCfgKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &ntpCfg)
	}
	if !ntpCfg.ServeLAN || len(ntpCfg.AllowedNetworks) == 0 {
		return ""
	}
	return h.getConfig().Gateway
}

func (h *NetsvcHandler) reservationsForProvider() []netsvc.Reservation {
	rs, _ := h.db.ListDHCPReservations()
	out := make([]netsvc.Reservation, 0, len(rs))
	for _, r := range rs {
		out = append(out, netsvc.Reservation{MAC: r.MAC, IP: r.IP, Hostname: r.Hostname})
	}
	return out
}

// ─── DHCP ────────────────────────────────────────────────────────────────────

// GetDHCP returns the DHCP config, reservations and live leases.
func (h *NetsvcHandler) GetDHCP(w http.ResponseWriter, r *http.Request) {
	rs, _ := h.db.ListDHCPReservations()
	if rs == nil {
		rs = []storage.DHCPReservation{}
	}
	leases, err := h.provider.Leases(r.Context())
	if err != nil {
		leases = []netsvc.Lease{} // backend not active yet (pre-cutover)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":       h.getConfig(),
		"reservations": rs,
		"leases":       leases,
		"backend":      h.provider.Backend(),
		"last_apply":   h.lastApplyStatus(),
	})
}

// UpdateDHCPConfig updates the DHCP-related settings.
func (h *NetsvcHandler) UpdateDHCPConfig(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Interface    string   `json:"interface"`
		SubnetCIDR   string   `json:"subnet_cidr"`
		RangeStart   string   `json:"range_start"`
		RangeEnd     string   `json:"range_end"`
		Gateway      string   `json:"gateway"`
		LeaseHours   int      `json:"lease_hours"`
		DNSToClients []string `json:"dns_to_clients"`
		DomainSuffix string   `json:"domain_suffix"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Validate every field: some (gateway, subnet, domain suffix) are rendered
	// into unbound.conf by string concatenation, so an unvalidated value could
	// inject config directives.
	iface := strings.TrimSpace(b.Interface)
	subnet := strings.TrimSpace(b.SubnetCIDR)
	rStart := strings.TrimSpace(b.RangeStart)
	rEnd := strings.TrimSpace(b.RangeEnd)
	gw := strings.TrimSpace(b.Gateway)
	suffix := strings.TrimSpace(b.DomainSuffix)
	if iface != "" && !validate.Iface(iface) {
		writeError(w, http.StatusBadRequest, "interface inválida")
		return
	}
	if subnet != "" {
		if _, _, err := net.ParseCIDR(subnet); err != nil {
			writeError(w, http.StatusBadRequest, "sub-rede inválida")
			return
		}
	}
	dns := []string{}
	for _, d := range b.DNSToClients {
		if d = strings.TrimSpace(d); d != "" {
			dns = append(dns, d)
		}
	}
	cfg := h.getConfig()
	cfg.Interface, cfg.SubnetCIDR = iface, subnet
	cfg.RangeStart, cfg.RangeEnd = rStart, rEnd
	cfg.Gateway, cfg.LeaseHours = gw, b.LeaseHours
	cfg.DNSToClients, cfg.DomainSuffix = dns, suffix

	// A COERÊNCIA ENTRE OS CAMPOS, que nenhuma validação campo-a-campo pegava
	// (#161). Endereço bem formado mas fora da sub-rede, ou IPv6 onde o daemon
	// exige IPv4, era aceito com 200 e recusado depois pelo kea ou pelo
	// unbound — travando TODA alteração de DHCP/DNS seguinte, com a mensagem
	// do daemon e sem o nome do campo culpado.
	if err := netsvc.ValidaConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.saveConfig(cfg); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "dhcp.config", "netsvc", "")
	h.scheduleApply()
	writeJSON(w, http.StatusOK, cfg)
}

// UpsertReservation creates/updates a DHCP reservation (by MAC).
func (h *NetsvcHandler) UpsertReservation(w http.ResponseWriter, r *http.Request) {
	var b struct{ MAC, IP, Hostname string }
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// CANÔNICO, e não só "parseável" (#161). net.ParseMAC aceita a grafia do
	// Windows (aa-bb-cc-dd-ee-ff) e a da Cisco (aabb.ccdd.eeff), e
	// NormalizeMAC só passa para minúsculas — o valor ia para o banco na grafia
	// original e o kea recusava a config inteira com "invalid host identifier
	// value". Pior: o MAC é a chave primária da tabela, então a linha ruim só
	// saía com um DELETE mandando exatamente a mesma grafia esquisita.
	//
	// É o mesmo furo que macParaNft fecha do lado do nftables. Estava nos dois
	// lugares, e eu só tinha olhado um.
	mac := validate.MACCanonico(b.MAC)
	if mac == "" {
		writeError(w, http.StatusBadRequest,
			"endereço físico inválido: use a forma aa:bb:cc:dd:ee:ff (com dois-pontos)")
		return
	}
	// IPv4 E NÃO net.ParseIP, e a diferença é a issue #152.
	//
	// net.ParseIP aceita IPv6, e o endereço ia para o banco com um 200 na
	// resposta — o apply é assíncrono, então o handler responde antes de alguém
	// tentar usar o valor. Depois, o `kea-dhcp4 -t` recusa a config inteira e
	// NADA é aplicado: nem faixa nova, nem DNS aos clientes, nem outra reserva.
	// E a linha ruim continua no banco, re-renderizada em todo apply seguinte.
	//
	// O caminho ficou mais provável com a #119: a tela de Hosts passou a mostrar
	// o endereço IPv6 de um aparelho, e é de lá que o admin copia.
	if !netsvc.DentroDaSubrede(strings.TrimSpace(b.IP), h.getConfig().SubnetCIDR) {
		// Medido no kea-dhcp4 2.6.3: "specified reservation ... is not within
		// the IPv4 subnet". É a #152 com outro valor — a guarda de família não
		// pega, e o efeito é o mesmo: nada mais é aplicado.
		writeError(w, http.StatusBadRequest,
			"a reserva precisa estar dentro da sub-rede servida ("+h.getConfig().SubnetCIDR+"); fora dela o servidor de DHCP recusa a configuração inteira")
		return
	}
	if !validate.IPv4(b.IP) {
		writeError(w, http.StatusBadRequest,
			"reserva de DHCP precisa de um endereço IPv4: o servidor de DHCP desta caixa é IPv4, e um endereço IPv6 aqui faria toda alteração de DHCP/DNS parar de ser aplicada")
		return
	}
	if err := h.db.UpsertDHCPReservation(mac, strings.TrimSpace(b.IP), strings.TrimSpace(b.Hostname)); err != nil {
		// A mensagem nomeia o MAC dono de propósito (issue #59). Sem ele o admin
		// descobre que não pode usar aquele IP e não descobre qual reserva
		// remover para poder — e a lista da tela é por MAC, não por IP.
		//
		// 409 e não 400: o pedido está bem formado, o que conflita é o estado.
		var taken *storage.ErrDHCPIPTaken
		if errors.As(err, &taken) {
			writeError(w, http.StatusConflict, taken.Error())
			return
		}
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "dhcp.reservation.set", "mac:"+mac, b.IP)
	h.scheduleApply()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// DeleteReservation removes a reservation by MAC.
func (h *NetsvcHandler) DeleteReservation(w http.ResponseWriter, r *http.Request) {
	var b struct{ MAC string }
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mac := validate.NormalizeMAC(b.MAC)
	if mac == "" {
		writeError(w, http.StatusBadRequest, "MAC inválido")
		return
	}
	if err := h.db.DeleteDHCPReservation(mac); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "dhcp.reservation.del", "mac:"+mac, "")
	h.scheduleApply()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── DNS ─────────────────────────────────────────────────────────────────────

// GetDNS returns the DNS config and blocklist.
func (h *NetsvcHandler) GetDNS(w http.ResponseWriter, r *http.Request) {
	bl, _ := h.db.ListDNSBlocklist()
	if bl == nil {
		bl = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":     h.getConfig(),
		"blocklist":  bl,
		"backend":    h.provider.Backend(),
		"last_apply": h.lastApplyStatus(),
	})
}

// UpdateDNSConfig updates the DNS-related settings.
func (h *NetsvcHandler) UpdateDNSConfig(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Upstreams  []string `json:"upstreams"`
		LogQueries bool     `json:"log_queries"`
		// Controle de fuga de DNS (#124).
		ForceLocalDNS bool     `json:"force_local_dns"`
		BlockDoT      bool     `json:"block_dot"`
		DNSExceptIPs  []string `json:"dns_except_ips"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ups := []string{}
	for _, u := range b.Upstreams {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if net.ParseIP(u) == nil {
			writeError(w, http.StatusBadRequest, "upstream inválido: "+u)
			return
		}
		ups = append(ups, u)
	}
	// As exceções vão para dentro de uma regra do nft; endereço inválido é
	// recusado aqui, e não descartado em silêncio: o admin que digitou errado
	// precisa saber que aquele host NÃO ficou isento.
	excecoes := []string{}
	for _, ip := range b.DNSExceptIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			writeError(w, http.StatusBadRequest, "endereço isento inválido: "+ip)
			return
		}
		excecoes = append(excecoes, ip)
	}

	cfg := h.getConfig()
	cfg.Upstreams = ups
	cfg.LogQueries = b.LogQueries
	cfg.ForceLocalDNS = b.ForceLocalDNS
	cfg.BlockDoT = b.BlockDoT
	cfg.DNSExceptIPs = excecoes
	if err := h.saveConfig(cfg); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "dns.config", "netsvc", "")
	h.scheduleApply()
	writeJSON(w, http.StatusOK, cfg)
}

// AddBlocklist / DeleteBlocklist manage blocked DNS domains.
func (h *NetsvcHandler) AddBlocklist(w http.ResponseWriter, r *http.Request) {
	h.blocklist(w, r, true)
}
func (h *NetsvcHandler) DeleteBlocklist(w http.ResponseWriter, r *http.Request) {
	h.blocklist(w, r, false)
}
func (h *NetsvcHandler) blocklist(w http.ResponseWriter, r *http.Request, add bool) {
	var b struct{ Domain string }
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	d := strings.ToLower(strings.TrimSpace(b.Domain))
	if d == "" {
		writeError(w, http.StatusBadRequest, "domínio vazio")
		return
	}
	// Validate charset only when adding; a delete must always be able to remove
	// an already-stored entry, including ones saved under an older, laxer rule.
	if add && !validate.Domain(d) {
		writeError(w, http.StatusBadRequest, "domínio inválido")
		return
	}
	var err error
	if add {
		err = h.db.AddDNSBlocklist(d)
		auditAction(h.db, r, "dns.blocklist.add", d, "")
	} else {
		err = h.db.DeleteDNSBlocklist(d)
		auditAction(h.db, r, "dns.blocklist.del", d, "")
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	h.scheduleApply()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Preview / Apply ─────────────────────────────────────────────────────────

// Preview returns the rendered backend config files (without applying).
func (h *NetsvcHandler) Preview(w http.ResponseWriter, r *http.Request) {
	bl, _ := h.db.ListDNSBlocklist()
	files, err := h.provider.GenerateConfigs(h.getConfig(), h.reservationsForProvider(), bl, h.ntpServerOption())
	if err != nil {
		// A config that cannot be rendered cannot be previewed either —
		// showing "the rest of it" would be showing a file that will never
		// be written (I-7).
		writeError(w, http.StatusBadRequest, "não foi possível gerar a configuração: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, files)
}

// Apply is the "Aplicar agora" button: it gracefully reloads the backend
// immediately (bypassing the debounce), validating the config first.
//
// A failure answers with the actual reason, not "erro interno do servidor".
// That generic answer (writeInternalError) exists to keep exec stderr and
// storage internals away from a lower-privileged role — but here it hid the
// one thing the admin needed to read ("o pacote kea-dhcp4-server não está
// instalado"), and hid nothing at all in practice: doReload has already
// persisted the very same string in netsvc_last_apply, which GET /api/dhcp
// returns to anyone with dhcp.read and the page renders in a red banner. So
// the real error goes back on the wire, and the server-side log line the
// generic path provided is kept explicitly.
//
// A missing prerequisite gets 503 rather than 500: nothing is broken, the
// machine is just not able to serve DHCP/DNS yet, and the message says what
// to do about it.
func (h *NetsvcHandler) Apply(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), applyBudget)
	defer cancel()
	if err := h.doReload(ctx); err != nil {
		slog.Error("falha ao aplicar DHCP/DNS", "err", err)
		var prereq *netsvc.PrereqError
		if errors.As(err, &prereq) {
			writeError(w, http.StatusServiceUnavailable, prereq.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "falha ao aplicar: "+err.Error())
		return
	}
	auditAction(h.db, r, "netsvc.apply", string(h.provider.Backend()), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "aplicado"})
}
