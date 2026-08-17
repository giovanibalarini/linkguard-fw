package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── Routing policies ────────────────────────────────────────────────────────

func TestCreateRoutingPolicyRoundTripsEveryField(t *testing.T) {
	db := newTestDB(t)

	p := &storage.RoutingPolicy{
		Name:       "voip pela vivo",
		SourceCIDR: "192.168.3.0/24",
		DestCIDR:   "200.10.0.0/16",
		LinkID:     "link-vivo",
		Priority:   10,
		Enabled:    true,
		Failover:   true,
	}
	if err := db.CreateRoutingPolicy(p); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}
	if p.ID == "" {
		t.Error("esperava um ID gerado quando o campo vem vazio")
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Errorf("esperava created_at/updated_at preenchidos, veio %v / %v", p.CreatedAt, p.UpdatedAt)
	}

	list, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 política, veio %d", len(list))
	}
	got := list[0]
	if got.ID != p.ID {
		t.Errorf("esperava ID=%s, veio %s", p.ID, got.ID)
	}
	if got.Name != "voip pela vivo" {
		t.Errorf("esperava Name=voip pela vivo, veio %s", got.Name)
	}
	if got.SourceCIDR != "192.168.3.0/24" {
		t.Errorf("esperava SourceCIDR=192.168.3.0/24, veio %s", got.SourceCIDR)
	}
	if got.DestCIDR != "200.10.0.0/16" {
		t.Errorf("esperava DestCIDR=200.10.0.0/16, veio %s", got.DestCIDR)
	}
	if got.LinkID != "link-vivo" {
		t.Errorf("esperava LinkID=link-vivo, veio %s", got.LinkID)
	}
	if got.Priority != 10 {
		t.Errorf("esperava Priority=10, veio %d", got.Priority)
	}
	if !got.Enabled || !got.Failover {
		t.Errorf("esperava enabled/failover true, veio %v / %v", got.Enabled, got.Failover)
	}
}

// Os defaults da tabela são 1 para enabled e failover: uma política gravada
// desligada precisa voltar desligada, senão ela passa a valer sozinha.
func TestCreateRoutingPolicyKeepsFalseFlagsFalse(t *testing.T) {
	db := newTestDB(t)

	p := &storage.RoutingPolicy{Name: "desligada", LinkID: "link-1", Enabled: false, Failover: false}
	if err := db.CreateRoutingPolicy(p); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}

	list, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 política, veio %d", len(list))
	}
	if list[0].Enabled {
		t.Error("esperava Enabled=false, veio true")
	}
	if list[0].Failover {
		t.Error("esperava Failover=false, veio true")
	}
}

func TestCreateRoutingPolicyHonoursAnExplicitID(t *testing.T) {
	db := newTestDB(t)

	p := &storage.RoutingPolicy{ID: "politica-fixa", Name: "com id", LinkID: "link-1"}
	if err := db.CreateRoutingPolicy(p); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}
	if p.ID != "politica-fixa" {
		t.Errorf("esperava o ID informado preservado, veio %s", p.ID)
	}

	list, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(list) != 1 || list[0].ID != "politica-fixa" {
		t.Fatalf("esperava a política com ID informado, veio %+v", list)
	}
}

func TestCreateRoutingPolicyRejectsDuplicateID(t *testing.T) {
	db := newTestDB(t)

	first := &storage.RoutingPolicy{ID: "duplicada", Name: "primeira", LinkID: "link-1"}
	if err := db.CreateRoutingPolicy(first); err != nil {
		t.Fatalf("CreateRoutingPolicy (1): %v", err)
	}

	second := &storage.RoutingPolicy{ID: "duplicada", Name: "segunda", LinkID: "link-2"}
	if err := db.CreateRoutingPolicy(second); err == nil {
		t.Fatal("esperava erro de chave duplicada, veio nil")
	}

	list, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(list) != 1 || list[0].Name != "primeira" {
		t.Fatalf("a política original deveria continuar intacta, veio %+v", list)
	}
}

// O banco roda com foreign keys OFF (modernc): o link_id não é validado nem no
// insert nem quando o link some. Política órfã é problema de quem consome.
func TestRoutingPolicySurvivesADeletedLinkBecauseForeignKeysAreOff(t *testing.T) {
	db := newTestDB(t)

	l := &storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", Enabled: true}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	p := &storage.RoutingPolicy{Name: "aponta pro link", LinkID: l.ID}
	if err := db.CreateRoutingPolicy(p); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}

	if err := db.DeleteLink(l.ID); err != nil {
		t.Fatalf("DeleteLink: %v", err)
	}

	list, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava a política órfã ainda presente, veio %d", len(list))
	}
	if list[0].LinkID != l.ID {
		t.Errorf("esperava o link_id órfão preservado (%s), veio %s", l.ID, list[0].LinkID)
	}
}

func TestCreateRoutingPolicyFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.CreateRoutingPolicy(&storage.RoutingPolicy{Name: "x", LinkID: "y"}); err == nil {
		t.Fatal("esperava erro ao criar política com o banco fechado, veio nil")
	}
}

func TestGetRoutingPoliciesIsOrderedByPriority(t *testing.T) {
	db := newTestDB(t)

	for _, p := range []struct {
		name     string
		priority int
	}{
		{"terceira", 300},
		{"primeira", 100},
		{"segunda", 200},
	} {
		if err := db.CreateRoutingPolicy(&storage.RoutingPolicy{
			Name: p.name, LinkID: "link-1", Priority: p.priority, Enabled: true,
		}); err != nil {
			t.Fatalf("CreateRoutingPolicy %s: %v", p.name, err)
		}
	}

	list, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	want := []string{"primeira", "segunda", "terceira"}
	if len(list) != len(want) {
		t.Fatalf("esperava %d políticas, veio %d", len(want), len(list))
	}
	for i := range want {
		if list[i].Name != want[i] {
			t.Errorf("posição %d: esperava %s, veio %s", i, want[i], list[i].Name)
		}
	}
}

func TestGetRoutingPoliciesOnAnEmptyTable(t *testing.T) {
	db := newTestDB(t)

	list, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("esperava nenhuma política, veio %d", len(list))
	}
}

// Uma linha com created_at ilegível (banco mexido à mão, restore parcial)
// derruba a listagem inteira em vez de pular a linha — nenhuma política volta.
func TestGetRoutingPoliciesFailOnACorruptTimestamp(t *testing.T) {
	db := newTestDB(t)

	if err := db.CreateRoutingPolicy(&storage.RoutingPolicy{Name: "boa", LinkID: "link-1"}); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}
	if _, err := db.Conn().Exec(`
		INSERT INTO routing_policies (id, name, source_cidr, dest_cidr, link_id, priority, enabled, failover, created_at, updated_at)
		VALUES ('corrompida', 'ruim', '', '', 'link-1', 1, 1, 1, 'isto-nao-e-uma-data', 'isto-nao-e-uma-data')`); err != nil {
		t.Fatalf("insert corrompido: %v", err)
	}

	list, err := db.GetRoutingPolicies()
	if err == nil {
		t.Fatal("esperava erro de scan na linha corrompida, veio nil")
	}
	if len(list) != 0 {
		t.Errorf("esperava nenhuma política junto com o erro, veio %d", len(list))
	}
}

func TestGetRoutingPoliciesFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := db.GetRoutingPolicies(); err == nil {
		t.Fatal("esperava erro ao listar políticas com o banco fechado, veio nil")
	}
}

func TestDeleteRoutingPolicyRemovesOnlyTheGivenID(t *testing.T) {
	db := newTestDB(t)

	vai := &storage.RoutingPolicy{Name: "vai", LinkID: "link-1", Priority: 100}
	fica := &storage.RoutingPolicy{Name: "fica", LinkID: "link-2", Priority: 200}
	if err := db.CreateRoutingPolicy(vai); err != nil {
		t.Fatalf("CreateRoutingPolicy vai: %v", err)
	}
	if err := db.CreateRoutingPolicy(fica); err != nil {
		t.Fatalf("CreateRoutingPolicy fica: %v", err)
	}

	if err := db.DeleteRoutingPolicy(vai.ID); err != nil {
		t.Fatalf("DeleteRoutingPolicy: %v", err)
	}

	list, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 política restante, veio %d", len(list))
	}
	if list[0].ID != fica.ID {
		t.Errorf("apagou a política errada: sobrou %s (%s)", list[0].Name, list[0].ID)
	}
}

// Apagar um ID inexistente não é erro — nem derruba as políticas existentes.
func TestDeleteRoutingPolicyUnknownIDIsANoOp(t *testing.T) {
	db := newTestDB(t)

	p := &storage.RoutingPolicy{Name: "fica", LinkID: "link-1"}
	if err := db.CreateRoutingPolicy(p); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}

	if err := db.DeleteRoutingPolicy("nao-existe"); err != nil {
		t.Fatalf("DeleteRoutingPolicy (ID inexistente): %v", err)
	}

	list, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava a política existente intacta, veio %d", len(list))
	}
}

func TestDeleteRoutingPolicyFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.DeleteRoutingPolicy("qualquer"); err == nil {
		t.Fatal("esperava erro ao apagar política com o banco fechado, veio nil")
	}
}

// ─── Failover events ─────────────────────────────────────────────────────────

func TestCreateFailoverEventRoundTripsEveryField(t *testing.T) {
	db := newTestDB(t)

	e := &storage.FailoverEvent{
		LinkID:     "link-giga",
		LinkName:   "WAN-Giga",
		FromStatus: "online",
		ToStatus:   "degraded",
		Reason:     "perda de 30% em 3 sondagens",
		Commands:   "ip route replace default via 10.0.0.1",
		DryRun:     false,
	}
	if err := db.CreateFailoverEvent(e); err != nil {
		t.Fatalf("CreateFailoverEvent: %v", err)
	}
	if e.ID == "" {
		t.Error("esperava um ID gerado quando o campo vem vazio")
	}
	if e.CreatedAt.IsZero() {
		t.Error("esperava created_at preenchido")
	}

	events, err := db.GetFailoverEvents(10)
	if err != nil {
		t.Fatalf("GetFailoverEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("esperava 1 evento, veio %d", len(events))
	}
	got := events[0]
	if got.ID != e.ID {
		t.Errorf("esperava ID=%s, veio %s", e.ID, got.ID)
	}
	if got.LinkID != "link-giga" || got.LinkName != "WAN-Giga" {
		t.Errorf("esperava link-giga/WAN-Giga, veio %s/%s", got.LinkID, got.LinkName)
	}
	if got.FromStatus != "online" || got.ToStatus != "degraded" {
		t.Errorf("esperava online→degraded, veio %s→%s", got.FromStatus, got.ToStatus)
	}
	if got.Reason != "perda de 30% em 3 sondagens" {
		t.Errorf("esperava a razão preservada, veio %q", got.Reason)
	}
	if got.Commands != "ip route replace default via 10.0.0.1" {
		t.Errorf("esperava os comandos preservados, veio %q", got.Commands)
	}
	if got.DryRun {
		t.Error("esperava DryRun=false, veio true")
	}
}

// dry_run é 1 por default na tabela; um evento REAL gravado como dry-run (ou o
// contrário) mentiria no histórico de failover. Os dois valores têm que voltar
// como foram gravados.
func TestCreateFailoverEventKeepsDryRunFlagBothWays(t *testing.T) {
	db := newTestDB(t)

	seco := &storage.FailoverEvent{ID: "ev-dry", LinkID: "l1", LinkName: "WAN1", FromStatus: "online", ToStatus: "offline", DryRun: true}
	real := &storage.FailoverEvent{ID: "ev-real", LinkID: "l1", LinkName: "WAN1", FromStatus: "offline", ToStatus: "online", DryRun: false}
	if err := db.CreateFailoverEvent(seco); err != nil {
		t.Fatalf("CreateFailoverEvent dry: %v", err)
	}
	if err := db.CreateFailoverEvent(real); err != nil {
		t.Fatalf("CreateFailoverEvent real: %v", err)
	}

	events, err := db.GetFailoverEvents(10)
	if err != nil {
		t.Fatalf("GetFailoverEvents: %v", err)
	}
	byID := map[string]storage.FailoverEvent{}
	for _, ev := range events {
		byID[ev.ID] = ev
	}
	if !byID["ev-dry"].DryRun {
		t.Error("ev-dry deveria voltar com DryRun=true")
	}
	if byID["ev-real"].DryRun {
		t.Error("ev-real deveria voltar com DryRun=false")
	}
}

func TestCreateFailoverEventRejectsDuplicateID(t *testing.T) {
	db := newTestDB(t)

	if err := db.CreateFailoverEvent(&storage.FailoverEvent{ID: "mesmo-id", LinkID: "l1", LinkName: "WAN1", FromStatus: "online", ToStatus: "offline"}); err != nil {
		t.Fatalf("CreateFailoverEvent (1): %v", err)
	}
	if err := db.CreateFailoverEvent(&storage.FailoverEvent{ID: "mesmo-id", LinkID: "l1", LinkName: "WAN1", FromStatus: "offline", ToStatus: "online"}); err == nil {
		t.Fatal("esperava erro de chave duplicada, veio nil")
	}

	events, err := db.GetFailoverEvents(10)
	if err != nil {
		t.Fatalf("GetFailoverEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("esperava 1 evento gravado, veio %d", len(events))
	}
}

func TestCreateFailoverEventFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.CreateFailoverEvent(&storage.FailoverEvent{LinkID: "l1", LinkName: "WAN1", FromStatus: "online", ToStatus: "offline"}); err == nil {
		t.Fatal("esperava erro ao gravar evento com o banco fechado, veio nil")
	}
}

func TestGetFailoverEventsReturnsTheMostRecentFirstAndRespectsTheLimit(t *testing.T) {
	db := newTestDB(t)

	for _, name := range []string{"primeiro", "segundo", "terceiro", "quarto"} {
		if err := db.CreateFailoverEvent(&storage.FailoverEvent{
			LinkID: "l1", LinkName: "WAN1", FromStatus: "online", ToStatus: "offline", Reason: name,
		}); err != nil {
			t.Fatalf("CreateFailoverEvent %s: %v", name, err)
		}
	}

	events, err := db.GetFailoverEvents(2)
	if err != nil {
		t.Fatalf("GetFailoverEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("esperava 2 eventos (limite), veio %d", len(events))
	}
	if events[0].Reason != "quarto" {
		t.Errorf("esperava o mais recente primeiro (quarto), veio %s", events[0].Reason)
	}
	if events[1].Reason != "terceiro" {
		t.Errorf("esperava terceiro na segunda posição, veio %s", events[1].Reason)
	}
}

// limite <= 0 não significa "nenhum evento": significa o default de 100.
func TestGetFailoverEventsWithNonPositiveLimitUsesTheDefault(t *testing.T) {
	db := newTestDB(t)

	for i := 0; i < 3; i++ {
		if err := db.CreateFailoverEvent(&storage.FailoverEvent{
			LinkID: "l1", LinkName: "WAN1", FromStatus: "online", ToStatus: "offline",
		}); err != nil {
			t.Fatalf("CreateFailoverEvent: %v", err)
		}
	}

	for _, limit := range []int{0, -1} {
		events, err := db.GetFailoverEvents(limit)
		if err != nil {
			t.Fatalf("GetFailoverEvents(%d): %v", limit, err)
		}
		if len(events) != 3 {
			t.Errorf("GetFailoverEvents(%d): esperava 3 eventos, veio %d", limit, len(events))
		}
	}
}

func TestGetFailoverEventsOnAnEmptyTable(t *testing.T) {
	db := newTestDB(t)

	events, err := db.GetFailoverEvents(10)
	if err != nil {
		t.Fatalf("GetFailoverEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("esperava nenhum evento, veio %d", len(events))
	}
}

// Uma linha com created_at ilegível (banco mexido à mão, restore parcial)
// derruba a listagem inteira em vez de pular a linha. Fixa o comportamento
// atual: erro, e nenhum evento devolvido.
func TestGetFailoverEventsFailsOnACorruptTimestamp(t *testing.T) {
	db := newTestDB(t)

	if err := db.CreateFailoverEvent(&storage.FailoverEvent{
		LinkID: "l1", LinkName: "WAN1", FromStatus: "online", ToStatus: "offline",
	}); err != nil {
		t.Fatalf("CreateFailoverEvent: %v", err)
	}
	if _, err := db.Conn().Exec(`
		INSERT INTO failover_events (id, link_id, link_name, from_status, to_status, reason, commands, dry_run, created_at)
		VALUES ('corrompido', 'l1', 'WAN1', 'online', 'offline', '', '', 1, 'isto-nao-e-uma-data')`); err != nil {
		t.Fatalf("insert corrompido: %v", err)
	}

	events, err := db.GetFailoverEvents(10)
	if err == nil {
		t.Fatal("esperava erro de scan na linha corrompida, veio nil")
	}
	if len(events) != 0 {
		t.Errorf("esperava nenhum evento junto com o erro, veio %d", len(events))
	}
}

func TestGetFailoverEventsFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := db.GetFailoverEvents(10); err == nil {
		t.Fatal("esperava erro ao listar eventos com o banco fechado, veio nil")
	}
}

// ─── SearchAuditLogs ─────────────────────────────────────────────────────────

func seedAuditLogs(t *testing.T, db *storage.DB, actions ...string) {
	t.Helper()
	for _, a := range actions {
		if err := db.CreateAuditLog(&storage.AuditLog{
			User: "admin", Action: a, Resource: "recurso", Details: "detalhe", IP: "192.168.3.10",
		}); err != nil {
			t.Fatalf("CreateAuditLog %s: %v", a, err)
		}
	}
}

func TestSearchAuditLogsWithoutFilterReturnsEverythingNewestFirst(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create", "dhcp.reservation.set", "dns.blocklist.add")

	logs, err := db.SearchAuditLogs("", 10)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("esperava 3 registros, veio %d", len(logs))
	}
	if logs[0].Action != "dns.blocklist.add" {
		t.Errorf("esperava o mais recente primeiro (dns.blocklist.add), veio %s", logs[0].Action)
	}
	if logs[0].User != "admin" || logs[0].IP != "192.168.3.10" {
		t.Errorf("esperava user/ip preservados, veio %s / %s", logs[0].User, logs[0].IP)
	}
}

func TestSearchAuditLogsFiltersByActionSubstring(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create", "dhcp.reservation.set", "dhcp.reservation.del", "dns.blocklist.add")

	logs, err := db.SearchAuditLogs("dhcp", 10)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("esperava 2 registros de dhcp, veio %d", len(logs))
	}
	for _, l := range logs {
		if l.Action != "dhcp.reservation.set" && l.Action != "dhcp.reservation.del" {
			t.Errorf("registro fora do filtro: %s", l.Action)
		}
	}
}

func TestSearchAuditLogsIgnoresCaseInTheFilter(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "dns.blocklist.add")

	logs, err := db.SearchAuditLogs("DNS.BLOCKLIST", 10)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("esperava 1 registro com filtro em maiúsculas, veio %d", len(logs))
	}
}

// O filtro é minusculado antes de virar LIKE, então acento em maiúscula também
// encontra a ação gravada em minúsculas.
func TestSearchAuditLogsLowercasesAccentedFilters(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "configuração.salvar")

	logs, err := db.SearchAuditLogs("CONFIGURAÇÃO", 10)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("esperava 1 registro com filtro acentuado em maiúsculas, veio %d", len(logs))
	}
}

// O filtro olha só a coluna action: procurar pelo usuário, pelo recurso ou pelo
// IP não devolve nada (contrato importante para quem monta a tela de auditoria).
func TestSearchAuditLogsOnlyMatchesTheActionColumn(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create")

	for _, filter := range []string{"admin", "recurso", "192.168.3.10", "detalhe"} {
		logs, err := db.SearchAuditLogs(filter, 10)
		if err != nil {
			t.Fatalf("SearchAuditLogs(%q): %v", filter, err)
		}
		if len(logs) != 0 {
			t.Errorf("SearchAuditLogs(%q): esperava 0 registros (só action é pesquisada), veio %d", filter, len(logs))
		}
	}
}

func TestSearchAuditLogsWithNoMatchReturnsNothingWithoutError(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create")

	logs, err := db.SearchAuditLogs("firewall", 10)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(logs) != 0 {
		t.Fatalf("esperava nenhum registro, veio %d", len(logs))
	}
}

func TestSearchAuditLogsRespectsTheLimitAndDefaultsWhenNonPositive(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create", "link.update", "link.delete")

	limited, err := db.SearchAuditLogs("link", 2)
	if err != nil {
		t.Fatalf("SearchAuditLogs(limite 2): %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("esperava 2 registros, veio %d", len(limited))
	}
	if limited[0].Action != "link.delete" {
		t.Errorf("esperava o mais recente primeiro (link.delete), veio %s", limited[0].Action)
	}

	for _, limit := range []int{0, -5} {
		all, err := db.SearchAuditLogs("link", limit)
		if err != nil {
			t.Fatalf("SearchAuditLogs(limite %d): %v", limit, err)
		}
		if len(all) != 3 {
			t.Errorf("SearchAuditLogs(limite %d): esperava 3 registros (default), veio %d", limit, len(all))
		}
	}
}

func TestSearchAuditLogsFailsOnACorruptTimestamp(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create")
	if _, err := db.Conn().Exec(`
		INSERT INTO audit_logs (id, user, action, resource, details, ip, created_at)
		VALUES ('corrompido', 'admin', 'link.create', '', '', '', 'isto-nao-e-uma-data')`); err != nil {
		t.Fatalf("insert corrompido: %v", err)
	}

	logs, err := db.SearchAuditLogs("link", 10)
	if err == nil {
		t.Fatal("esperava erro de scan na linha corrompida, veio nil")
	}
	if len(logs) != 0 {
		t.Errorf("esperava nenhum registro junto com o erro, veio %d", len(logs))
	}
}

func TestSearchAuditLogsFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := db.SearchAuditLogs("", 10); err == nil {
		t.Fatal("esperava erro ao pesquisar auditoria sem filtro com o banco fechado, veio nil")
	}
	if _, err := db.SearchAuditLogs("link", 10); err == nil {
		t.Fatal("esperava erro ao pesquisar auditoria com filtro com o banco fechado, veio nil")
	}
}

// ─── SetHostAlias ────────────────────────────────────────────────────────────

func hostByMAC(t *testing.T, db *storage.DB, mac string) *storage.HostMetadata {
	t.Helper()
	list, err := db.ListHostMetadata()
	if err != nil {
		t.Fatalf("ListHostMetadata: %v", err)
	}
	for i := range list {
		if list[i].MAC == mac {
			return &list[i]
		}
	}
	return nil
}

func TestSetHostAliasCreatesTheHostRowWhenItDoesNotExist(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:11:22:01", "notebook da recepção"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}

	got := hostByMAC(t, db, "aa:bb:cc:11:22:01")
	if got == nil {
		t.Fatal("esperava a linha do host criada pelo apelido")
	}
	if got.Alias != "notebook da recepção" {
		t.Errorf("esperava o apelido gravado, veio %q", got.Alias)
	}
	if got.FirstSeen.IsZero() || got.LastSeen.IsZero() {
		t.Errorf("esperava first_seen/last_seen preenchidos, veio %v / %v", got.FirstSeen, got.LastSeen)
	}
	if got.Blocked {
		t.Error("host novo não deveria nascer bloqueado")
	}
}

func TestSetHostAliasOverwritesThePreviousAlias(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:11:22:02", "apelido antigo"); err != nil {
		t.Fatalf("SetHostAlias (1): %v", err)
	}
	if err := db.SetHostAlias("aa:bb:cc:11:22:02", "apelido novo"); err != nil {
		t.Fatalf("SetHostAlias (2): %v", err)
	}

	list, err := db.ListHostMetadata()
	if err != nil {
		t.Fatalf("ListHostMetadata: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 host (upsert, não insert), veio %d", len(list))
	}
	if list[0].Alias != "apelido novo" {
		t.Errorf("esperava o apelido novo, veio %q", list[0].Alias)
	}
}

func TestSetHostAliasWithEmptyStringClearsTheAlias(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:11:22:03", "tinha apelido"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}
	if err := db.SetHostAlias("aa:bb:cc:11:22:03", ""); err != nil {
		t.Fatalf("SetHostAlias (limpar): %v", err)
	}

	got := hostByMAC(t, db, "aa:bb:cc:11:22:03")
	if got == nil {
		t.Fatal("esperava a linha do host ainda presente")
	}
	if got.Alias != "" {
		t.Errorf("esperava apelido vazio depois de limpar, veio %q", got.Alias)
	}
}

// Nomear um host não pode desbloqueá-lo nem apagar o IP visto na rede: o upsert
// só toca a coluna alias.
func TestSetHostAliasPreservesIPAndBlockedFlag(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertHostSightings(map[string]string{"aa:bb:cc:11:22:04": "192.168.3.44"}); err != nil {
		t.Fatalf("UpsertHostSightings: %v", err)
	}
	if err := db.SetHostBlocked("aa:bb:cc:11:22:04", true); err != nil {
		t.Fatalf("SetHostBlocked: %v", err)
	}

	if err := db.SetHostAlias("aa:bb:cc:11:22:04", "tablet do estoque"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}

	got := hostByMAC(t, db, "aa:bb:cc:11:22:04")
	if got == nil {
		t.Fatal("esperava a linha do host")
	}
	if got.Alias != "tablet do estoque" {
		t.Errorf("esperava o apelido gravado, veio %q", got.Alias)
	}
	if !got.Blocked {
		t.Error("o apelido não pode desbloquear o host")
	}
	if got.IP != "192.168.3.44" {
		t.Errorf("o apelido não pode apagar o IP visto: esperava 192.168.3.44, veio %q", got.IP)
	}
}

// E o caminho inverso: bloquear depois de nomear mantém o apelido.
func TestSetHostBlockedPreservesTheAlias(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:11:22:05", "câmera do portão"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}
	if err := db.SetHostBlocked("aa:bb:cc:11:22:05", true); err != nil {
		t.Fatalf("SetHostBlocked: %v", err)
	}

	got := hostByMAC(t, db, "aa:bb:cc:11:22:05")
	if got == nil {
		t.Fatal("esperava a linha do host")
	}
	if got.Alias != "câmera do portão" {
		t.Errorf("esperava o apelido preservado, veio %q", got.Alias)
	}
	if !got.Blocked {
		t.Error("esperava o host bloqueado")
	}
}

// O MAC entra cru na chave: quem chama tem que normalizar antes (o handler HTTP
// aplica ToLower). Sem isso o apelido vai parar numa segunda linha e some da
// tela, que casa o host pelo MAC minúsculo.
func TestSetHostAliasIsCaseSensitiveOnMAC(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:11:22:06", "minúsculo"); err != nil {
		t.Fatalf("SetHostAlias minúsculo: %v", err)
	}
	if err := db.SetHostAlias("AA:BB:CC:11:22:06", "maiúsculo"); err != nil {
		t.Fatalf("SetHostAlias maiúsculo: %v", err)
	}

	list, err := db.ListHostMetadata()
	if err != nil {
		t.Fatalf("ListHostMetadata: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("esperava 2 linhas (MAC é case-sensitive no storage), veio %d", len(list))
	}
}

func TestSetHostAliasFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.SetHostAlias("aa:bb:cc:11:22:07", "x"); err == nil {
		t.Fatal("esperava erro ao gravar apelido com o banco fechado, veio nil")
	}
}

// ─── CountAlerts ─────────────────────────────────────────────────────────────

func TestCountAlertsIsZeroOnAFreshDatabase(t *testing.T) {
	db := newTestDB(t)

	n, err := db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 0 {
		t.Errorf("esperava 0 alertas, veio %d", n)
	}
}

func TestCountAlertsCountsOnlyTheUnresolvedOnes(t *testing.T) {
	db := newTestDB(t)

	var ids []string
	for _, title := range []string{"WAN1 caiu", "WAN2 degradada", "disco cheio"} {
		a := &storage.Alert{Type: "link_offline", Severity: "critical", Title: title}
		if err := db.CreateAlert(a); err != nil {
			t.Fatalf("CreateAlert %s: %v", title, err)
		}
		ids = append(ids, a.ID)
	}

	n, err := db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 3 {
		t.Fatalf("esperava 3 alertas em aberto, veio %d", n)
	}

	if err := db.ResolveAlert(ids[0]); err != nil {
		t.Fatalf("ResolveAlert: %v", err)
	}

	n, err = db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts (após resolver): %v", err)
	}
	if n != 2 {
		t.Errorf("esperava 2 alertas em aberto depois de resolver um, veio %d", n)
	}
}

// Um alerta já criado como resolvido não conta em nenhum momento.
func TestCountAlertsIgnoresAlertsCreatedAlreadyResolved(t *testing.T) {
	db := newTestDB(t)

	if err := db.CreateAlert(&storage.Alert{Type: "info", Severity: "info", Title: "já resolvido", Resolved: true}); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}

	n, err := db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 0 {
		t.Errorf("esperava 0 alertas em aberto, veio %d", n)
	}
}

func TestCountAlertsFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := db.CountAlerts(); err == nil {
		t.Fatal("esperava erro ao contar alertas com o banco fechado, veio nil")
	}
}
