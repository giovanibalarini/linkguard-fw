package auth

// This file defines the RBAC permission catalog. Permissions are defined in
// code (they map 1:1 to application features); roles are user-defined sets of
// permissions stored in the database. The UI renders the catalog grouped by
// Area so an admin can build custom roles by toggling permissions per feature.

// Permission is a stable key referenced by roles in the database. Never rename
// an existing key — that would silently drop it from roles that reference it.
type Permission string

const (
	// Read access per feature area.
	PermDashboardRead  Permission = "dashboard.read"
	PermMonitoringRead Permission = "monitoring.read"
	PermLogsRead       Permission = "logs.read"
	PermLinksRead      Permission = "links.read"
	PermRoutesRead     Permission = "routes.read"
	PermFirewallRead   Permission = "firewall.read"
	PermHostsRead      Permission = "hosts.read"
	PermSystemRead     Permission = "system.read"
	PermDHCPRead       Permission = "dhcp.read"
	PermDNSRead        Permission = "dns.read"
	PermVPNRead        Permission = "vpn.read"
	PermInterfacesRead Permission = "interfaces.read"

	// Write / action access per feature area.
	PermLinksWrite    Permission = "links.write"
	PermRoutesWrite   Permission = "routes.write"
	PermFirewallWrite Permission = "firewall.write"
	PermHostsBlock    Permission = "hosts.block"
	PermHostsAssign   Permission = "hosts.assign" // mover host/grupo para uma WAN
	PermSystemWrite   Permission = "system.write" // settings, retenção, aliases
	PermDHCPWrite     Permission = "dhcp.write"   // ranges, reservas, aplicar
	PermDNSWrite      Permission = "dns.write"    // upstreams, blocklist, aplicar
	PermVPNWrite      Permission = "vpn.write"    // configurar VPN e clientes (WireGuard)
	PermInterfacesWrite Permission = "interfaces.write" // editar interface, identificar porta fisicamente

	// Administrative.
	PermUsersManage Permission = "users.manage" // criar/editar/remover usuários
	PermRolesManage Permission = "roles.manage" // criar/editar/remover papéis
)

// CatalogEntry is the UI-facing description of a single permission.
type CatalogEntry struct {
	Key         Permission `json:"key"`
	Area        string     `json:"area"`
	Label       string     `json:"label"`
	Description string     `json:"description"`
}

// Catalog is the ordered, UI-facing list of every permission, grouped by Area.
// The frontend builds the role editor from this list (one toggle per entry).
var Catalog = []CatalogEntry{
	{PermDashboardRead, "Dashboard", "Ver dashboard", "Visualizar a visão geral e o status dos links"},
	{PermMonitoringRead, "Monitoramento", "Ver monitoramento", "Métricas em tempo real e histórico de tráfego"},
	{PermLogsRead, "Auditoria", "Ver logs", "Consultar o log de auditoria"},

	{PermLinksRead, "Links WAN", "Ver links", "Listar links e seu status"},
	{PermLinksWrite, "Links WAN", "Gerenciar links", "Criar, editar, remover e auto-detectar links"},

	{PermRoutesRead, "Rotas", "Ver rotas", "Listar rotas e regras de policy routing"},
	{PermRoutesWrite, "Rotas", "Gerenciar rotas", "Adicionar, editar e remover rotas e regras"},

	{PermFirewallRead, "Firewall", "Ver firewall", "Inspecionar regras iptables/nftables e backups"},
	{PermFirewallWrite, "Firewall", "Gerenciar firewall", "Aplicar regras, backup e rollback"},

	{PermHostsRead, "Hosts", "Ver hosts", "Inventário e consumo de hosts da LAN"},
	{PermHostsBlock, "Hosts", "Bloquear host", "Bloquear/desbloquear um host"},
	{PermHostsAssign, "Hosts", "Direcionar host", "Mover host/grupo para uma WAN específica"},

	{PermSystemRead, "Sistema", "Ver sistema", "Métricas de sistema e configurações"},
	{PermSystemWrite, "Sistema", "Alterar configurações", "Retenção, aliases de interface e ajustes globais"},

	{PermDHCPRead, "DHCP", "Ver DHCP", "Ver config, reservas e leases ativos"},
	{PermDHCPWrite, "DHCP", "Gerenciar DHCP", "Editar range/reservas e aplicar (Kea)"},

	{PermDNSRead, "DNS", "Ver DNS", "Ver upstreams, cache e blocklist"},
	{PermDNSWrite, "DNS", "Gerenciar DNS", "Editar upstreams/blocklist e aplicar (unbound)"},

	{PermVPNRead, "VPN", "Ver VPN", "Ver status do servidor WireGuard e clientes"},
	{PermVPNWrite, "VPN", "Gerenciar VPN", "Ativar/configurar a VPN e criar/remover clientes"},

	{PermInterfacesRead, "Interfaces", "Ver interfaces", "Topologia de rede, estado físico e diagnóstico"},
	{PermInterfacesWrite, "Interfaces", "Gerenciar interfaces", "Identificar porta fisicamente (piscar LED)"},

	{PermUsersManage, "Administração", "Gerenciar usuários", "Criar, editar e remover usuários e seus papéis"},
	{PermRolesManage, "Administração", "Gerenciar papéis", "Criar, editar e remover papéis e suas permissões"},
}

// allPermissions returns every permission key in the catalog.
func allPermissions() []Permission {
	perms := make([]Permission, len(Catalog))
	for i, e := range Catalog {
		perms[i] = e.Key
	}
	return perms
}

// IsValidPermission reports whether key exists in the catalog.
func IsValidPermission(key string) bool {
	for _, e := range Catalog {
		if string(e.Key) == key {
			return true
		}
	}
	return false
}

// DefaultRole is a built-in role seeded on first run as a starting point.
// Admins can edit non-builtin roles freely; built-in roles are seeded once and
// can be customized later (they are not re-seeded over user changes).
type DefaultRole struct {
	ID          string
	Name        string
	Description string
	Permissions []Permission
}

// readOnlyPermissions is the set of all *.read permissions (the Viewer role).
func readOnlyPermissions() []Permission {
	var perms []Permission
	for _, e := range Catalog {
		switch e.Key {
		case PermDashboardRead, PermMonitoringRead, PermLogsRead,
			PermLinksRead, PermRoutesRead, PermFirewallRead,
			PermHostsRead, PermSystemRead, PermDHCPRead, PermDNSRead, PermVPNRead, PermInterfacesRead:
			perms = append(perms, e.Key)
		}
	}
	return perms
}

// DefaultRoles are seeded on first migration as ready-to-use starting points.
var DefaultRoles = []DefaultRole{
	{
		ID:          "role-admin",
		Name:        "Administrador",
		Description: "Acesso total, incluindo gestão de usuários e papéis",
		Permissions: allPermissions(),
	},
	{
		ID:          "role-operator",
		Name:        "Operador",
		Description: "Operação do dia a dia: links, rotas, firewall e hosts (sem administração)",
		Permissions: []Permission{
			PermDashboardRead, PermMonitoringRead, PermLogsRead,
			PermLinksRead, PermLinksWrite,
			PermRoutesRead, PermRoutesWrite,
			PermFirewallRead, PermFirewallWrite,
			PermHostsRead, PermHostsBlock, PermHostsAssign,
			PermSystemRead,
			PermDHCPRead, PermDHCPWrite, PermDNSRead, PermDNSWrite,
			PermVPNRead, PermVPNWrite,
			PermInterfacesRead, PermInterfacesWrite,
		},
	},
	{
		ID:          "role-viewer",
		Name:        "Visualizador",
		Description: "Somente leitura",
		Permissions: readOnlyPermissions(),
	},
}
