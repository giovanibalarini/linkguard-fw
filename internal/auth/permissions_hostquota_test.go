package auth

import "testing"

// A cota por aparelho nasceu gateada por hosts.block — a permissão de TRANCAR
// um aparelho. Com isso, o papel que só deveria declarar teto e acompanhar
// consumo era impossível de montar: ou o operador ganhava o poder de cortar, ou
// não conseguia mexer em cota. E "quem pode cortar" e "quem pode declarar
// cota" viravam o mesmo conjunto, permanentemente, também para a auditoria
// inversa.
func TestCotaPorAparelhoTemPermissaoPropriaESeparadaDoBloqueio(t *testing.T) {
	if PermHostsQuota == PermHostsBlock {
		t.Fatal("declarar cota e trancar aparelho não podem ser a mesma permissão")
	}
	if PermHostsQuota == PermHostsAssign {
		t.Fatal("direcionar host para uma WAN não é declarar cota")
	}

	var noCatalogo *CatalogEntry
	for i := range Catalog {
		if Catalog[i].Key == PermHostsQuota {
			noCatalogo = &Catalog[i]
		}
	}
	if noCatalogo == nil {
		t.Fatal("hosts.quota não está no catálogo: o editor de papéis não teria como concedê-la")
	}
	if noCatalogo.Area != "Hosts" {
		t.Errorf("hosts.quota está na área %q", noCatalogo.Area)
	}

	// O Operador declarava cota antes desta permissão existir (via hosts.block).
	// Perdê-la no upgrade seria uma regressão de produto.
	if !temPermissao(t, "role-operator", PermHostsQuota) {
		t.Error("o papel Operador não recebe hosts.quota")
	}
	// Somente leitura continua somente leitura.
	if temPermissao(t, "role-viewer", PermHostsQuota) {
		t.Error("o papel Visualizador recebeu hosts.quota")
	}
	if !temPermissao(t, "role-admin", PermHostsQuota) {
		t.Error("o papel Administrador não recebe hosts.quota")
	}
}

func temPermissao(t *testing.T, roleID string, p Permission) bool {
	t.Helper()
	for _, r := range DefaultRoles {
		if r.ID != roleID {
			continue
		}
		for _, got := range r.Permissions {
			if got == p {
				return true
			}
		}
		return false
	}
	t.Fatalf("papel %q não existe em DefaultRoles", roleID)
	return false
}
