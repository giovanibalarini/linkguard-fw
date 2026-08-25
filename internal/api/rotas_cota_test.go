package api

import (
	"os"
	"regexp"
	"testing"
)

// As rotas que MUDAM a cota de um aparelho não podem exigir hosts.block.
//
// hosts.block é o portão de POST /api/hosts/block, que TRANCA o aparelho.
// Enquanto a cota estivesse atrás dela, o papel que só declara teto e acompanha
// consumo era impossível de montar — e "quem pode cortar" e "quem pode
// declarar cota" ficavam colados um no outro para sempre, inclusive para a
// auditoria inversa.
//
// A verificação é sobre a FONTE porque o roteador é montado dentro de New(), e
// as permissões entram como middleware por rota: não há como perguntar ao chi
// qual permissão guarda um caminho depois de montado.
func TestRotasQueMudamCotaNaoExigemPermissaoDeBloqueio(t *testing.T) {
	fonte, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("ler server.go: %v", err)
	}
	casos := []struct {
		verbo string
		re    *regexp.Regexp
	}{
		{"Put", regexp.MustCompile(`r\.With\(require\(auth\.(\w+)\)\)\.Put\("/api/hosts/quotas/`)},
		{"Delete", regexp.MustCompile(`r\.With\(require\(auth\.(\w+)\)\)\.Delete\("/api/hosts/quotas/`)},
	}
	for _, c := range casos {
		m := c.re.FindSubmatch(fonte)
		if m == nil {
			t.Errorf("não achei a rota %s de /api/hosts/quotas em server.go", c.verbo)
			continue
		}
		perm := string(m[1])
		if perm == "PermHostsBlock" {
			t.Errorf("a rota %s de cota exige PermHostsBlock: declarar teto passa a exigir o poder de trancar o aparelho", c.verbo)
		}
		if perm != "PermHostsQuota" {
			t.Errorf("a rota %s de cota exige %s, queria PermHostsQuota", c.verbo, perm)
		}
	}

	// E a leitura continua atrás de hosts.read: consumo por aparelho é
	// inventário da rede do cliente e não pode cair em rota mais aberta que a
	// lista de aparelhos.
	reGet := regexp.MustCompile(`r\.With\(require\(auth\.(\w+)\)\)\.Get\("/api/hosts/quotas`)
	m := reGet.FindSubmatch(fonte)
	if m == nil {
		t.Fatal("não achei a rota de leitura de /api/hosts/quotas")
	}
	if string(m[1]) != "PermHostsRead" {
		t.Errorf("a leitura da cota exige %s, queria PermHostsRead", string(m[1]))
	}
}
