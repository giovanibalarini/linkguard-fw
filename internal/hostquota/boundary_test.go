package hostquota

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// A PROIBIÇÃO DE CORTAR, ESCRITA COMO REGRA QUE O CI SEGURA.
//
// O cabeçalho de hostquota.go gasta trinta e cinco linhas explicando por que
// esta feature avisa e não corta. Comentário não é executável: nada impedia um
// patch futuro de acrescentar internal/hosts a este pacote e chamar SetBlocked
// dentro de evaluate. Compilaria, o vet calaria, os testes passariam, o npm
// check passaria — e a única coisa que gritaria seria uma bateria de máquina
// virtual que ninguém roda no CI.
//
// O TestPackageBoundary de internal/api/handlers governa o que o HANDLER pode
// importar. Não governa isto. Este arquivo governa.
//
// A lista abaixo é curta e literal de propósito: são os caminhos pelos quais o
// corte, o bloqueio e a limitação de banda entram num pacote Go deste projeto.
// Se algum dia a decisão de produto mudar, o ato deliberado é apagar a entrada
// daqui — com a justificativa no commit —, e não descobrir meses depois que a
// cota trancou o aparelho do admin numa terça-feira.
// ─────────────────────────────────────────────────────────────────────────────

// importsQueCortam mapeia caminho de import → por que ele não pode entrar aqui.
var importsQueCortam = map[string]string{
	"github.com/giovanibalarini/linkguard-fw/internal/nftables":      "escrever no ruleset vivo é o corte; ver LiveSnapshotSettingKey e survival.go",
	"github.com/giovanibalarini/linkguard-fw/internal/hosts":         "hosts.SetBlocked tranca o aparelho, e o que estourou a cota pode ser o do admin",
	"github.com/giovanibalarini/linkguard-fw/internal/firewall":      "o executor central aplica regra; medir e avisar não aplica regra nenhuma",
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules": "regra de firewall por cota é o corte com outro nome",
	"github.com/giovanibalarini/linkguard-fw/internal/iptables":      "idem nftables, pela porta antiga",
	"os/exec": "este pacote não executa processo: nem tc, nem nft, nem ip. Se precisar, o desenho está errado",
}

func TestOPacoteDaCotaNaoConsegueCortar(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	visto := 0
	for _, pkg := range pkgs {
		for nome, arquivo := range pkg.Files {
			if strings.HasSuffix(nome, "_test.go") {
				continue // teste pode importar o que quiser para montar cenário
			}
			visto++
			for _, imp := range arquivo.Imports {
				caminho, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					t.Fatalf("import ilegível em %s: %v", nome, err)
				}
				if porque, proibido := importsQueCortam[caminho]; proibido {
					t.Errorf("%s importa %q."+
						"\n  Esta feature MEDE E AVISA; ela não corta, não bloqueia e não limita banda."+
						"\n  Por quê: %s"+
						"\n  Se a decisão de produto mudou, apague a entrada de importsQueCortam"+
						"\n  neste arquivo, no mesmo commit, com o porquê escrito.",
						nome, caminho, porque)
				}
			}
		}
	}
	if visto == 0 {
		t.Fatal("nenhum arquivo de produção examinado: este teste não estaria medindo nada")
	}
}
