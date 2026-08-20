package handlers_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Guarda de fronteira do pacote handlers (issue #27 / ARQ-10).
//
// LEIA ISTO ANTES DE MEXER NAS LISTAS ABAIXO. As três regras deste arquivo NÃO
// têm o mesmo valor probatório, e misturá-las é o jeito mais fácil de acreditar
// numa proteção que não existe.
//
// A issue #27 pediu uma regra só: falhar se um arquivo de handlers importar
// `os/exec`, `database/sql` ou `internal/firewall`. Ao implementar, a primeira
// coisa medida foi se essa regra teria pegado a doença que a motivou — e não
// teria. Os três imports estão AUSENTES de handlers hoje e estiveram ausentes
// durante todo o período em que ARQ-1, ARQ-2 e ARQ-5 aconteceram:
//
//	git log --all -S'"os/exec"'      -- internal/api/handlers/   → 0 commits
//	git log --all -S'"database/sql"' -- internal/api/handlers/   → 0 commits
//	git log --all -S'internal/firewall"' -- internal/api/handlers/
//	    → 2 commits, os dois em vpn_test.go (arquivo de TESTE, feature
//	      removida em 42655a4). Nenhum arquivo de produção, nunca.
//
// Ou seja: a regra da issue teria ficado VERDE o tempo inteiro em que o
// protocolo confirmar-ou-reverte era recopiado dez vezes aqui (ARQ-1), em que
// a conversão de grupo vivia em duas cópias (ARQ-2) e em que o restore de
// backup inteiro morava no handler (ARQ-5). Ela é um piso útil, não um
// detector — e este comentário existe para que ninguém a leia como detector.
//
// Por isso são três regras, com etiquetas honestas:
//
//	Regra 1 — imports proibidos (a da issue).
//	          PROTEGE OUTRA CLASSE DE REGRESSÃO: a camada HTTP passar a
//	          executar processo, falar SQL cru ou chamar o executor central.
//	          Nunca aconteceu. É prevenção, não regressão observada.
//
//	Regra 2 — teto de pacotes internos POR ARQUIVO.
//	          É a única com prova histórica: teria ficado vermelha no commit
//	          b667ec5, o exato commit que trouxe o domínio do ARQ-5 para cá.
//
//	Regra 3 — lista fechada de pacotes internos do PACOTE.
//	          Prende a largura que o ARQ-10 mede ("24 dependências internas").
//	          Também não teria pegado ARQ-1/2/5 — todos os pacotes envolvidos
//	          já estavam importados. É ratchet de crescimento, não detector.
//
// O QUE NENHUMA DAS TRÊS PEGA, e é importante dizer em voz alta: ARQ-1 e ARQ-2
// eram lógica de domínio escrita como função não-exportada do pacote
// (`toStoredGroup`, `groupReachesInput`, `newOnlyInputSignatures`). Isso não
// tem assinatura de import nenhuma — nasce e morre dentro de handlers. Um
// teste de import não consegue vê-las, e fingir que consegue seria teatro.
// A fronteira contra esse caso continua sendo revisão humana.
//
// ─── Por que só imports DIRETOS ──────────────────────────────────────────────
//
// Uma regra transitiva reprovaria o pacote inteiro na primeira execução e
// estaria certa em zero dos casos:
//
//	internal/nftables/service.go:19  importa internal/firewall
//	internal/iptables/service.go:12  importa internal/firewall
//
// e handlers importa nftables (17 arquivos) e iptables (1). Chamar o serviço
// que sabe executar `nft` é exatamente o que a camada HTTP DEVE fazer; abrir o
// executor com as próprias mãos é que não. A diferença mora no import direto.
//
// ─── Por que os arquivos _test.go ficam de fora das três regras ──────────────
//
// Não é conveniência, é o que a história mostra:
//
//   - O único `internal/firewall` que já existiu neste diretório estava em
//     vpn_test.go, montando um executor falso para um fixture. Incluir testes
//     na Regra 1 transformaria essa prática correta em erro.
//
//   - main_test.go usa `os` para redirecionar nftables.ConfPath para um
//     diretório temporário. Sem isso a suíte sobrescreve o /etc/nftables.conf
//     DA MÁQUINA de quem roda — na appliance, o firewall do próximo boot. É
//     por isso, aliás, que a Regra 1 proíbe `os/exec` e NÃO `os`: alargar de
//     um para o outro proibiria a única coisa que impede a suíte de danificar
//     a máquina.
//
//   - As Regras 2 e 3 viram ruído puro em teste: backup_test.go importa 7
//     pacotes internos hoje, e legitimamente — para exercitar um handler é
//     preciso construir o mundo em volta dele.
//
// A fronteira defendida aqui é a forma da camada HTTP que VAI PARA A
// APPLIANCE, não a dos andaimes que a testam.
// ─────────────────────────────────────────────────────────────────────────────

const modulePrefix = "github.com/giovanibalarini/linkguard-fw/"

// forbiddenDirectImports é a Regra 1 — a regra literal da issue #27. O valor
// do mapa é a frase que o autor da mudança vai ler quando ficar vermelho: uma
// proibição sem o motivo dela vira contorno em cinco minutos.
var forbiddenDirectImports = map[string]string{
	"os/exec": "executar processo é de internal/firewall (o executor central, argv separado, nunca shell) " +
		"e dos serviços que o embrulham. Um exec.Command num handler é um caminho de execução que não " +
		"passa pelo dry-run, pelo log de comando nem pela guarda de persistência.",

	"database/sql": "a camada HTTP fala com internal/storage, não com o driver. SQL cru aqui pula as " +
		"transações que internal/storage é o dono de montar — e restaurar/gravar configuração fora de " +
		"transação já foi o achado ARQ-5.",

	modulePrefix + "internal/firewall": "internal/firewall é o executor de comando. Handlers chamam " +
		"internal/nftables ou internal/iptables, que já o embrulham com dry-run, guarda e log. Importá-lo " +
		"direto é contornar tudo isso.",
}

// maxInternalImportsPerFile é a Regra 2 — a única regra deste arquivo com
// prova histórica de que detecta a doença.
//
// A concentração de pacotes internos num arquivo só é a assinatura de "este
// handler parou de ser HTTP e virou dono de domínio dos outros". Números
// medidos:
//
//	hoje, máximo em arquivo não-teste ....... 5  (netsvc.go, ntp.go)
//	backup.go antes de b667ec5 .............. 4  (auth, backup, secrets, storage)
//	backup.go DEPOIS de b667ec5 ............. 7  (+ monitoring, netsvc, timesync)
//	backup.go no commit da auditoria 5360ce7  9  (+ firewallrules, nftables)
//
// b667ec5 é "fix(backup): validate settings/blocklist/reservations on restore":
// o commit que pôs a validação de domínio do restore dentro do handler, isto
// é, o nascimento do ARQ-5. Ele saltou de 4 para 7 numa tacada — um teto de 6
// teria ficado vermelho ali, no dia, e não dez meses depois numa auditoria.
//
// O teto é 6 e não 5 de propósito: um slot de folga sobre o máximo atual, para
// que uma correção legítima num sexto pacote não trave um branch de hotfix. O
// sétimo é a conversa que este teste quer forçar.
const maxInternalImportsPerFile = 6

// allowedInternalImports é a Regra 3 — a foto congelada da largura do pacote,
// tirada DEPOIS da extração de domínio das issues #21 (ARQ-2) e #23 (ARQ-5).
// Congelar antes seria congelar a foto errada: a lista carregaria os pacotes
// que o restore arrastava para dentro do handler.
//
// São 28 pacotes internos em arquivos não-teste. A diferença para a auditoria
// é de dois: a lista nominal do ARQ-10 tem 26 nomes (o cabeçalho dele diz
// "24", mas a própria enumeração traz 26 — divergência do documento, anotada e
// não corrigida aqui), e hoje há esses 26 mais internal/validate, o pacote
// folha que a #23 criou para tirar validDomain/validIface/normalizeMAC daqui,
// mais internal/dashboard, que a #25 criou para tirar do storage o catálogo de
// widgets e o RBAC do painel. Os dois entraram aqui pelo motivo certo: o
// handler passou a DELEGAR a regra em vez de carregá-la, e delegar exige
// importar. Esta linha foi acrescentada ao integrar a #25 com a #27 — as duas
// nasceram em ramos irmãos, e a lista foi congelada antes de internal/dashboard
// existir.
//
// Acrescentar um pacote aqui é barato e legítimo — uma linha. O ponto é que
// seja um ato deliberado, com um humano perguntando "isto é HTTP?", em vez de
// acontecer sozinho num import automático do editor.
var allowedInternalImports = map[string]bool{
	"internal/ai":            true,
	"internal/alerts":        true,
	"internal/auth":          true,
	"internal/backup":        true,
	"internal/balancer":      true,
	"internal/dashboard":     true,
	"internal/dnslog":        true,
	"internal/failover":      true,
	"internal/firewallrules": true,
	"internal/hosts":         true,
	"internal/hosttraffic":   true,
	"internal/iptables":      true,
	"internal/links":         true,
	"internal/monitoring":    true,
	"internal/netif":         true,
	"internal/netsvc":        true,
	"internal/nftables":      true,
	"internal/notify":        true,
	// internal/pktcapture entrou com a captura de pacotes (#114) pelo mesmo
	// motivo do stresstest: o handler decodifica o pedido, chama o serviço e
	// traduz o erro em status. A regra — tetos, filtro, uma por vez, varredura
	// do TTL — mora lá, e não aqui.
	"internal/pktcapture": true,
	// internal/linkquota entrou com a franquia por link (#126): o handler
	// decodifica, chama e traduz erro em status. A validação (dia de
	// fechamento, percentual) e o ciclo moram lá.
	"internal/linkquota":  true,
	"internal/links":      true,
	"internal/monitoring": true,
	"internal/netif":      true,
	"internal/netsvc":     true,
	"internal/nftables":   true,
	"internal/notify":     true,
	"internal/routes":     true,
	"internal/secrets":    true,
	"internal/storage":    true,
	"internal/stresstest": true,
	"internal/system":     true,
	"internal/sysupdates": true,
	"internal/timesync":   true,
	"internal/tsdb":       true,
	"internal/updater":    true,
	"internal/validate":   true,
}

// boundaryFile é um arquivo não-teste do pacote com seus imports diretos.
type boundaryFile struct {
	name     string   // nome base, para a mensagem de erro
	all      []string // todo import direto, como escrito
	internal []string // só os do módulo, já sem o prefixo do módulo
}

// parseHandlerPackage lê os .go não-teste DESTE diretório e devolve os imports
// diretos de cada um. Usa go/parser em vez de busca de texto para não casar com
// caminhos citados em comentário — este arquivo mesmo cita "os/exec" numa
// dúzia de linhas de prosa, e um grep se enganaria com ele.
func parseHandlerPackage(t *testing.T) []boundaryFile {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar este arquivo de teste")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ler %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var files []boundaryFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsear %s: %v", name, err)
		}
		bf := boundaryFile{name: name}
		for _, im := range f.Imports {
			path, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				t.Fatalf("%s: caminho de import ilegível %s: %v", name, im.Path.Value, err)
			}
			bf.all = append(bf.all, path)
			if strings.HasPrefix(path, modulePrefix) {
				bf.internal = append(bf.internal, strings.TrimPrefix(path, modulePrefix))
			}
		}
		sort.Strings(bf.internal)
		files = append(files, bf)
	}

	// Sanidade: se a varredura não achar nada, o teste passaria por vazio em
	// vez de por correção — o modo de falha mais perigoso de um guarda.
	if len(files) < 20 {
		t.Fatalf("varredura achou só %d arquivos não-teste em %s -- o pacote encolheu de verdade "+
			"ou este guarda parou de enxergar o diretório?", len(files), dir)
	}
	return files
}

// TestPackageBoundary é a fronteira declarada do pacote handlers, e o único
// mecanismo que impede a camada HTTP de voltar a inchar sem que ninguém note
// (`go vet` não pega nada disto). As três sub-regras, o que cada uma vale e o
// que nenhuma delas alcança estão argumentados no comentário no topo deste
// arquivo — se você chegou aqui vindo de uma falha, leia-o antes de editar
// qualquer lista.
func TestPackageBoundary(t *testing.T) {
	files := parseHandlerPackage(t)

	// ── Regra 1: imports proibidos (issue #27). Prevenção, não regressão. ──
	t.Run("ImportsProibidos", func(t *testing.T) {
		for _, f := range files {
			for _, path := range f.all {
				if why, forbidden := forbiddenDirectImports[path]; forbidden {
					t.Errorf("%s importa %q, que a camada HTTP não pode importar direto.\n  Por quê: %s",
						f.name, path, why)
				}
			}
		}
	})

	// ── Regra 2: concentração por arquivo. A que tem prova histórica. ──
	t.Run("PacotesInternosPorArquivo", func(t *testing.T) {
		for _, f := range files {
			if len(f.internal) <= maxInternalImportsPerFile {
				continue
			}
			t.Errorf("%s importa %d pacotes internos (teto: %d): %s\n"+
				"  Um arquivo de handler que precisa de tantos domínios ao mesmo tempo normalmente "+
				"parou de traduzir HTTP e passou a ser o dono da regra. Foi assim que o restore de "+
				"backup virou o ARQ-5: backup.go saltou de 4 para 7 pacotes no commit b667ec5 e chegou "+
				"a 9.\n"+
				"  Antes de subir o teto, pergunte se o que puxou o import não pertence a um pacote de "+
				"domínio — foi essa a saída nas issues #21 e #23.",
				f.name, len(f.internal), maxInternalImportsPerFile, strings.Join(f.internal, ", "))
		}
	})

	// ── Regra 3: largura do pacote. Ratchet, não detector. ──
	t.Run("PacotesInternosDoPacote", func(t *testing.T) {
		seen := map[string]bool{}
		for _, f := range files {
			for _, pkg := range f.internal {
				if allowedInternalImports[pkg] {
					seen[pkg] = true
					continue
				}
				t.Errorf("%s importa %s, que não está na lista de dependências internas declaradas "+
					"do pacote handlers.\n"+
					"  Se a camada HTTP realmente precisa falar com este pacote, acrescente a linha em "+
					"allowedInternalImports — a lista existe para tornar isso um ato deliberado, não "+
					"para impedi-lo. Se o que você precisa é da REGRA dentro dele, o handler é o lugar "+
					"errado.",
					f.name, pkg)
			}
		}

		// O outro lado do ratchet: uma entrada que sobrou depois de uma
		// extração vira permissão fantasma, e a próxima reintrodução passa
		// despercebida. Falhar aqui é uma linha a APAGAR.
		for pkg := range allowedInternalImports {
			if !seen[pkg] {
				t.Errorf("allowedInternalImports lista %s, mas nenhum arquivo não-teste o importa mais "+
					"-- apague a linha, senão a lista deixa de ser a foto do pacote.", pkg)
			}
		}
	})
}
