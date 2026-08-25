package hostquota

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// TODA BATERIA DO vm-validate PRECISA EXISTIR EM ESCOPO GLOBAL.
//
// battery_host_quota foi escrita DENTRO de battery_accounting: a bateria G
// abria e não fechava, e os dois fechamentos empilhados no fim da Y fechavam as
// duas. Em bash, função aninhada só passa a existir depois que a externa roda
// até a linha da definição — e battery_accounting tem saída antecipada
// ("sem sessão administrativa").
//
// O efeito: numa rodada em que a sessão falhasse, battery_host_quota nunca
// seria definida, a chamada no runner morreria com "command not found" em
// stderr, o script roda com set -uo pipefail e SEM -e, FAIL não subiria, a
// bateria não entraria em PULADAS e o resumo não mencionaria que a Y não
// existiu. As cinco asserções de silêncio — a única prova executável de que a
// cota não tranca ninguém — sumiriam da rodada inteira, caladas.
//
// bash -n aceita aninhamento sem reclamar. Era a única ferramenta que rodava
// sobre esse arquivo, e foi exatamente por isso que passou.
// ─────────────────────────────────────────────────────────────────────────────

var reDefinicaoDeBateria = regexp.MustCompile(`(?m)^([ \t]*)(battery_[a-z0-9_]+)\(\)`)

func TestTodaBateriaDoVMValidateEstaEmEscopoGlobal(t *testing.T) {
	fonte := lerVMValidate(t)
	achadas := reDefinicaoDeBateria.FindAllStringSubmatch(fonte, -1)
	if len(achadas) == 0 {
		t.Fatal("nenhuma definição de bateria encontrada: o teste não estaria medindo nada")
	}
	for _, m := range achadas {
		if m[1] != "" {
			t.Errorf("%s() está indentada (%d espaço(s)): função aninhada só existe depois que a externa roda, "+
				"e a bateria some da rodada em silêncio se a externa sair mais cedo",
				m[2], len(m[1]))
		}
	}
}

// E toda bateria definida tem de ser CHAMADA — uma bateria que existe e ninguém
// invoca é a mesma cobertura fantasma por outro caminho.
func TestTodaBateriaDefinidaEhChamada(t *testing.T) {
	fonte := lerVMValidate(t)
	for _, m := range reDefinicaoDeBateria.FindAllStringSubmatch(fonte, -1) {
		nome := m[2]
		chamada := regexp.MustCompile(`(?m)^\s*` + nome + `\s*$`)
		if !chamada.MatchString(fonte) {
			t.Errorf("%s() é definida e nunca chamada", nome)
		}
	}
}

// A bateria da cota tem de registrar PULADA quando não roda. Sem isso o resumo
// conta cobertura que não houve, que é o mesmo defeito com outra roupa.
func TestBateriaDaCotaRegistraQuandoNaoRoda(t *testing.T) {
	fonte := lerVMValidate(t)
	i := strings.Index(fonte, "battery_host_quota() {")
	if i < 0 {
		t.Fatal("battery_host_quota não existe")
	}
	corpo := fonte[i:]
	if j := strings.Index(corpo[1:], "\nbattery_"); j > 0 {
		corpo = corpo[:j]
	}
	if !strings.Contains(corpo, "pular ") {
		t.Error("a bateria da cota falha em silêncio quando não há sessão: nada entra em PULADAS")
	}
}

func lerVMValidate(t *testing.T) string {
	t.Helper()
	_, arquivo, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	raiz := filepath.Dir(filepath.Dir(filepath.Dir(arquivo)))
	b, err := os.ReadFile(filepath.Join(raiz, "scripts", "vm-validate.sh"))
	if err != nil {
		t.Fatalf("ler vm-validate.sh: %v", err)
	}
	return string(b)
}
