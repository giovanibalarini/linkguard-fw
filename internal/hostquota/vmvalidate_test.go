package hostquota

import (
	"os"
	"os/exec"
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
// (sem sessão administrativa).
//
// O efeito: numa rodada em que a sessão falhasse, battery_host_quota nunca
// seria definida, a chamada no runner morreria com "command not found" em
// stderr, o script roda com set -uo pipefail e SEM -e, FAIL não subiria, a
// bateria não entraria em PULADAS e o resumo não mencionaria que a Y não
// existiu. As cinco asserções de silêncio — a única prova executável de que a
// cota não tranca ninguém — sumiriam da rodada inteira, caladas.
//
// A VERIFICAÇÃO É FEITA PELO PRÓPRIO BASH, e não por contagem de chaves. Uma
// definição aninhada fica na coluna zero igual a uma de topo: só quem sabe
// dizer a diferença é o parser que vai executar o arquivo. O teste corta o
// runner do fim, fonta o resto e pergunta ao shell quais funções existem.
//
// bash -n aceita aninhamento sem reclamar. Era a única ferramenta que rodava
// sobre esse arquivo, e foi exatamente por isso que o defeito passou.
// ─────────────────────────────────────────────────────────────────────────────

var (
	reDefinicaoDeBateria = regexp.MustCompile(`(?m)^[ \t]*(battery_[a-z0-9_]+)\(\)`)
	reChamadaDeRunner    = regexp.MustCompile(`(?m)^battery_[a-z0-9_]+[ \t]*$`)
)

func TestTodaBateriaDoVMValidateEstaEmEscopoGlobal(t *testing.T) {
	fonte := lerVMValidate(t)

	declaradas := map[string]bool{}
	for _, m := range reDefinicaoDeBateria.FindAllStringSubmatch(fonte, -1) {
		declaradas[m[1]] = true
	}
	if len(declaradas) == 0 {
		t.Fatal("nenhuma definição de bateria encontrada: o teste não estaria medindo nada")
	}

	definidas := funcoesQueOBashDefine(t, fonte)
	for nome := range declaradas {
		if !definidas[nome] {
			t.Errorf("%s() está escrita no arquivo e NÃO existe em escopo global — está aninhada dentro de outra função. "+
				"Numa rodada em que a externa saia mais cedo, a bateria some da execução em silêncio, "+
				"sem FAIL e sem entrar em PULADAS.", nome)
		}
	}
}

// funcoesQueOBashDefine corta o runner do fim do script, fonta o resto num bash
// separado e devolve o conjunto de funções que passaram a existir.
//
// O corte é necessário porque o runner CHAMA as baterias, e chamá-las aqui
// tentaria falar com uma máquina virtual. O que fica de código de topo antes
// dele são atribuições de variável e a leitura dos argumentos — por isso o
// --deb aponta para um arquivo que existe: sem ele o script sai com 2 antes de
// chegar às definições.
func funcoesQueOBashDefine(t *testing.T, fonte string) map[string]bool {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("sem bash nesta máquina")
	}
	corte := reChamadaDeRunner.FindStringIndex(fonte)
	if corte == nil {
		t.Fatal("não achei o runner no fim do script")
	}
	dir := t.TempDir()
	prefixo := filepath.Join(dir, "prefixo.sh")
	if err := os.WriteFile(prefixo, []byte(fonte[:corte[0]]), 0o600); err != nil {
		t.Fatalf("escrever o prefixo: %v", err)
	}
	deb := filepath.Join(dir, "falso.deb")
	if err := os.WriteFile(deb, []byte("x"), 0o600); err != nil {
		t.Fatalf("escrever o .deb falso: %v", err)
	}
	saida, err := exec.Command("bash", "-c",
		"source "+prefixo+" --deb "+deb+" >/dev/null 2>&1; declare -F").Output()
	if err != nil {
		t.Fatalf("fontar o script: %v", err)
	}
	out := map[string]bool{}
	for _, linha := range strings.Split(string(saida), "\n") {
		campos := strings.Fields(linha)
		if len(campos) == 3 {
			out[campos[2]] = true
		}
	}
	return out
}

// E toda bateria definida tem de ser CHAMADA — uma bateria que existe e ninguém
// invoca é a mesma cobertura fantasma por outro caminho.
func TestTodaBateriaDefinidaEhChamada(t *testing.T) {
	fonte := lerVMValidate(t)
	for _, m := range reDefinicaoDeBateria.FindAllStringSubmatch(fonte, -1) {
		nome := m[1]
		chamada := regexp.MustCompile(`(?m)^[ \t]*` + nome + `[ \t]*$`)
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
