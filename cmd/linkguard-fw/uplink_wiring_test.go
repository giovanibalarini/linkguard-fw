package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Guardas de deriva do uplink implícito, no mesmo espírito de
// TestMainLigaOEixoDasRegrasAPlataforma e pelo mesmo motivo: SE A LIGAÇÃO
// SUMIR, NADA QUEBRA VISIVELMENTE.
//
// Todas as fontes deste produto têm zero-value permissivo — é o que impede que
// um caminho esquecido mude o comportamento de uma caixa em produção. O preço
// disso é que um refactor que remova a fiação deixa a suíte inteira verde, a
// caixa on-prem perfeita, e a VM de nuvem de volta ao estado que este
// incremento existe para consertar: chain de NAT vazia e nada saindo. Estes
// testes são o que torna esse esquecimento visível.

// mainAST parseia cmd/linkguard-fw/main.go.
func mainAST(t *testing.T) *ast.File {
	t.Helper()
	_, thisFile, ok := localizar()
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(filepath.Dir(thisFile), "main.go"), nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}
	return file
}

// chamadasA conta as chamadas a uma função de nome simples dentro do arquivo.
func chamadasA(file *ast.File, nome string) int {
	n := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		if id, isIdent := call.Fun.(*ast.Ident); isIdent && id.Name == nome {
			n++
		}
		return true
	})
	return n
}

// TestOBootDerivaAsWANsPelaFonteUnica prende os pontos de fiação.
//
// São QUATRO em main.go, e cada um responde por um sintoma diferente numa VM de
// nuvem sem link cadastrado: a fonte da chain input (proteção de entrada e tela
// de exposição), o bootstrap da tabela (a instalação nova nascer já com NAT), a
// reconciliação de boot (masquerade, contabilidade, MSS, registro de conversa)
// e a fonte que a API e o vigia de NAT consultam.
//
// O NÚMERO É MÍNIMO, não exato: acrescentar um consumidor novo é bem-vindo;
// perder os que existem é a regressão.
func TestOBootDerivaAsWANsPelaFonteUnica(t *testing.T) {
	file := mainAST(t)

	if n := chamadasA(file, "wansEfetivas"); n < 4 {
		t.Errorf("main.go chama wansEfetivas %d vez(es); são pelo menos 4 pontos de fiação "+
			"(fonte da chain input, bootstrap da tabela, reconciliação de boot e a fonte da API/vigia). "+
			"Um laço sobre db.GetLinks() no lugar de um deles devolve lista vazia numa VM de nuvem, "+
			"e ali a lista vazia é a máquina sem saída para a Internet", n)
	}
	if n := chamadasA(file, "uplinkDaPlataforma"); n < 1 {
		t.Error("main.go não alimenta mais o PathMTU pela plataforma: a MTU do caminho externo não chega " +
			"ao ajuste de MSS, e o `docker pull` volta a pendurar numa VM de nuvem sem nada falhar")
	}
	// E TEM DE SER O DA PLATAFORMA, NÃO O EFETIVO. São quase o mesmo nome e a
	// troca não quebra nada visivelmente: com o efetivo, cadastrar o link pela
	// tela zera o PathMTU, o ramo `rt mtu` é inalcançável em hairpin, e a
	// mss_clamp nasce vazia numa máquina que a plataforma sabe medir — que é
	// precisamente a configuração do bastion.
	if chamadasA(file, "uplinkEfetivo") > 0 {
		t.Error("main.go voltou a derivar o PathMTU de uplinkEfetivo: um link cadastrado pela tela " +
			"passa a zerar a MTU do caminho, e em hairpin isso não devolve o `rt mtu` — deixa a " +
			"chain de ajuste de MSS VAZIA")
	}
}

// TestONucleoNaoVoltaATerCopiaDoLacoDeLinks: o filtro "link habilitado com
// interface" tinha QUATRO cópias antes desta entrega, e é justamente ele que
// aprendeu a plataforma. Uma quinta cópia — ou uma das quatro ressuscitada —
// seria um consumidor que não enxerga o uplink implícito, isto é, uma parte do
// produto discordando da outra sobre quais são as WANs desta máquina.
func TestONucleoNaoVoltaATerCopiaDoLacoDeLinks(t *testing.T) {
	_, thisFile, ok := localizar()
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "main.go"))
	if err != nil {
		t.Fatalf("ler main.go: %v", err)
	}
	if strings.Contains(string(b), "l.Enabled && l.Interface !=") {
		t.Error("main.go voltou a filtrar os links à mão: a derivação canônica é wansEfetivas, " +
			"em uplink.go, e é a única que conhece o uplink implícito")
	}
}
