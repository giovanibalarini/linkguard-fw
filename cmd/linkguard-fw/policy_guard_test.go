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

// TestMainNaoLigaPoliticaRestritiva é uma guarda de INTENÇÃO, não de correção.
//
// nftables.PolicyDrop existe como tipo desde a issue #81, e o renderizador sabe
// escrevê-la. O que ainda NÃO existe é o direito de usá-la: `drop` na chain
// input corta SSH e painel no instante em que é aplicada, e a issue #78 lista o
// que precisa estar de pé antes — as regras de sobrevivência (survival.go)
// LIGADAS, que hoje são função pura sem chamador.
//
// Sem esta guarda, ligar a política restritiva é uma linha de três palavras em
// buildServices, que passa numa revisão distraída e chega a um firewall de
// produção. Com ela, quem for fazer isso tem de apagar este teste — e aí a
// escolha é deliberada, que é tudo o que se pede.
//
// A checagem é na ÁRVORE SINTÁTICA, e não em texto: um grep casaria com a
// palavra dentro deste próprio comentário.
func TestMainNaoLigaPoliticaRestritiva(t *testing.T) {
	fset := token.NewFileSet()

	entradas, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ler o diretório: %v", err)
	}

	for _, e := range entradas {
		nome := e.Name()
		if e.IsDir() || !strings.HasSuffix(nome, ".go") || strings.HasSuffix(nome, "_test.go") {
			continue
		}

		arq, err := parser.ParseFile(fset, filepath.Join(".", nome), nil, 0)
		if err != nil {
			t.Fatalf("interpretar %s: %v", nome, err)
		}

		ast.Inspect(arq, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "nftables" {
				return true
			}
			if sel.Sel.Name == "PolicyDrop" {
				t.Errorf("%s:%d usa nftables.PolicyDrop.\n\n"+
					"Ligar a política restritiva exige que as regras de sobrevivência\n"+
					"(internal/nftables/survival.go) estejam EM VIGOR — sem elas, `drop`\n"+
					"na chain input corta SSH e painel no instante em que é aplicada.\n"+
					"Ver a issue #78 antes de apagar este teste.",
					nome, fset.Position(sel.Pos()).Line)
			}
			return true
		})
	}
}

// TestMainLigaAsDuasFontesJuntas substitui a guarda anterior, que proibia ligar
// a fonte de política enquanto o recurso não estivesse pronto (issue #81).
//
// Ela cumpriu o papel e foi removida DE PROPÓSITO na issue #78, que é quando o
// recurso ficou pronto — era exatamente esse o combinado: quem ligasse teria de
// apagar um teste, e a escolha seria deliberada em vez de acidental.
//
// O que fica no lugar é a invariante que passou a importar: as DUAS fontes
// andam juntas. Uma política restritiva renderizada sem saber quais portas
// manter abertas corta SSH e painel no instante em que é aplicada. O
// renderizador aborta nesse caso (TestPoliticaRestritivaSemAcessoAdministrativoAborta),
// mas abortar significa a chain input parar de ser reconciliada — e é melhor
// que este teste quebre no CI do que a máquina descobrir isso em produção.
func TestMainLigaAsDuasFontesJuntas(t *testing.T) {
	fset := token.NewFileSet()
	entradas, _ := os.ReadDir(".")

	var temPolitica, temAcesso bool
	for _, e := range entradas {
		nome := e.Name()
		if e.IsDir() || !strings.HasSuffix(nome, ".go") || strings.HasSuffix(nome, "_test.go") {
			continue
		}
		arq, err := parser.ParseFile(fset, filepath.Join(".", nome), nil, 0)
		if err != nil {
			continue
		}
		ast.Inspect(arq, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "SetInputPolicySource":
				temPolitica = true
			case "SetAdminAccessSource":
				temAcesso = true
			}
			return true
		})
	}

	if temPolitica != temAcesso {
		t.Errorf("as duas fontes da política precisam andar juntas: SetInputPolicySource=%v, SetAdminAccessSource=%v.\n\n"+
			"Política restritiva sem acesso administrativo corta SSH e painel no instante em que é aplicada.",
			temPolitica, temAcesso)
	}
	if !temPolitica {
		t.Error("nenhuma das duas está ligada: a postura do firewall não chega ao renderizador (issue #78)")
	}
}
