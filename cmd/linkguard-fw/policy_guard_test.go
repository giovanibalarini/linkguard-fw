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

// TestMainNaoLigaFonteDePolitica: o mesmo, um degrau antes. Ligar a fonte já
// permite que um valor gravado no banco vire política — e o caminho que grava
// esse valor é justamente o que ainda não existe.
func TestMainNaoLigaFonteDePolitica(t *testing.T) {
	fset := token.NewFileSet()
	entradas, _ := os.ReadDir(".")

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
			if !ok || sel.Sel.Name != "SetInputPolicySource" {
				return true
			}
			t.Errorf("%s:%d chama SetInputPolicySource.\n\n"+
				"A fonte da política só deve ser ligada quando o caminho que a grava\n"+
				"existir e as regras de sobrevivência estiverem em vigor (issue #78).",
				nome, fset.Position(sel.Pos()).Line)
			return true
		})
	}
}
