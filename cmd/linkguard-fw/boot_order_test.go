package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

// TestEnsureSystemGroupsRunsBeforeTheMigrationsThatReconcile é um guarda de
// deriva sobre a ORDEM da sequência de boot deste arquivo, e não é estética.
//
// ImportOnce e MigrateRulesIntoDefaultGroup chamam Reconcile por dentro. A
// partir do momento em que a chain forward passa a ser montada a partir da
// lista de grupos, reconciliar antes de os dois grupos do sistema existirem
// renderizaria uma forward SEM os bloqueios — e é o pior tipo de falha,
// porque não pareceria falha nenhuma: pareceria um admin que simplesmente
// não bloqueou nada. A defesa de firewallrules recusa exatamente esse
// estado, então, com a ordem invertida, o boot de um upgrade passa a
// registrar erro nas duas migrações em vez de migrar.
//
// EnsureSystemGroups não depende de nenhuma das duas (só lê a própria trava
// e insere as duas linhas, deslocando as posições existentes), então rodar
// primeiro não custa nada — e é o que garante que TODA reconciliação do boot
// já enxergue os bloqueios na lista.
//
// A verificação é feita sobre a árvore sintática, e não por busca de texto,
// para não depender de comentários que citem os mesmos nomes.
func TestEnsureSystemGroupsRunsBeforeTheMigrationsThatReconcile(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}

	// Primeira ocorrência de cada chamada, em offset de byte (a ordem léxica
	// dentro do mesmo bloco sequencial é a ordem de execução).
	pos := map[string]int{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		recv, isIdent := sel.X.(*ast.Ident)
		if !isIdent || recv.Name != "frSvc" {
			return true
		}
		if _, already := pos[sel.Sel.Name]; !already {
			pos[sel.Sel.Name] = int(call.Pos())
		}
		return true
	})

	for _, name := range []string{"EnsureSystemGroups", "ImportOnce", "MigrateRulesIntoDefaultGroup", "Reconcile"} {
		if _, found := pos[name]; !found {
			t.Fatalf("o boot não chama mais frSvc.%s -- se a sequência mudou de forma, este guarda precisa mudar junto", name)
		}
	}
	for _, later := range []string{"ImportOnce", "MigrateRulesIntoDefaultGroup", "Reconcile"} {
		if pos["EnsureSystemGroups"] > pos[later] {
			t.Errorf("frSvc.EnsureSystemGroups tem que vir ANTES de frSvc.%s: as duas migrações reconciliam por dentro, e reconciliar sem os grupos do sistema na lista é uma chain forward sem os bloqueios", later)
		}
	}
}
