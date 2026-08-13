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

// TestMainWiresTheInputChainSources guarda a ligação de que a chain input
// depende, e que nenhum teste de pacote consegue enxergar.
//
// Desde a Fase C2 a chain input é reconstruída INTEIRA a cada passada, por um
// renderizador só: as regras de proteção do NTP mais os jumps dos grupos de
// escopo input. Quem reconcilia o NTP sabe o estado do NTP e precisa dos
// grupos; quem reconcilia os grupos sabe os grupos e precisa do estado do
// NTP. nftables.SetInputChainSources é o que entrega a metade que falta em
// cada caso — e o único lugar que pode ligá-la é este main, porque
// internal/nftables não pode importar internal/storage.
//
// Sem essa chamada nada quebra visivelmente: os testes continuam verdes, o
// boot continua subindo, e o efeito é salvar um grupo apagar da chain input a
// proteção do serviço de hora (ou ligar o NTP apagar os grupos do admin) —
// exatamente o tipo de falha silenciosa que a Fase C2 existe para fechar. Daí
// o guarda de deriva, sobre a árvore sintática e não por busca de texto.
func TestMainWiresTheInputChainSources(t *testing.T) {
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

	wired := -1
	firstReconcile := -1
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
		if !isIdent {
			return true
		}
		switch {
		case recv.Name == "nftSvc" && sel.Sel.Name == "SetInputChainSources":
			if wired == -1 {
				wired = int(call.Pos())
			}
		case recv.Name == "nftSvc" && sel.Sel.Name == "ReconcileNTPInput",
			recv.Name == "nftSvc" && sel.Sel.Name == "ReconcileGroups",
			recv.Name == "frSvc" && sel.Sel.Name == "Reconcile":
			if firstReconcile == -1 || int(call.Pos()) < firstReconcile {
				firstReconcile = int(call.Pos())
			}
		}
		return true
	})

	if wired == -1 {
		t.Fatal("o boot não liga mais nftSvc.SetInputChainSources: salvar um grupo passa a apagar a proteção do NTP da chain input, e reconciliar o NTP passa a apagar os grupos de escopo input")
	}
	if firstReconcile == -1 {
		t.Fatal("o boot não reconcilia mais a chain input por nenhum caminho -- se a sequência mudou de forma, este guarda precisa mudar junto")
	}
	if wired > firstReconcile {
		t.Errorf("nftSvc.SetInputChainSources tem que ser ligado ANTES da primeira reconciliação do boot: a primeira passada reconstruiria a chain input com metade do conteúdo")
	}
}
