package main

import (
	"errors"
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

// ─── Correções da revisão da Fase C2 ─────────────────────────────────────

// I-4. A chain input passou a carregar também um `jump` por grupo de escopo
// input, e quem CRIA as chains grp_ é o passo 1 de ReconcileGroups — alcançado
// no boot por frSvc.Reconcile. Numa máquina cujo ruleset foi recriado do zero
// por EnsureTable (recuperação de desastre, como em 2026-08-10) e cujo banco
// tenha um grupo de escopo input, reconciliar a input ANTES disso emite um
// jump para uma chain que ainda não existe: o nft recusa com "No such file or
// directory" e o boot registra um aviso alarmante. A passada seguinte conserta
// sozinha — então o custo não é o firewall, é o log de boot de um firewall de
// produção sendo lido na próxima emergência com um erro que não é erro.
//
// m1 da revisão: nftSvc.ReconcileNTPInput deixou de rodar solto depois de
// frSvc.Reconcile e passou a ficar preso ao ramo de erro dele (frSvc.Reconcile
// → ReconcileGroups já reconstrói a chain input inteira no caminho feliz; ver
// o comentário em main.go). A garantia de ordem original — a input nunca é
// reconciliada por este caminho antes de as chains grp_ existirem — continua
// tendo que valer, então o teste mantém a checagem de posição. Mas agora
// também verifica a condição: a chamada tem que estar DENTRO do bloco
// `if err := frSvc.Reconcile(ctx); err != nil { ... }`, nunca solta depois
// dele — um retrocesso para a chamada incondicional reabriria a duplicação de
// reconciliação que m1 fechou (duas janelas de chain-input-vazia por boot,
// dois Persist) sem que nenhum outro teste deste pacote perceba, já que os
// testes de unidade de internal/nftables não enxergam a sequência de main.go.
//
// Guarda de deriva sobre a árvore sintática, como os dois acima.
func TestNTPInputIsReconciledAfterTheGroupChainsExist(t *testing.T) {
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

	reconcileGroups, reconcileNTP := -1, -1
	var errBranch *ast.BlockStmt // corpo do `if err := frSvc.Reconcile(ctx); err != nil { ... }`
	ast.Inspect(file, func(n ast.Node) bool {
		// Localiza o próprio `if` cujo Init chama frSvc.Reconcile, para saber
		// os limites do bloco de erro dele -- não basta achar a chamada solta,
		// porque o que muda de comportamento aqui é justamente estar dentro ou
		// fora deste bloco.
		if ifStmt, isIf := n.(*ast.IfStmt); isIf {
			if assign, isAssign := ifStmt.Init.(*ast.AssignStmt); isAssign && len(assign.Rhs) == 1 {
				if call, isCall := assign.Rhs[0].(*ast.CallExpr); isCall {
					if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel {
						if recv, isIdent := sel.X.(*ast.Ident); isIdent && recv.Name == "frSvc" && sel.Sel.Name == "Reconcile" {
							if reconcileGroups == -1 {
								reconcileGroups = int(call.Pos())
							}
							if errBranch == nil {
								errBranch = ifStmt.Body
							}
						}
					}
				}
			}
		}

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
		if recv.Name == "nftSvc" && sel.Sel.Name == "ReconcileNTPInput" && reconcileNTP == -1 {
			reconcileNTP = int(call.Pos())
		}
		return true
	})

	if reconcileGroups == -1 || reconcileNTP == -1 {
		t.Fatalf("o boot não chama mais frSvc.Reconcile (%d) e/ou nftSvc.ReconcileNTPInput (%d) -- se a sequência mudou de forma, este guarda precisa mudar junto",
			reconcileGroups, reconcileNTP)
	}
	if reconcileNTP < reconcileGroups {
		t.Errorf("nftSvc.ReconcileNTPInput tem que vir DEPOIS de frSvc.Reconcile: as chains grp_ que os jumps de escopo input alcançam são criadas lá, e emitir o jump antes disso enche o log de boot de erro que não é erro")
	}
	if errBranch == nil {
		t.Fatal("não encontrei o bloco `if err := frSvc.Reconcile(ctx); err != nil { ... }` em main.go -- se a forma mudou, este guarda precisa mudar junto (m1 da revisão)")
	}
	if !(int(errBranch.Pos()) <= reconcileNTP && reconcileNTP <= int(errBranch.End())) {
		t.Errorf("nftSvc.ReconcileNTPInput tem que estar DENTRO do bloco de erro de frSvc.Reconcile, não solto depois dele: frSvc.Reconcile já reconstrói a chain input no caminho feliz (m1 da revisão) -- chamar de novo fora do ramo de erro volta a duplicar a reconciliação e a janela de chain-input-vazia por boot")
	}
}

// I-1, a outra ponta: a fonte que o boot e SetInputChainSources usam para ler
// o estado do NTP não pode devolver "desligado" quando o que aconteceu foi um
// erro de leitura. As quatro saídas, uma a uma.
func TestNtpInputStateFromNeverTurnsAReadErrorIntoServingOff(t *testing.T) {
	boom := errors.New("banco travado")
	if _, serving, err := ntpInputStateFrom(func(string) (string, error) { return "", boom }); err == nil {
		t.Errorf("erro de leitura foi engolido e virou serving=%v", serving)
	} else if !errors.Is(err, boom) {
		t.Errorf("o erro original tem que chegar ao chamador, veio %v", err)
	}

	if _, serving, err := ntpInputStateFrom(func(string) (string, error) { return "{isso não é json", nil }); err == nil {
		t.Errorf("JSON corrompido foi engolido e virou serving=%v", serving)
	}

	// Chave nunca gravada: aí sim "desligado" é a verdade, e não pode virar
	// erro — seria um aviso em todo boot de máquina nova.
	networks, serving, err := ntpInputStateFrom(func(string) (string, error) { return "", nil })
	if err != nil || serving || len(networks) != 0 {
		t.Errorf("chave ausente tinha que ser desligado sem erro, obtive %v/%v/%v", networks, serving, err)
	}

	networks, serving, err = ntpInputStateFrom(func(key string) (string, error) {
		if key != "ntp_config" {
			t.Errorf("chave lida = %q, queria ntp_config", key)
		}
		return `{"serve_lan":true,"allowed_networks":["192.168.3.0/24"]}`, nil
	})
	if err != nil || !serving || len(networks) != 1 || networks[0] != "192.168.3.0/24" {
		t.Errorf("configuração válida mal lida: %v/%v/%v", networks, serving, err)
	}
}
