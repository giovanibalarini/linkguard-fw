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

// ─── Confirmar-ou-reverte: a verificação de boot (Fase C2) ────────────────

// TestPendingChangeIsRevertedBeforeAnyReconcileOnBoot guarda a ordem de que
// depende a única proteção que existe contra o pior caso desta fase.
//
// Uma regra de escopo input mal escrita tira o SSH e o painel do próprio
// operador, numa máquina remota. A rede de proteção é a janela de 90 s; a
// rede EMBAIXO dela é esta verificação de boot, para quando a máquina cai
// dentro da janela — que é o caso comum quando a mudança foi a causa da
// queda.
//
// A posição é a proteção, não organização: reverter DEPOIS de já ter
// reconciliado é aplicar mais uma vez, na máquina que acabou de voltar,
// exatamente a regra que pode tê-la derrubado. Por isso
// frSvc.RevertPendingOnBoot tem que vir antes de TUDO que aplica firewall no
// boot — as reconciliações do nftSvc e as do frSvc, incluindo o
// nftSvc.Restore que repõe os elementos salvos depois de um bootstrap.
//
// Guarda de deriva sobre a árvore sintática, como os demais deste arquivo:
// nenhum teste de pacote enxerga a sequência de main.go.
func TestPendingChangeIsRevertedBeforeAnyReconcileOnBoot(t *testing.T) {
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

	// m-6: a comparação é feita DENTRO do corpo de provisionSystem, não no
	// arquivo inteiro. Comparar posições no arquivo aprovava um
	// RevertPendingOnBoot que estivesse numa função anterior qualquer — até
	// numa função morta —, e o guarda existe justamente para dizer que ele vem
	// antes das reconciliações NA SEQUÊNCIA QUE O BOOT EXECUTA.
	body := provisionSystemBody(t, file)

	// Só o que APLICA firewall entra na lista. frSvc.WatchPending não entra:
	// é a goroutine do timer, e ela não aplica nada por si.
	applies := map[string]bool{
		"frSvc.EnsureSystemGroups":           true,
		"frSvc.ImportOnce":                   true,
		"frSvc.MigrateRulesIntoDefaultGroup": true,
		"frSvc.Reconcile":                    true,
		"nftSvc.Restore":                     true,
		"nftSvc.ReconcileMasquerade":         true,
		"nftSvc.ReconcileStructuralChains":   true,
		"nftSvc.ReconcileNTPInput":           true,
		"nftSvc.ReconcileGroups":             true,
	}

	revert := -1
	firstApply, firstApplyName := -1, ""
	ast.Inspect(body, func(n ast.Node) bool {
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
		name := recv.Name + "." + sel.Sel.Name
		if recv.Name == "frSvc" && sel.Sel.Name == "RevertPendingOnBoot" && revert == -1 {
			revert = int(call.Pos())
		}
		if applies[name] && (firstApply == -1 || int(call.Pos()) < firstApply) {
			firstApply, firstApplyName = int(call.Pos()), name
		}
		return true
	})

	if revert == -1 {
		t.Fatal("provisionSystem não verifica mais a mudança de firewall pendente: um reboot dentro da janela de confirmação passaria a deixar valendo para sempre uma regra não confirmada que pode ter trancado o operador fora da máquina")
	}
	if firstApply == -1 {
		t.Fatal("provisionSystem não aplica mais firewall por nenhum caminho conhecido -- se a sequência mudou de forma, este guarda precisa mudar junto")
	}
	if revert > firstApply {
		t.Errorf("frSvc.RevertPendingOnBoot tem que vir ANTES de %s: reverter depois de já ter aplicado é aplicar mais uma vez, na máquina que acabou de voltar, a regra que pode tê-la derrubado", firstApplyName)
	}
}

// provisionSystemBody devolve o corpo do FuncLit atribuído a
// `provisionSystem := func() { … }` em main.go — a sequência que o boot de
// fato executa. Os guardas deste arquivo comparam posições DENTRO dele: no
// arquivo inteiro, uma chamada perdida numa função anterior (ou morta)
// aprovaria uma sequência de boot errada (m-6).
func provisionSystemBody(t *testing.T, file *ast.File) *ast.FuncLit {
	t.Helper()
	var body *ast.FuncLit
	ast.Inspect(file, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		name, isIdent := assign.Lhs[0].(*ast.Ident)
		if !isIdent || name.Name != "provisionSystem" {
			return true
		}
		if lit, isLit := assign.Rhs[0].(*ast.FuncLit); isLit && body == nil {
			body = lit
		}
		return true
	})
	if body == nil {
		t.Fatal("não encontrei `provisionSystem := func() { … }` em main.go -- se a sequência de boot mudou de forma, os guardas deste arquivo precisam mudar junto")
	}
	return body
}

// A verificação de boot roda UMA vez POR PROCESSO. provisionSystem é
// reexecutado quando uma tentativa posterior de instalar a base finalmente dá
// certo, e isso pode acontecer meia hora depois da subida, com o operador já
// no painel: sem a trava, essa segunda passada reverteria uma janela de
// confirmação recém-aberta como se a máquina tivesse reiniciado. "No boot"
// tem que querer dizer no boot.
//
// I-5 — por que o guarda olha a DECLARAÇÃO do sync.Once e não só a chamada.
// A versão anterior procurava qualquer CallExpr com selector `.Do` que
// contivesse RevertPendingOnBoot no corpo, e isso não guardava nada: mover o
// `var pendingCheckedOnce sync.Once` para DENTRO do FuncLit de
// provisionSystem — que o recria a cada chamada, ou seja, proteção zero e
// exatamente o bug que este teste existe para pegar — deixava o teste VERDE.
// Passaria também com qualquer outro método chamado `Do`. Então agora são
// três coisas, e nenhuma delas sozinha basta: a chamada é `X.Do(func(){…})`
// com RevertPendingOnBoot dentro; `X` é declarado FORA do corpo de
// provisionSystem (senão não sobrevive entre as passadas); e o tipo de `X` é
// sync.Once (senão `Do` não quer dizer nada).
func TestTheBootPendingCheckRunsOnlyOnce(t *testing.T) {
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
	body := provisionSystemBody(t, file)

	// 1. a chamada: `<recv>.Do(func(){ … frSvc.RevertPendingOnBoot … })`,
	//    dentro de provisionSystem.
	guardName := ""
	ast.Inspect(body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "Do" {
			return true
		}
		recv, isIdent := sel.X.(*ast.Ident)
		if !isIdent {
			return true
		}
		ast.Inspect(call, func(inner ast.Node) bool {
			innerCall, isInnerCall := inner.(*ast.CallExpr)
			if !isInnerCall {
				return true
			}
			if innerSel, isInnerSel := innerCall.Fun.(*ast.SelectorExpr); isInnerSel {
				if r, isID := innerSel.X.(*ast.Ident); isID &&
					r.Name == "frSvc" && innerSel.Sel.Name == "RevertPendingOnBoot" && guardName == "" {
					guardName = recv.Name
				}
			}
			return true
		})
		return true
	})
	if guardName == "" {
		t.Fatal("frSvc.RevertPendingOnBoot tem que estar dentro de um sync.Once.Do em provisionSystem: provisionSystem roda de novo quando a base termina de instalar, e uma segunda passada reverteria uma janela de confirmação aberta minutos antes pelo operador")
	}

	// 2 e 3. a declaração de guardName: fora do corpo de provisionSystem e do
	//        tipo sync.Once. Um `var` recriado a cada passada não guarda nada,
	//        e um `.Do` que não seja de um sync.Once não é uma trava.
	declaredOutside, isOnce := false, false
	ast.Inspect(file, func(n ast.Node) bool {
		spec, isSpec := n.(*ast.ValueSpec)
		if !isSpec {
			return true
		}
		named := false
		for _, name := range spec.Names {
			if name.Name == guardName {
				named = true
			}
		}
		if !named {
			return true
		}
		if int(spec.Pos()) < int(body.Pos()) || int(spec.Pos()) > int(body.End()) {
			declaredOutside = true
		}
		if sel, isSel := spec.Type.(*ast.SelectorExpr); isSel {
			if pkg, isIdent := sel.X.(*ast.Ident); isIdent && pkg.Name == "sync" && sel.Sel.Name == "Once" {
				isOnce = true
			}
		}
		return true
	})

	if !declaredOutside {
		t.Errorf("a trava %q tem que ser declarada FORA do corpo de provisionSystem: declarada dentro, ela é recriada a cada passada e a segunda execução (quando a base termina de instalar) volta a reverter a janela de confirmação que o operador acabou de abrir", guardName)
	}
	if !isOnce {
		t.Errorf("a trava %q tem que ser um sync.Once: `.Do` de qualquer outro tipo não garante execução única, e é a execução única que faz \"no boot\" querer dizer no boot", guardName)
	}
}
