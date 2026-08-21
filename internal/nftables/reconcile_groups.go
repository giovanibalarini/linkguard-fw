package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
)

// reGroupChain é o formato exato que GroupChainName produz. O nome da chain
// sai do banco e é interpolado no argv do `nft`, que junta os argumentos e
// parseia o resultado — um valor fora deste formato (linha antiga, banco
// editado à mão, corrupção) seria injeção de comando no nft, exatamente o
// que reIface e ValidMark já barram nos outros geradores deste pacote. Um
// nome que não casa é motivo para pular o grupo, nunca para mandar mesmo
// assim.
var reGroupChain = regexp.MustCompile(`^` + GroupChainPrefix + `[a-z0-9_]{1,32}$`)

func validGroupChainName(name string) bool {
	return reGroupChain.MatchString(name)
}

// listGroupChains devolve os nomes das chains do ruleset vivo que pertencem
// a grupos (prefixo grp_). É o que permite apagar a chain de um grupo que o
// admin removeu sem nunca tocar em chain de terceiros.
//
// Lê `nft list table inet linkguard` — escopado na tabela do LinkGuard — e
// não `nft list chains`, que só aceita a FAMÍLIA (`list chains [family]`,
// nft(8)): pedir `list chains inet linkguard` é erro de sintaxe, e `list
// chains inet` devolveria também as chains de tabelas de terceiros que por
// acaso comecem com grp_. Reaproveita parseTableRuleset, o mesmo parser que
// o painel usa, em vez de um regex próprio que poderia divergir dele.
func (s *Service) listGroupChains(ctx context.Context) ([]string, error) {
	out, err := s.exec.ExecuteRead(ctx, "nft", "list", "table", Family, Table)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, c := range parseTableRuleset(out) {
		if strings.HasPrefix(c.Name, GroupChainPrefix) {
			names = append(names, c.Name)
		}
	}
	return names, nil
}

// anyRuleIsADrop reporta se algum dos token sets termina em "drop" — é como
// se reconhece, nesta representação, uma linha de bloqueio administrativo
// (todas terminam em "counter", "drop") entre os jumps de grupo do admin
// (que terminam em "jump", <chain>). Usado só pelo alarme de ReconcileGroups
// (m-5): não precisa ser mais esperto que isso, porque o objetivo é detectar
// "zero bloqueios", não validar a forma exata de cada linha.
func anyRuleIsADrop(rules [][]string) bool {
	for _, tokens := range rules {
		if len(tokens) > 0 && tokens[len(tokens)-1] == "drop" {
			return true
		}
	}
	return false
}

// missingSystemKinds devolve os kinds de grupo do sistema que NÃO aparecem na
// lista recebida — a condição exata que o alarme abaixo existe para pegar (um
// chamador que contornou ensureSystemGroupsPresent), e que "nenhuma linha de
// drop na forward" não distingue.
//
// Sem isto o alarme era um slog.Error sempre que o admin desligava os dois
// bloqueios DE PROPÓSITO, coisa que a spec §2.1 permite explicitamente: um
// grupo desligado não emite linha nenhuma (forwardChainRules pula), a forward
// fica sem drop e o log gritava sobre uma máquina em perfeito estado. Alarme
// que dispara sem condição de erro é alarme que ninguém lê.
func missingSystemKinds(groups []StoredGroup) []string {
	present := make(map[string]bool, len(groups))
	for _, g := range groups {
		if IsSystemGroup(g.Kind) {
			present[g.Kind] = true
		}
	}
	var missing []string
	for kind := range systemGroupForwardRules {
		if !present[kind] {
			missing = append(missing, kind)
		}
	}
	sort.Strings(missing) // ordem estável no log
	return missing
}

// ReconcileGroups reconstrói, a partir do banco, todo o conjunto de chains
// dos grupos e a chain forward que os alcança. Mantém as mesmas garantias
// de segurança do resto do pacote: só dá flush nos chains próprios (nunca
// na tabela nem no ruleset), é idempotente para a mesma entrada, é no-op em
// dry-run, e persiste ao final.
//
// A ordem dos quatro passos não é arbitrária, e trocá-la quebra:
//
//  1. Criar as chains que faltam. O nft recusa um `jump` para chain
//     inexistente, então elas precisam existir antes do passo 3.
//  2. Preencher cada chain (flush + regras + linha de "e o que sobrar").
//     Vale também para grupo desligado: as regras dele continuam guardadas
//     no nft, só que ninguém pula para lá.
//  3. Reconstruir a forward: uma lista ordenada só, em que cada item ativado
//     vira ou o jump do grupo do admin ou as linhas de set do bloqueio, na
//     posição que o admin escolheu (ver forwardChainRules). E, logo depois, a
//     input pelo mesmo modelo (inputChainRules, Fase C2): as regras de
//     proteção do NTP mais os jumps dos grupos de escopo input.
//  4. Só agora apagar as chains órfãs (grupos que o admin removeu), e só se
//     o passo 3 tiver dado certo NAS DUAS CHAINS. O nft recusa apagar chain
//     ainda referenciada (EBUSY) — se isto rodasse antes do passo 3, ou
//     depois de um passo 3 que falhou, a forward (ou a input) ainda teria o
//     jump; o `delete` falharia, mas o `flush` que vem antes dele não, e a
//     órfã ficaria vazia e ainda referenciada (fail-open — ver o passo 4 no
//     código).
//
// CONTRATO DO CHAMADOR — lista vazia apaga tudo. `groups` é o conjunto
// COMPLETO de grupos que devem existir no firewall, não um delta:
// ReconcileGroups(ctx, nil) esvazia a forward por completo — desde que ela
// virou uma lista ordenada só, nem os bloqueios administrativos sobram,
// porque eles também são itens da lista — e apaga TODAS as chains grp_. É o
// que uma lista vazia literalmente pede, e é indistinguível, aqui dentro, de
// um chamador que perguntou ao banco, recebeu erro e passou a lista vazia
// mesmo assim — o resultado seria o firewall inteiro do admin sumindo, agora
// com os bloqueios junto, por causa de um SELECT que falhou. Quem chama tem
// que ABORTAR se ListFirewallGroups devolver erro, nunca seguir com lista
// vazia, e é por isso que internal/firewallrules.Service.Reconcile recusa a
// passada quando os dois grupos do sistema não estão na lista
// (ensureSystemGroupsPresent) — a defesa que substitui a garantia que os
// literais em código davam. (Quando a lista chega vazia com chains grp_
// vivas, isto emite um slog.Warn nomeando as chains removidas — é o último
// aviso possível, não uma proteção.)
//
// Falha por regra é contida (design spec §8): o nft recusar uma regra de um
// grupo NÃO interrompe os passos seguintes. Interromper faria uma única
// regra ruim tirar da forward os jumps de todos os outros grupos — o admin
// veria os grupos dele pararem de valer sem ter mexido em nada. O erro é
// acumulado e devolvido no fim, depois de o que dá para aplicar estar
// aplicado, para o apply ser reportado como não-ok (nunca um "ok"
// sintético).
func (s *Service) ReconcileGroups(ctx context.Context, groups []StoredGroup) error {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	return s.reconcileGroups(ctx, groups)
}

// ReconcileGroupsFrom é ReconcileGroups com a LEITURA DO ESTADO junto: `load`
// roda dentro do mesmo lock de reconciliação que a reconstrução.
//
// É o que fecha o I-3 da revisão final, e a diferença entre as duas é a corrida
// inteira. `rebuildChain` é `flush chain` + N × `add rule`, o que não é atômico
// no kernel, e quem chama ReconcileGroups lê o banco antes de chamar. Duas
// passadas concorrentes — uma reversão automática pelo watchdog e um toggle de
// NTP, ou uma mutação de outro admin — podiam então intercalar assim: a passada
// B lê os grupos; a reversão restaura o banco e reescreve as chains; a passada B
// escreve o que leu ANTES da restauração e devolve ao kernel o `jump` que a
// reversão tirou. E o pior não é o jump: o watchdog viu o Reconcile dele devolver
// nil, apagou o pendente, e o firewall fica com a regra perigosa VIVA, sem
// janela, sem watchdog, sem trava e com o painel dizendo que reverteu.
//
// Com a leitura aqui dentro, a passada que perde a corrida lê o banco JÁ
// restaurado e reescreve o mesmo estado — que é o resultado certo.
//
// `load` devolver erro aborta sem tocar em nada, e é obrigação dela (ver o
// CONTRATO DO CHAMADOR acima): lista vazia continua querendo dizer "o admin não
// tem grupo nenhum".
func (s *Service) ReconcileGroupsFrom(ctx context.Context, load func() ([]StoredGroup, error)) error {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	groups, err := load()
	if err != nil {
		return err
	}
	return s.reconcileGroups(ctx, groups)
}

// reconcileGroups é o corpo dos dois. Chamada com reconcileMu já travado.
func (s *Service) reconcileGroups(ctx context.Context, groups []StoredGroup) error {
	if s.exec.IsDryRun() {
		return nil
	}
	// A set de endereços físicos precisa EXISTIR antes de a chain que a
	// referencia ser escrita, e garanti-la aqui é o que faz ela aparecer numa
	// máquina já instalada (#119, fase 2).
	//
	// O DEFEITO QUE ISTO CORRIGE, VISTO EM PRODUÇÃO. A set nascia só no
	// EnsureTable, que é NO-OP em caixa já provisionada — a tabela já existe,
	// então o bootstrap não roda e a set nunca aparece. Resultado do upgrade:
	// a regra `ether saddr @blocked_macs` não podia ser escrita, sumia em
	// silêncio da forward, e o bloqueio continuava valendo só para IPv4 numa
	// caixa cujo painel dizia o contrário.
	//
	// É exatamente o mesmo defeito que a bateria G pegou na contabilidade por
	// host, pela mesma causa: coisa nova que precisa existir em instalação
	// EXISTENTE tem de ser garantida a cada reconciliação, não no bootstrap.
	// A set da contenção (#127) nasce aqui pela mesma razão da de endereços
	// físicos: EnsureTable é no-op em máquina já provisionada, e uma regra que
	// referencia set inexistente some em silêncio da chain.
	if err := s.EnsureAbusersSet(ctx); err != nil {
		slog.Warn("não foi possível garantir a set de contenção; a proteção contra tentativa repetida pode não estar valendo", "err", err)
	}
	if err := s.EnsureBlockedMACSet(ctx); err != nil {
		slog.Warn("não foi possível garantir a set de endereços físicos bloqueados; o bloqueio pode valer só para IPv4 nesta reconciliação", "err", err)
	}

	// Um nome de chain que não pode ir para o nft tira o grupo inteiro do
	// jogo — os outros continuam. Filtrar aqui, uma vez, garante que os
	// quatro passos abaixo enxergam o mesmo conjunto: um grupo pulado não
	// tem chain criada, não é preenchido e não entra na forward (o filtro
	// de forwardChainRules é a segunda camada, para qualquer outro chamador).
	valid := make([]StoredGroup, 0, len(groups))
	var failures []string
	for _, g := range groups {
		if IsSystemGroup(g.Kind) {
			// Grupo do sistema não tem chain própria: o conteúdo dele é um
			// named set e as linhas dele são emitidas direto na forward. O
			// chain_name reservado (sys_…) existe só para ocupar a coluna NOT
			// NULL UNIQUE do banco e nunca vai para o nft — daí ele não passar
			// (nem precisar passar) por validGroupChainName, que cobre o
			// formato grp_ que ReconcileGroups de fato cria e apaga.
			//
			// Segue na lista `valid` porque a forward é montada a partir
			// dela, e a POSIÇÃO do bloqueio no meio dos grupos do admin é
			// escolha do admin.
			valid = append(valid, g)
			continue
		}
		if !validGroupChainName(g.ChainName) {
			slog.Error("grupo não aplicado: nome de chain inseguro",
				"grupo", g.ID, "nome", g.Name, "chain", g.ChainName)
			failures = append(failures, fmt.Sprintf("grupo %q: nome de chain inválido", g.Name))
			continue
		}
		// Um grupo ATIVADO cuja condição de entrada não renderiza não vai
		// ganhar jump na forward (forwardChainRules pula) — a chain dele é
		// criada e preenchida e nenhum pacote entra ali. Um grupo com "e o
		// que sobrar: descartar" simplesmente para de bloquear, o painel o
		// mostra ativado, e sem esta linha o apply ainda dizia ok: falha
		// aberta reportada como sucesso. A chain continua sendo criada e
		// preenchida (contenção de falha: os outros grupos não são
		// afetados, e as regras deste continuam guardadas para quando a
		// condição for corrigida), mas o apply é não-ok e nomeia o grupo.
		//
		// Só para grupo ativado: desligado não tem jump por definição
		// (spec §2.1), e marcá-lo como falha deixaria o painel vermelho por
		// um grupo que o admin não está usando.
		if g.Enabled {
			if _, err := groupJumpTokens(g); err != nil {
				slog.Error("grupo ativado ficou fora da chain forward: condição de entrada inválida",
					"grupo", g.ID, "nome", g.Name, "err", err)
				failures = append(failures, fmt.Sprintf("grupo %q: condição de entrada inválida (%v); o grupo está ativado mas nenhum tráfego passa por ele", g.Name, err))
			}
		}
		valid = append(valid, g)
	}

	// Grupo do sistema fica de fora de `wanted`: ele não tem chain viva para
	// preservar, e o nome reservado dele não é uma chain grp_ que a limpeza de
	// órfãs enxergue.
	wanted := make(map[string]bool, len(valid))
	for _, g := range valid {
		if IsSystemGroup(g.Kind) {
			continue
		}
		wanted[g.ChainName] = true
	}

	// 1. criar o que falta (idempotente: `add chain` não reclama se já existe)
	for _, g := range valid {
		if IsSystemGroup(g.Kind) {
			continue // não tem chain própria
		}
		if _, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, g.ChainName); err != nil {
			// Fatal de propósito: se nem criar chain dá certo, a tabela ou o
			// próprio nft estão fora do ar, e seguir para o passo 3 esvaziaria
			// a forward (flush) sem conseguir reescrever nada nela — o
			// firewall ficaria sem os bloqueios administrativos.
			return fmt.Errorf("criar chain do grupo %q: %w", g.Name, err)
		}
	}

	// 2. preencher cada chain
	var skippedAll []string
	for _, g := range valid {
		if IsSystemGroup(g.Kind) {
			continue // não tem chain própria: nada a preencher
		}
		tokenSets, skipped := renderGroupChain(g)
		skippedAll = append(skippedAll, skipped...)
		if err := s.rebuildChain(ctx, g.ChainName, tokenSets); err != nil {
			// rebuildChain já aplicou tudo que o nft aceitou e registrou cada
			// recusa; o que sobra é levar o erro adiante sem parar os demais.
			slog.Error("chain do grupo ficou incompleta; os outros grupos continuam sendo aplicados",
				"grupo", g.ID, "nome", g.Name, "err", err)
			failures = append(failures, fmt.Sprintf("grupo %q: %v", g.Name, err))
		}
	}

	// 3. reconstruir a forward
	forwardRules := forwardChainRules(valid, s.logBlocks())
	// A invariante "a forward nunca fica sem bloqueio em silêncio" mora uma
	// camada acima (internal/firewallrules.ensureSystemGroupsPresent, que
	// aborta ANTES de chegar aqui quando a lista não tem os dois grupos do
	// sistema) — hoje não há chamador que escape dela, mas ReconcileGroups é
	// exportada, e um chamador futuro que não passe por ali ficaria fora
	// dessa defesa. Isto não é a defesa de verdade: é o alarme para esse
	// caso, barato (um slog.Error, nunca um erro fatal) e que não existia —
	// o único aviso hoje é o de "nenhum grupo veio do banco" (abaixo, passo
	// 4), que não cobre "veio lista, mas sem nenhum bloqueio dentro".
	//
	// A condição é o grupo do sistema ESTAR AUSENTE da lista, não a forward
	// estar sem drop: desligar os dois bloqueios é uma decisão que a spec
	// §2.1 permite, e ela também deixa a forward sem nenhuma linha de drop.
	// A checagem de drop fica como confirmação — presente a linha, não houve
	// contorno nenhum a denunciar.
	if missing := missingSystemKinds(groups); len(missing) > 0 && !anyRuleIsADrop(forwardRules) {
		slog.Error("a chain forward foi reconciliada sem grupo do sistema na lista e sem nenhum bloqueio administrativo (nenhuma linha `drop`); a defesa esperada é internal/firewallrules.ensureSystemGroupsPresent — isto é o alarme para o caso de algum chamador tê-la contornado",
			"kinds_ausentes", missing, "grupos_recebidos", len(groups), "grupos_aplicados", len(valid))
	}
	// A política da forward (issue #92). Erro de leitura aborta a chain inteira,
	// o mesmo contrato dos grupos e do NTP: não saber qual é a política não pode
	// virar "então é accept" numa chain que talvez esteja bloqueando de
	// propósito.
	fwPolicy, fwErr := s.forwardPolicy()
	if fwErr != nil {
		return fmt.Errorf("reconciliar a chain %s: %w", ForwardChain, fwErr)
	}

	var forwardErr error
	if fwPolicy == PolicyDrop {
		// As regras de sobrevivência da forward vêm ANTES de tudo: sem o
		// `established,related`, "bloquear tudo" derruba cada conexão que a rede
		// já tinha, no instante em que é aplicado.
		comSobrevivencia := append(ForwardSurvivalRules(), forwardRules...)

		// Caminho ATÔMICO, e só aqui. Com `flush` + N × `add`, a chain fica
		// vazia com política drop por alguns milissegundos — todo o tráfego da
		// rede cortado a cada reconciliação. Ver rebuildChainAtomic para por que
		// este caminho não é o padrão de todas as máquinas.
		decl := fmt.Sprintf("add chain %s %s %s { type filter hook forward priority filter ; policy %s ; }",
			Family, Table, ForwardChain, string(PolicyDrop))
		forwardErr = s.rebuildChainAtomic(ctx, ForwardChain, decl, comSobrevivencia)
	} else {
		// Política permissiva: o caminho de sempre, byte a byte. A declaração é
		// reafirmada para que voltar de `drop` para `accept` funcione — sem ela,
		// uma máquina que já foi bloqueada nunca mais seria liberada.
		if _, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, ForwardChain,
			"{", "type", "filter", "hook", "forward", "priority", "filter", ";", "policy", "accept", ";", "}"); err != nil {
			return fmt.Errorf("declarar a chain %s: %w", ForwardChain, err)
		}
		forwardErr = s.rebuildChain(ctx, ForwardChain, forwardRules)
	}
	if forwardErr != nil {
		failures = append(failures, forwardErr.Error())
	}

	// 3b. reconstruir a input (Fase C2). A chain input tem um dono só —
	// inputChainRules —, e é por isso que ela é reconstruída aqui e não em
	// ReconcileNTPInput: se cada um escrevesse a sua parte, salvar um grupo
	// apagaria a proteção do NTP e ligar o NTP apagaria os jumps dos grupos.
	// O estado do NTP vem da fonte ligada em SetInputChainSources — a metade
	// que esta função não recebe por parâmetro.
	//
	// Sempre, mesmo sem nenhum grupo de escopo input na lista: só assim
	// APAGAR o último grupo de input tira mesmo o jump dele do firewall.
	//
	// Erro ao LER o estado do NTP aborta a chain input sem tocar nela, exata-
	// mente como ReconcileNTPInput já faz quando não consegue ler os grupos
	// (I-1 da revisão). Um erro de leitura não é "servir NTP está desligado":
	// reconstruir a chain obedecendo a esse valor daria flush nela e reescre-
	// veria só os jumps, apagando do firewall vivo as duas linhas de udp/123
	// enquanto o painel continua mostrando o toggle ligado. A forward já foi
	// reconstruída acima e continua valendo — a contenção de falha deste
	// pacote é por chain, não tudo ou nada.
	ntpNetworks, ntpServing, ntpErr := s.ntpInputState()
	var inputErr error
	if ntpErr != nil {
		inputErr = fmt.Errorf("ler o estado do NTP para reconstruir a chain %s: %w", InputChain, ntpErr)
		slog.Error("a chain input NÃO foi tocada nesta passada: não foi possível ler o estado do NTP, e reconstruí-la sem ele apagaria a proteção do serviço de hora do firewall vivo",
			"err", ntpErr)
		failures = append(failures, inputErr.Error())
	} else if inputErr = s.reconcileInputChain(ctx, valid, ntpNetworks, ntpServing); inputErr != nil {
		slog.Error("a chain input não pôde ser reconstruída por completo", "err", inputErr)
		failures = append(failures, inputErr.Error())
	}

	// 4. remover as órfãs, agora que ninguém mais pula para elas — e SÓ se o
	// passo 3 deu certo. Com a forward antiga ainda viva, ela ainda tem o
	// `jump` para a órfã: o `delete` falharia com EBUSY (o nft recusa apagar
	// chain referenciada), mas o `flush` que vem antes funciona — o nft
	// aceita esvaziar chain referenciada. Sobraria uma forward antiga
	// pulando para uma chain órfã recém-esvaziada, e o tráfego que morria no
	// `drop` daquele grupo passaria a passar. Fail-open num firewall. Uma
	// chain órfã que sobrevive até o próximo apply não custa nada perto
	// disso.
	if forwardErr != nil || inputErr != nil {
		// Vale igual para a input: um grupo de escopo input removido do banco
		// ainda tem o `jump` dele na chain input viva, e o nft recusa apagar
		// chain referenciada (EBUSY) — o `delete` falharia, mas nada garante
		// que o estado intermediário seja seguro. Sem as duas chains
		// reconstruídas, ninguém apaga nada.
		slog.Error("chains de grupo órfãs não foram limpas nesta passada: a forward e/ou a input não puderam ser reconstruídas e ainda podem referenciá-las",
			"err_forward", forwardErr, "err_input", inputErr)
	} else if live, err := s.listGroupChains(ctx); err != nil {
		// Sem saber o que está vivo, não se apaga nada — um `delete` no
		// escuro é pior do que uma chain órfã, que não é alcançada por
		// ninguém desde o passo 3.
		slog.Warn("não foi possível listar as chains de grupo para limpar as órfãs", "err", err)
	} else {
		if len(groups) == 0 && len(live) > 0 {
			// Lista vazia é um comando legítimo ("o admin não tem grupo
			// nenhum") e é indistinguível, daqui de dentro, de um chamador
			// que engoliu o erro de ListFirewallGroups — quem evita o
			// segundo caso é o contrato no doc-comment acima. O que dá para
			// fazer aqui é não deixar isso passar como uma linha de info no
			// meio do boot: apagar todos os grupos do firewall de uma vez é
			// aviso, e nomeia o que foi embora.
			slog.Warn("nenhum grupo veio do banco: TODAS as chains de grupo estão sendo removidas do firewall",
				"chains", live)
		}
		for _, name := range live {
			if wanted[name] || !validGroupChainName(name) {
				continue
			}
			// Delete direto, sem esvaziar antes: verificado ao vivo no nft da
			// produção (Debian 13), `delete chain` numa chain COM regras
			// funciona normalmente — a única restrição real é referência
			// (um `jump` vivo apontando para ela dá "Device or resource
			// busy"), e disso cuida a ordem dos passos 3/4 acima.
			//
			// Um `flush` antes não seria só supérfluo: se o delete falhasse
			// por qualquer referência que esta reconciliação não conhece, a
			// chain sobreviveria VAZIA — e um grupo que terminava em `drop`
			// deixaria de bloquear. Assim, ou a chain some inteira ou nada
			// muda, e o pior caso é uma órfã inalcançável no ruleset.
			if _, err := s.exec.Execute(ctx, "nft", "delete", "chain", Family, Table, name); err != nil {
				slog.Warn("não foi possível remover chain de grupo órfã", "chain", name, "err", err)
				continue
			}
			slog.Info("chain de grupo órfã removida", "chain", name)
		}
	}

	// m-7: "aplicados" tinha que dizer quantas CHAINS foram aplicadas, e
	// len(valid) inclui os dois grupos do sistema — que não têm chain
	// própria (o conteúdo deles é o named set, nunca tocado aqui). Contar
	// só quem de fato ganhou uma chain evita o log sugerir uma aplicação
	// maior do que a que realmente aconteceu.
	chainsApplied := 0
	for _, g := range valid {
		if !IsSystemGroup(g.Kind) {
			chainsApplied++
		}
	}
	slog.Info("grupos de regras reconciliados a partir do banco",
		"grupos", len(groups), "chains_aplicadas", chainsApplied,
		"regras_puladas", len(skippedAll), "falhas", len(failures))

	// Persist grava o ruleset VIVO em /etc/nftables.conf, e o nftables.service
	// do systemd carrega esse arquivo ANTES de o LinkGuard subir. Ou seja: o
	// que for persistido aqui é o firewall com que a máquina volta em TODO
	// boot seguinte, antes de qualquer reconciliação nossa.
	//
	// Por isso ele agora depende de as duas chains estruturais terem sido
	// reconstruídas nesta passada. Antes era incondicional, e o caso que isso
	// quebrava é o pior desta fase: numa REVERSÃO em que a forward e/ou a
	// input não puderam ser reescritas (nft recusando com EBUSY, tabela
	// recriada do zero, leitura do estado do NTP falhando — este último deixa
	// a input intocada por desenho), a regra perigosa que trancou o operador
	// continuava viva no ruleset e era gravada no arquivo de boot. A máquina
	// passava a voltar trancada, sozinha, para sempre.
	//
	// Falha por GRUPO não bloqueia (o `failures` continua podendo ter itens
	// aqui): um grupo com nome de chain inválido ou condição de entrada que
	// não renderiza é um problema do grupo, não do arquivo de boot — a forward
	// e a input foram reconstruídas corretamente sem ele, e não persistir por
	// causa disso congelaria o /etc/nftables.conf num estado antigo enquanto o
	// admin acha que salvou. O caminho normal não muda.
	if forwardErr != nil || inputErr != nil {
		slog.Error("o ruleset NÃO foi persistido para o próximo boot: a chain forward e/ou a input não puderam ser reconstruídas nesta passada, e gravar o ruleset vivo faria a máquina voltar com esse meio-termo em todo boot",
			"err_forward", forwardErr, "err_input", inputErr)
	} else if err := s.Persist(ctx); err != nil {
		// Este WARN já foi a ÚNICA evidência da falha — o apply_status desta
		// mesma passada continuava `{"ok": true}` porque as regras de fato
		// entraram no kernel, só não foram gravadas para o próximo boot. Foi
		// exatamente este caminho que a validação em VM mediu (§10). Hoje o
		// próprio Persist registra o resultado em PersistState, e é de lá que
		// saem o `boot_persist_error` do apply_status e o item "Regras no
		// próximo boot" da Saúde do sistema; o WARN continua por ser o detalhe
		// que só o journal comporta.
		slog.Warn("grupos reconciliados, mas não foi possível persistir para o próximo boot", "err", err)
	}
	if len(failures) > 0 {
		// A recusa do próprio nft é a mensagem mais urgente e vem primeiro.
		// Mas as duas coisas cabem na mesma passada — uma regra que nem
		// renderiza E outra que o nft recusa —, e o chamador precisa das
		// duas: internal/firewallrules.Service.Reconcile faz
		// errors.As(applyErr, &skipped) para nomear no banner as regras que
		// ficaram de fora. Devolver só o texto das failures fazia esses ids
		// nunca saírem do journal. Daí o %w no fim: a mensagem continua
		// sendo uma linha só (é banner), nomeia as regras puladas, e o
		// errors.As continua achando o SkippedRulesError.
		//
		// Atenção para quem for tratar isso: aqui um SkippedRulesError PODE
		// vir acompanhado de recusa do nft. Quem usa errors.As para decidir
		// "foi só uma regra fora, o resto aplicou" (é o que Reconcile faz
		// hoje com user_rules) precisa checar o caso composto antes de
		// converter isso em sucesso.
		msg := fmt.Sprintf("%d grupo(s) não puderam ser aplicados por completo (os demais foram aplicados normalmente): %s",
			len(failures), strings.Join(failures, "; "))
		if len(skippedAll) > 0 {
			return fmt.Errorf("%s; %w", msg, &SkippedRulesError{IDs: skippedAll})
		}
		return fmt.Errorf("%s", msg)
	}
	if len(skippedAll) > 0 {
		return &SkippedRulesError{IDs: skippedAll}
	}
	return nil
}

// DeleteUnreferencedChain remove do ruleset uma chain que ninguém mais
// alcança — hoje, a user_rules depois de a migração para grupos ter tirado o
// `jump` dela da forward (ver
// internal/firewallrules.Service.MigrateRulesIntoDefaultGroup).
//
// Não é "DeleteChainIfEmpty", e a diferença é deliberada: NÃO existe flush
// antes do delete. Verificado ao vivo no nft da produção (Debian 13),
// `delete chain` numa chain COM regras funciona; a única restrição real é
// referência — um `jump` vivo apontando para ela dá "Device or resource
// busy". Um flush "para garantir" não seria só supérfluo: se o delete
// falhasse justamente por ainda haver referência (o nft ACEITA esvaziar
// chain referenciada), a chain sobreviveria VAZIA e ainda alcançada, e todo
// tráfego que as regras do admin bloqueavam ali passaria a passar. Fail-open
// num firewall, causado pela linha que existia para "garantir". Assim, ou a
// chain some inteira ou nada muda — e o pior caso é uma chain inalcançável
// no ruleset, sem efeito nenhum sobre o tráfego, que a próxima passada
// remove. É a mesma escolha, pela mesma razão, do passo 4 de ReconcileGroups.
//
// "Não existe" não é erro: isto é chamado em todo boot depois da migração e
// não pode virar ruído no log de uma máquina onde a chain sumiu há semanas.
func (s *Service) DeleteUnreferencedChain(ctx context.Context, chain string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	if _, err := s.exec.ExecuteRead(ctx, "nft", "list", "chain", Family, Table, chain); err != nil {
		return nil // não existe mais: nada a fazer
	}
	if _, err := s.exec.Execute(ctx, "nft", "delete", "chain", Family, Table, chain); err != nil {
		return fmt.Errorf("remover chain %s: %w", chain, err)
	}
	slog.Info("chain legada removida do ruleset", "chain", chain)
	return nil
}

// CheckGroups valida, com um dry run só de parsing (`nft -c`), exatamente
// as chains que ReconcileGroups renderizaria — mesma renderização, mesma
// ordem — para que uma regra que passa aqui esteja garantida de virar os
// mesmos comandos que a reconciliação de verdade vai emitir depois.
//
// Roda ANTES de qualquer escrita no banco (ver
// internal/firewallrules.Service.CheckPendingGroups): validação de campo
// não pega tudo que o nft recusaria, e reconciliar direto numa regra que o
// nft recusa já custou uma chain truncada em produção.
//
// São TRÊS scripts validados, e a input é um deles (I-3 da revisão da Fase
// C2): a chain de cada grupo, a forward e a input. Deixar a input de fora
// quebrava a promessa do parágrafo acima justamente onde ela custa mais — no
// dia em que a API expuser o campo `scope`, uma condição de entrada que o nft
// recusa passaria pelo gate de 400, entraria no banco e só falharia no apply,
// depois de o flush já ter esvaziado a chain input viva.
//
// Como roda antes do INSERT, a chain do grupo NOVO ainda não existe no
// kernel — e no nft (verificado ao vivo) tanto `flush chain` quanto `jump`
// para chain inexistente falham dentro de um script de `nft -c`. Por isso
// cada script validado é precedido do `add chain` das chains de grupo que
// ele usa (CheckChainEnsuring): sem isso, a validação recusaria todo grupo
// novo — ou seja, criar qualquer grupo devolveria 400.
//
// A própria chain input entra nesse mesmo `ensure`, e pelo mesmo motivo: ela
// pode não existir numa máquina anterior a 2026-08-11, e aí o `flush chain`
// dela derrubaria o script inteiro. Forma verificada ao vivo contra o nft de
// verdade (v1.1.3, Debian 13, dentro de um netns), nos dois estados que
// importam: com a input já existindo como base chain (`add chain` sem
// declaração é aceito como no-op) e com ela ausente (o `add chain` do script
// é o que faz o resto parsear). Nos dois casos `nft -c` aceitou e não
// materializou nada — a mesma verificação, sem o `add chain`, falha com "No
// such file or directory".
func (s *Service) CheckGroups(ctx context.Context, groups []StoredGroup) error {
	ensure := make([]string, 0, len(groups))
	for _, g := range groups {
		if IsSystemGroup(g.Kind) {
			// Sem chain própria para validar — e recusá-lo aqui seria pior do
			// que inútil: o pré-voo recebe o conjunto COMPLETO de grupos, então
			// um "nome de chain inválido" no grupo do sistema faria toda
			// mutação de regra do admin ser rejeitada com 400.
			continue
		}
		if !validGroupChainName(g.ChainName) {
			return fmt.Errorf("grupo %q: nome de chain inválido (%q)", g.Name, g.ChainName)
		}
		ensure = append(ensure, g.ChainName)
		tokenSets, _ := renderGroupChain(g)
		if err := s.CheckChainEnsuring(ctx, g.ChainName, tokenSets, []string{g.ChainName}); err != nil {
			return fmt.Errorf("grupo %q: %w", g.Name, err)
		}
	}
	if err := s.CheckChainEnsuring(ctx, ForwardChain, forwardChainRules(groups, s.logBlocks()), ensure); err != nil {
		return err
	}

	// A input é validada com o MESMO renderizador que a reconciliação usa
	// (inputChainRules), incluindo as linhas de proteção do NTP: validar uma
	// forma diferente da que vai ser aplicada é validar outra coisa.
	//
	// Não conseguir ler o estado do NTP NÃO reprova o grupo do admin. Aqui não
	// se está escrevendo nada — as linhas de udp/123 são geradas por este
	// pacote a partir de CIDRs já saneados (sanitizeNetworks), não é delas que
	// vem a recusa que este pré-voo existe para pegar —, e devolver 400 para
	// toda mutação de grupo por causa de um SELECT de settings que falhou seria
	// trancar o admin fora do painel. O que se valida então são os jumps, que é
	// exatamente a parte que vem do que ele acabou de digitar. (Na hora de
	// APLICAR o mesmo erro tem o efeito oposto e obrigatório: ReconcileGroups
	// aborta sem tocar na chain.)
	ntpNetworks, ntpServing, err := s.ntpInputState()
	if err != nil {
		slog.Warn("não foi possível ler o estado do NTP para o pré-voo da chain input; os jumps dos grupos continuam sendo validados, as linhas de NTP não", "err", err)
		ntpNetworks, ntpServing = nil, false
	}
	// Cópia antes do append: `ensure` foi construído com capacidade de sobra no
	// laço acima, e escrever direto nele poderia sobrescrever o array que o
	// script da forward acabou de usar.
	ensureInput := make([]string, 0, len(ensure)+1)
	ensureInput = append(ensureInput, ensure...)
	ensureInput = append(ensureInput, InputChain)
	// A política entra no pré-voo pelo mesmo princípio da linha acima: validar
	// uma forma diferente da que vai ser aplicada é validar outra coisa. Com
	// política restritiva, as regras de sobrevivência fazem parte da chain, e
	// um pré-voo sem elas aprovaria um conjunto que o nft depois recusa.
	//
	// Erro aqui NÃO reprova a mutação do admin, pela mesma razão do NTP: este
	// caminho não escreve nada, e devolver 400 para toda mutação por causa de um
	// SELECT que falhou seria trancá-lo fora do painel. Na hora de APLICAR o
	// mesmo erro tem o efeito oposto e obrigatório — reconcileInputChain aborta.
	policy, err := s.inputPolicy()
	if err != nil {
		slog.Warn("não foi possível ler a política padrão para o pré-voo da chain input; os jumps continuam sendo validados", "err", err)
		policy = PolicyAccept
	}
	var access AdminAccess
	if policy == PolicyDrop {
		if a, aerr := s.adminAccess(); aerr == nil {
			access = a
		} else {
			slog.Warn("não foi possível ler o acesso administrativo para o pré-voo", "err", aerr)
			policy = PolicyAccept
		}
	}
	// As WANs entram no pré-voo pelo mesmo princípio do NTP e da política:
	// validar uma forma diferente da que vai ser aplicada é validar outra
	// coisa. Erro aqui também não reprova a mutação — este caminho não escreve.
	wans, err := s.wanInterfaces()
	if err != nil {
		slog.Warn("não foi possível ler as WANs para o pré-voo da chain input; os jumps continuam sendo validados, a proteção de entrada não", "err", err)
		wans = nil
	}
	// Mesmo cancelamento do caminho que aplica: sem saber as portas de gerência
	// a proteção não é emitida, e o pré-voo tem de validar a MESMA forma.
	if len(wans) > 0 && policy != PolicyDrop {
		if a, aerr := s.adminAccess(); aerr == nil {
			access = a
		} else {
			wans = nil
		}
	}
	// O pré-voo valida a MESMA forma que o apply escreve: uma chain validada
	// sem a decisão de fechamento é outra chain.
	fechada, ferr := s.wanMgmtClosed()
	if ferr != nil {
		slog.Warn("não foi possível ler o fechamento da gerência para o pré-voo; os jumps continuam sendo validados", "err", ferr)
		fechada = false
	}
	cont, cerr := s.edgeContainment()
	if cerr != nil {
		slog.Warn("não foi possível ler a contenção de borda para o pré-voo", "err", cerr)
		cont = false
	}
	return s.CheckChainEnsuring(ctx, InputChain, inputChainRules(groups, ntpNetworks, ntpServing, policy, access, wans, fechada, cont), ensureInput)
}
