package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
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
//  3. Reconstruir a forward: bloqueios primeiro, depois um jump por grupo
//     ativado, na ordem do admin.
//  4. Só agora apagar as chains órfãs (grupos que o admin removeu), e só se
//     o passo 3 tiver dado certo. O nft recusa apagar chain ainda
//     referenciada (EBUSY) — se isto rodasse antes do passo 3, ou depois de
//     um passo 3 que falhou, a forward ainda teria o jump; o `delete`
//     falharia, mas o `flush` que vem antes dele não, e a órfã ficaria
//     vazia e ainda referenciada (fail-open — ver o passo 4 no código).
//
// Falha por regra é contida (design spec §8): o nft recusar uma regra de um
// grupo NÃO interrompe os passos seguintes. Interromper faria uma única
// regra ruim tirar da forward os jumps de todos os outros grupos — o admin
// veria os grupos dele pararem de valer sem ter mexido em nada. O erro é
// acumulado e devolvido no fim, depois de o que dá para aplicar estar
// aplicado, para o apply ser reportado como não-ok (nunca um "ok"
// sintético).
func (s *Service) ReconcileGroups(ctx context.Context, groups []StoredGroup) error {
	if s.exec.IsDryRun() {
		return nil
	}

	// Um nome de chain que não pode ir para o nft tira o grupo inteiro do
	// jogo — os outros continuam. Filtrar aqui, uma vez, garante que os
	// quatro passos abaixo enxergam o mesmo conjunto: um grupo pulado não
	// tem chain criada, não é preenchido e não entra na forward (o filtro
	// de forwardChainRules é a segunda camada, para qualquer outro chamador).
	valid := make([]StoredGroup, 0, len(groups))
	var failures []string
	for _, g := range groups {
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

	wanted := make(map[string]bool, len(valid))
	for _, g := range valid {
		wanted[g.ChainName] = true
	}

	// 1. criar o que falta (idempotente: `add chain` não reclama se já existe)
	for _, g := range valid {
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
	forwardErr := s.rebuildChain(ctx, ForwardChain, forwardChainRules(valid))
	if forwardErr != nil {
		failures = append(failures, forwardErr.Error())
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
	if forwardErr != nil {
		slog.Error("chains de grupo órfãs não foram limpas nesta passada: a forward não pôde ser reconstruída e ainda pode referenciá-las",
			"err", forwardErr)
	} else if live, err := s.listGroupChains(ctx); err != nil {
		// Sem saber o que está vivo, não se apaga nada — um `delete` no
		// escuro é pior do que uma chain órfã, que não é alcançada por
		// ninguém desde o passo 3.
		slog.Warn("não foi possível listar as chains de grupo para limpar as órfãs", "err", err)
	} else {
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

	slog.Info("grupos de regras reconciliados a partir do banco",
		"grupos", len(groups), "aplicados", len(valid),
		"regras_puladas", len(skippedAll), "falhas", len(failures))

	if err := s.Persist(ctx); err != nil {
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
// Como roda antes do INSERT, a chain do grupo NOVO ainda não existe no
// kernel — e no nft (verificado ao vivo) tanto `flush chain` quanto `jump`
// para chain inexistente falham dentro de um script de `nft -c`. Por isso
// cada script validado é precedido do `add chain` das chains de grupo que
// ele usa (CheckChainEnsuring): sem isso, a validação recusaria todo grupo
// novo — ou seja, criar qualquer grupo devolveria 400.
func (s *Service) CheckGroups(ctx context.Context, groups []StoredGroup) error {
	ensure := make([]string, 0, len(groups))
	for _, g := range groups {
		if !validGroupChainName(g.ChainName) {
			return fmt.Errorf("grupo %q: nome de chain inválido (%q)", g.Name, g.ChainName)
		}
		ensure = append(ensure, g.ChainName)
		tokenSets, _ := renderGroupChain(g)
		if err := s.CheckChainEnsuring(ctx, g.ChainName, tokenSets, []string{g.ChainName}); err != nil {
			return fmt.Errorf("grupo %q: %w", g.Name, err)
		}
	}
	return s.CheckChainEnsuring(ctx, ForwardChain, forwardChainRules(groups), ensure)
}
