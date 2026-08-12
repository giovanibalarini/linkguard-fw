package firewallrules

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// GroupsMigratedSettingKey trava a migração única das regras soltas para o
// grupo padrão. É uma flag de "isto já rodou alguma vez", deliberadamente, e
// não uma checagem de "a tabela de grupos está vazia": esta última faria o
// grupo voltar a existir no boot seguinte a um admin ter apagado todos os
// grupos de propósito — exatamente a confiança falsa que o modelo de
// reconciliação existe para eliminar. Mesmo raciocínio de ImportedSettingKey.
const GroupsMigratedSettingKey = "firewall_groups_migrated"

// DefaultGroupName é o nome do grupo que recebe as regras que já existiam.
// Neutro de propósito: o comportamento resultante é idêntico ao de antes da
// migração — sem condição de entrada e "continuar avaliando" —, então o
// admin renomeia e divide depois, com calma.
const DefaultGroupName = "Minhas regras"

// SystemGroupsSettingKey trava a criação única dos dois grupos do sistema
// (hosts bloqueados, destinos bloqueados). Pelo mesmo motivo de
// GroupsMigratedSettingKey e ImportedSettingKey, é "isto já rodou alguma vez"
// e não "a tabela já tem grupo do sistema": a segunda forma faria o boot
// seguinte recriar — ligado, e de volta ao topo — o bloqueio que o admin
// desligou ou reordenou de propósito.
//
// A trava tem um segundo papel, que é o que a torna crítica: gravada, ela
// significa "a partir de agora os dois grupos do sistema TÊM que estar na
// lista". É o que Reconcile verifica antes de reconstruir a chain forward —
// ver ensureSystemGroupsPresent.
const SystemGroupsSettingKey = "firewall_system_groups_created"

// Nomes fixos dos dois grupos do sistema. Ao contrário do nome de um grupo do
// admin, estes não são editáveis (spec §2.1): eles identificam um
// comportamento do produto, não uma escolha de organização.
const (
	BlockedHostsGroupName = "Hosts bloqueados"
	BlocklistGroupName    = "Destinos bloqueados"
)

// systemGroupRows é a definição canônica dos dois grupos do sistema, na ordem
// em que a migração os cria: bloqueios primeiro, que é o comportamento que já
// está em produção.
//
// Eles nascem sem condição de entrada e com "continuar avaliando" porque um
// grupo do sistema não tem nem uma coisa nem outra (spec §2.1): o conteúdo
// dele são os membros de um named set do nft, e as linhas que ele emite na
// forward são fixas. Os campos existem na tabela porque a tabela é a mesma;
// deixá-los no valor neutro é o que garante que, se algum código genérico de
// grupo olhar para eles, encontre "sem condição, sem linha final" em vez de
// lixo.
func systemGroupRows() []storage.FirewallGroup {
	return []storage.FirewallGroup{
		{
			ID:          uuid.NewString(),
			Name:        BlockedHostsGroupName,
			ChainName:   nftables.SystemChainBlockedHosts,
			Enabled:     true,
			Fallthrough: nftables.FallthroughContinue,
			Kind:        nftables.GroupKindBlockedHosts,
		},
		{
			ID:          uuid.NewString(),
			Name:        BlocklistGroupName,
			ChainName:   nftables.SystemChainBlocklist,
			Enabled:     true,
			Fallthrough: nftables.FallthroughContinue,
			Kind:        nftables.GroupKindBlocklist,
		},
	}
}

// EnsureSystemGroups cria, uma única vez, as duas linhas de grupo que
// representam os bloqueios do produto — os named sets @blocked_hosts e
// @blocklist —, nas posições 0 e 1, empurrando os grupos do admin para
// depois. Nenhum membro de set é tocado: os sets já existem no ruleset e no
// banco, e o que nasce aqui é só a representação deles na lista ordenada que
// o admin vê e reordena (spec §2.4).
//
// Deliberadamente NÃO reconcilia: o boot chama Reconcile logo em seguida, e
// toda mutação de grupo pela API já reconcilia por conta própria. Reconciliar
// aqui só duplicaria uma reconstrução da forward — e, pior, faria a
// verificação de invariante do Reconcile rodar no meio de uma sequência de
// migração ainda em andamento. O ctx está na assinatura para esta função
// continuar sendo chamável do mesmo lugar que as outras da sequência de boot,
// e para não mudar de forma quando precisar falar com o nft.
func (s *Service) EnsureSystemGroups(ctx context.Context) error {
	flag, err := s.db.GetSetting(SystemGroupsSettingKey)
	if err != nil {
		// Nunca "assume que não rodou": um erro de leitura tratado como trava
		// vazia recriaria os dois grupos a cada boot, duplicando-os na lista.
		// Mesma disciplina de MigrateRulesIntoDefaultGroup.
		return fmt.Errorf("ler a trava de criação dos grupos do sistema: %w", err)
	}
	if flag != "" {
		return nil // já criados num boot anterior (e o que houve com eles depois é escolha do admin)
	}

	rows := systemGroupRows()
	if err := s.db.CreateSystemGroups(rows, SystemGroupsSettingKey, "true"); err != nil {
		return fmt.Errorf("criar os grupos do sistema: %w", err)
	}
	slog.Info("grupos do sistema criados no topo da lista de grupos",
		"grupos", []string{BlockedHostsGroupName, BlocklistGroupName})
	return nil
}

// ensureSystemGroupsPresent é a defesa que torna aceitável a chain forward
// deixar de ter os bloqueios fixos em código: a partir do momento em que a
// trava está gravada, os dois grupos do sistema TÊM que estar na lista que vai
// ser renderizada.
//
// Se um deles não estiver (a migração falhou, a linha foi apagada à mão no
// banco, uma restauração parcial), renderizar a forward mesmo assim a
// deixaria sem os `drop` dos sets — e isso não pareceria erro nenhum:
// pareceria um admin que simplesmente não tem aquele bloqueio. Bloqueio
// administrativo sumindo em silêncio é exatamente a mentira que esta tela
// existe para impedir.
//
// Abortar é o lado seguro, e por uma razão concreta: a chain forward VIVA
// continua sendo a última que foi aplicada com sucesso — isto é, com os
// bloqueios dentro. Não emitir comando nenhum preserva a proteção que já está
// valendo e transforma o problema em erro visível (apply status não-ok, faixa
// no painel, alerta). Renderizar seria trocar proteção por silêncio.
//
// É a mesma disciplina que StoredGroups já aplica ao erro de leitura do banco.
// A diferença é que ali a leitura falhou; aqui ela funcionou, e o perigo está
// no que ela não devolveu.
func (s *Service) ensureSystemGroupsPresent(groups []nftables.StoredGroup) error {
	flag, err := s.db.GetSetting(SystemGroupsSettingKey)
	if err != nil {
		// Não dá para provar a invariante, então não se renderiza. Tratar o
		// erro de leitura como "a trava não está gravada" desligaria a
		// verificação exatamente no boot em que o banco está com problema.
		return fmt.Errorf("ler a trava dos grupos do sistema antes de reconstruir a chain forward: %w", err)
	}
	if flag == "" {
		return nil // ainda não migrado: os bloqueios não dependem da lista
	}

	present := make(map[string]bool, 2)
	for _, g := range groups {
		if nftables.IsSystemGroup(g.Kind) {
			present[g.Kind] = true
		}
	}
	var missing []string
	if !present[nftables.GroupKindBlockedHosts] {
		missing = append(missing, BlockedHostsGroupName)
	}
	if !present[nftables.GroupKindBlocklist] {
		missing = append(missing, BlocklistGroupName)
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("a chain forward NÃO foi reconstruída: %s sumiu da lista de grupos depois da migração já ter rodado, e renderizar assim deixaria o firewall sem esse bloqueio sem parecer erro; o firewall segue com o que já estava valendo",
		strings.Join(missing, " e "))
}

// MigrateRulesIntoDefaultGroup adota, uma única vez, as regras que hoje vivem
// soltas (sem group_id) num grupo chamado "Minhas regras": sem condição,
// "continuar avaliando", em primeira posição. A ordem é preservada, e o
// comportamento do firewall depois da migração é o mesmo de antes — é uma
// regra dessa migração, não uma coincidência: um grupo sem condição de
// entrada e sem linha final é, no nft, apenas um desvio que executa as
// mesmas regras na mesma ordem e volta.
//
// Ao final, a chain user_rules é removida do ruleset — mas só DEPOIS de a
// reconciliação ter reconstruído a chain forward, que deixa de emitir o
// `jump user_rules`: o nft recusa apagar uma chain ainda referenciada
// ("Device or resource busy", verificado ao vivo na produção), e inverter
// esses dois passos deixaria uma chain morta no ruleset para sempre. Se a
// reconciliação falhar, esta função para antes de tocar na user_rules: com a
// forward possivelmente ainda pulando para lá, a chain e as regras dentro
// dela são a única coisa que ainda está protegendo a rede.
func (s *Service) MigrateRulesIntoDefaultGroup(ctx context.Context) error {
	flag, err := s.db.GetSetting(GroupsMigratedSettingKey)
	if err != nil {
		return fmt.Errorf("ler a trava de migração de grupos: %w", err)
	}
	if flag != "" {
		// Já rodou num boot anterior. A remoção da chain legada é tentada de
		// novo assim mesmo: ela é tolerante a "não existe" (o caso normal,
		// silencioso) e é a única forma de a máquina onde o `delete` falhou
		// uma vez — nft ocupado, forward ainda referenciando — ter uma
		// segunda chance em vez de carregar a chain morta para sempre.
		//
		// Reconcilia ANTES de tentar remover: o ruleset com que este boot
		// começa é o que foi persistido em /etc/nftables.conf, não
		// necessariamente o que o banco diz agora — se a persistência falhou
		// num boot anterior, ou se o próprio delete falhou e nada mais
		// mexeu na forward depois, o `jump user_rules` pode muito bem ainda
		// estar lá quando chegamos aqui, e o nft recusaria o delete (mesmo
		// "Device or resource busy" da produção). Mesmo padrão do ramo de
		// primeira migração abaixo: reconciliar primeiro é o que garante que
		// a forward já não referencia mais a chain no momento do delete.
		// Best-effort: um erro aqui não pode impedir a tentativa de remoção
		// — removeLegacyUserRulesChain já tolera a chain seguir referenciada
		// (fica só um aviso no log, com nova chance no próximo boot).
		if err := s.Reconcile(ctx); err != nil {
			slog.Warn("não foi possível reconciliar antes de retentar a remoção da chain legada user_rules", "err", err)
		}
		return s.removeLegacyUserRulesChain(ctx)
	}

	rules, err := s.db.ListFirewallRules()
	if err != nil {
		return fmt.Errorf("ler as regras a migrar: %w", err)
	}
	var orphans int
	for _, r := range rules {
		if r.GroupID == "" {
			orphans++
		}
	}

	if orphans == 0 {
		// Nada a agrupar — mas a trava é gravada assim mesmo, senão isto roda
		// de novo a cada boot, para sempre.
		if err := s.db.SetSetting(GroupsMigratedSettingKey, "true"); err != nil {
			return err
		}
		slog.Info("nenhuma regra solta para migrar; grupos marcados como migrados")
		return s.removeLegacyUserRulesChain(ctx)
	}

	id := uuid.NewString()
	g := storage.FirewallGroup{
		ID:          id,
		Name:        DefaultGroupName,
		ChainName:   nftables.GroupChainName(id),
		Position:    0,
		Enabled:     true,
		Fallthrough: nftables.FallthroughContinue,
	}
	// Uma transação só: ou o grupo existe COM todas as regras dentro e a
	// trava gravada, ou nada aconteceu. A trava gravada com metade das regras
	// adotadas deixaria a outra metade órfã — no painel, fora do firewall — e
	// sem segunda chance, porque a trava impede a migração de rodar de novo.
	if err := s.db.MigrateRulesIntoGroup(g, GroupsMigratedSettingKey, "true"); err != nil {
		return fmt.Errorf("migrar regras para o grupo padrão: %w", err)
	}
	slog.Info("regras existentes adotadas pelo grupo padrão",
		"grupo", g.Name, "id", g.ID, "regras", orphans)

	// Reconcilia AGORA: é isto que renderiza a chain do grupo novo e
	// reconstrói a forward sem o jump para user_rules — condição para o passo
	// seguinte. Um erro aqui interrompe a migração: a user_rules não pode ser
	// removida com a forward em estado desconhecido.
	if err := s.Reconcile(ctx); err != nil {
		return fmt.Errorf("aplicar os grupos depois da migração: %w", err)
	}
	return s.removeLegacyUserRulesChain(ctx)
}

// removeLegacyUserRulesChain apaga a chain user_rules, que a partir dos
// grupos não é mais referenciada por ninguém. Falhar aqui não é fatal: a
// chain fica órfã no ruleset, inalcançável e sem efeito nenhum sobre o
// tráfego (DeleteUnreferencedChain nunca a esvazia — ver o doc-comment de
// lá), e a próxima tentativa a remove.
func (s *Service) removeLegacyUserRulesChain(ctx context.Context) error {
	if err := s.nft.DeleteUnreferencedChain(ctx, nftables.UserChain); err != nil {
		slog.Warn("não foi possível remover a chain legada user_rules; ela continua no ruleset como estava, sem ser alcançada pela forward",
			"err", err)
	}
	return nil
}
