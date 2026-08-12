package firewallrules

import (
	"context"
	"fmt"
	"log/slog"

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
