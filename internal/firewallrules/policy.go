package firewallrules

// A política padrão do firewall, guardada e revertida como o resto (issue #78).
//
// ONDE ELA MORA. Na tabela `settings`, e não numa coluna nova nem numa migração
// versionada. O precedente é o `ensureUniqueDHCPReservationIP`: migração que
// falha no boot não é um erro de schema, é o firewall não subir — a classe do
// incidente de 2026-07-24. Um par chave/valor não paga esse risco.
//
// POR QUE ELA ENTRA NO SNAPSHOT. A janela de 90 segundos reverte o que está no
// snapshot, e o snapshot tinha dois campos: grupos e regras. Uma troca de
// política não mexe em nenhum dos dois — então, sem esta mudança, a janela
// desarmaria a mudança MAIS PERIGOSA que o produto sabe fazer sem desfazê-la:
// o pendente sumiria, o prazo venceria, e a política restritiva continuaria de
// pé sem nada apontando para ela.
//
// O campo é ponteiro com omitempty de propósito: uma linha de pendente gravada
// por uma versão anterior não tem o campo, e o Unmarshal deixa o ponteiro nil.
// Nil significa "esta janela é anterior à política" — reverter não mexe na
// política, que é a resposta certa, e nenhuma migração é necessária. É a mesma
// propriedade que o applied_state já explora.

import (
	"fmt"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// PolicySettingKey é a chave em `settings`.
const PolicySettingKey = "firewall_input_policy"

// InputPolicy devolve a política padrão configurada da chain input.
//
// Chave ausente é `accept`, e isso NÃO é fail-open: é o estado de toda máquina
// instalada e o padrão de fábrica do produto. O que seria fail-open é resolver
// um ERRO DE LEITURA para accept — e esse caminho propaga, porque um SELECT que
// falhou não é "o admin não escolheu política". Ver nftables.inputPolicy, que
// trata as duas formas de forma oposta pelo mesmo motivo.
func (s *Service) InputPolicy() (nftables.Policy, error) {
	raw, err := s.db.GetSetting(PolicySettingKey)
	if err != nil {
		return "", fmt.Errorf("ler a política padrão do firewall: %w", err)
	}
	if raw == "" {
		return nftables.PolicyAccept, nil
	}
	p := nftables.Policy(raw)
	if !p.Valid() {
		// Valor estranho no banco não vira accept em silêncio: alguém gravou
		// algo que este código não entende, e escolher a resposta permissiva
		// para uma pergunta não entendida é como um firewall se abre sozinho.
		return "", fmt.Errorf("política padrão inválida gravada no banco: %q", raw)
	}
	return p, nil
}

// SetInputPolicy grava a política. Não aplica nada — quem aplica é a
// reconciliação, e quem a protege é ApplyGuarded.
func (s *Service) SetInputPolicy(p nftables.Policy) error {
	if !p.Valid() {
		return fmt.Errorf("política inválida: %q", p)
	}
	return s.db.SetSetting(PolicySettingKey, string(p))
}
