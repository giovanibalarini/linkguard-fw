# Reskin das telas Firewall e VPN

**Data:** 2026-07-28
**Status:** aprovado (grupo Segurança, rodada 3 do sub-projeto 4 — mesmo padrão validado nas rodadas
1-2; usuário pediu para seguir por todas as rodadas restantes sem pausar para aprovação
intermediária, então este documento registra a auto-revisão da rodada, não é gate de aprovação
humana)

---

## 1. Escopo — reskin puro, zero mudança de comportamento

- `web/src/pages/Firewall.tsx`: 6 seções `<div className="card">` (Regras personalizadas,
  Direcionamento por WAN, Destinos bloqueados, Hosts bloqueados, visualizador de ruleset, tabela de
  snapshots) → `Panel`; o modal de criar/editar regra (`fixed inset-0 bg-black/70
  backdrop-blur-sm...`, sem clique-fora-fecha, sem botão X — mesmo formato do modal do assistente
  2-WAN da rodada 1) → `Modal size="md"`.
- `web/src/components/PortForwarding.tsx` (sub-componente da aba "Encaminhamento"): `div.card` →
  `Panel`, mesmo padrão já usado em `WanBalancing.tsx`/`LinkStressTest.tsx`/`DnsQueryLog.tsx`.
- `web/src/pages/Vpn.tsx`: 3 seções `<div className="card">` (Status, Servidor, Clientes) → `Panel`;
  banner de mensagem → padrão `card border` já estabelecido.

## 2. Achado real durante o levantamento — `PeerConfigModal` precisa de capacidade nova no `Modal`

`Vpn.tsx`'s `PeerConfigModal` (linhas 199-227) tem **dois comportamentos que nenhum dos 6 modais já
convertidos nas rodadas 1-2 tinha**:
1. **Clique fora fecha o modal** — o overlay tem `onClick={onClose}`, e o card interno tem
   `onClick={(e) => e.stopPropagation()}` pra clique dentro não borbulhar e fechar por engano.
2. **Botão X de fechar no cabeçalho**, ao lado do título, além do fluxo normal (aqui nem tem um
   botão "Cancelar" no rodapé — só "Copiar"/"Baixar .conf" e o X do cabeçalho).

Isso não existia em nenhum dos outros 6 modais (Links: criar/editar, assistente 2-WAN, excluir; DHCP:
reserva) — todos fecham só por um botão explícito, nunca por clique fora. Se eu convertesse esse
modal pro `Modal` como ele está hoje, a conversão **removeria** essas duas capacidades — violaria
"zero mudança de comportamento", que é o princípio inegociável de todo este esforço de reskin.

**Decisão**: estender `Modal.tsx` com duas props opcionais, retrocompatíveis (default preserva o
comportamento atual de todo mundo que já usa `Modal`):
- `closeOnBackdropClick?: boolean` (default `false`) — quando `true`, clique no overlay chama
  `onClose`; o card interno sempre para a propagação do clique (`stopPropagation`), incondicional —
  isso não afeta ninguém que não tenha um listener no overlay pra começo de conversa, então é seguro
  deixar sempre ligado no card interno.
- `action?: ReactNode` (mesmo nome/ideia do slot `action` que o `Panel` já tem) — renderizado ao lado
  do `title`, no cabeçalho; quando presente, o cabeçalho vira `flex items-center justify-between` em
  vez do bloco simples de hoje.

Isso é uma mudança **aditiva e retrocompatível** em `Modal.tsx` — os 4 usos já em produção (Links ×3,
DHCP ×1) não passam essas props, então continuam exatamente como estão. Não é uma exceção ao "não
alterar Panel/Modal" das rodadas anteriores por capricho — é o motivo pelo qual esse princípio existe
(preservar comportamento real) que agora exige a mudança, porque apareceu um comportamento real que
as versões anteriores do componente não sabiam representar.

## 3. Testes

Mesmo padrão: `npm run build` por tarefa, sem framework de teste no frontend. Verificação visual
final pendente de confirmação do usuário após deploy (Playwright indisponível neste ambiente).
