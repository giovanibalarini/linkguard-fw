# Fase 2 de Gerenciamento de Interfaces + sistema de design

**Data:** 2026-07-28
**Status:** desenho aprovado, pronto para plano de implementação

---

## 1. Relação com specs existentes

Adendo, não reescrita. A arquitetura completa de Provider/Render/Apply/commit-confirm já está
fechada em `docs/superpowers/specs/2026-07-19-network-interface-management-design.md`
(§5.3, §6) — este documento não a reabre. Este é o segundo adendo de execução, seguindo o
mesmo padrão de `docs/superpowers/specs/2026-07-27-interfaces-fase1-design-system.md` (Fase 1,
já em produção desde v1.0.67).

O que faltava decidir, e este documento resolve:

1. Como sequenciar a Fase 2 frente à migração pendente do servidor de produção
   (`ifupdown` → `systemd-networkd`, spec futura separada)
2. Como a UI de edição/preview/commit-confirm reaproveita padrões já existentes no produto

## 2. Decisões

| Decisão | Razão |
|---|---|
| **Fase 2 constrói o Provider `systemd-networkd` normalmente, mesmo sabendo que fica inerte em produção até a migração** | Confirmado ao vivo em produção: `systemd-networkd` está `inactive`, `networking` (ifupdown) está `active`. A spec de 19/07 §14 já previa essa ordem ("depois, em spec separado: migração..."). Escrever arquivo `.network`/`.netdev` numa máquina que não roda `networkd` é seguro (nada os lê), então não há risco de queda de conectividade construindo a Fase 2 agora — só não há como provar em produção, hoje, que o commit/confirm de fato protege contra perda de acesso remoto. Essa prova real vem depois, quando a migração (próximo sub-projeto natural) rodar. |
| **Commit/confirm reusa o padrão visual/UX já existente em `WanBalancing.tsx`** | O componente já tem exatamente essa mecânica (`/api/routing/balance/confirm`, `/api/routing/balance/rollback`, banner com contagem regressiva) para o modo de balanceamento multi-WAN. Reaproveitar a UX (banner, botões confirmar/reverter, texto de aviso) — só restilizada com `Panel`/`Tag` do sistema de design — evita inventar uma segunda linguagem de "operação perigosa com rede protegida" no mesmo produto. |
| **Edição em página inteira, não modal** | Já é convenção documentada na spec original (§10.2) e evita formulário apertado pra um conjunto de campos com validação de rede (CIDR, gateway dentro da subnet). |

## 3. Escopo desta Fase 2 (= spec 19/07 §14, Fase 2, reafirmado aqui por clareza)

**Dentro:**
- `internal/netif/networkd/`: `Provider` — `Render` puro (arquivos `.network` com prefixo `10-`
  para físicas, preparando o terreno para os prefixos `20-`/`30-` que a Fase 3 vai usar para
  VLAN/bridge; cabeçalho `# managed by linkguard` obrigatório em todo arquivo gerado) e `Apply`
  (staging + swap atômico sobre `/etc/systemd/network/`, `networkctl reload` ou `reconfigure`
  conforme o diff exigir — ver spec 19/07 §5.3 sobre quando cada um é necessário)
- Commit/confirm: `pending_change` persistido no SQLite (deadline 90s padrão, ajustável),
  sobrevive a restart do LinkGuard no meio da janela; expira → restaura snapshot + `networkctl
  reload` + alerta via `internal/alerts`; falha na aplicação → rascunho preservado
- Edição de interface **física** apenas: `AddrMode` (static/dhcp/none), `CIDR`, `Gateway`,
  `MTU`, `Description` — sem criação de VLAN/bridge (Fase 3)
- Rotas: `PUT /api/interfaces/{name}`, `POST /api/interfaces/preview`, `POST
  /api/interfaces/apply`, `POST /api/interfaces/confirm`, `GET /api/interfaces/pending` — todas
  atrás de `interfaces.write`, com auditoria
- Frontend: formulário de edição em página inteira, tela de revisão com diff dos arquivos
  (vindo do `Render` puro), banner de commit/confirm (reuso do padrão `WanBalancing.tsx`), aviso
  destacado quando a mudança afeta a interface de acesso atual do admin (spec §10.4)

**Fora (fica para fases/sub-projetos seguintes, sem mudança):**
- VLAN, bridge, fluxos guiados de criação (Fase 3)
- Histórico de versões, restauração, detecção de deriva de verdade (Fase 4)
- Migração do servidor de produção de `ifupdown` para `systemd-networkd` (spec futura separada
  — sub-projeto seguinte natural após esta Fase 2, para que o Provider passe a ter efeito real)
- Chassi visual de portas físicas (decidido fora de escopo desde o adendo da Fase 1)

## 4. Verificação em produção — o que dá pra provar agora e o que não dá

Dado que `systemd-networkd` está inativo em produção:

- **Dá pra verificar**: preview/diff renderiza corretamente contra o estado real importado na
  Fase 1; `Apply` escreve os arquivos certos no lugar certo com o cabeçalho certo; o banner de
  commit/confirm aparece, conta o tempo, e os botões chamam as rotas certas; o timer de
  rollback persiste através de um restart do LinkGuard (testável via SQLite direto); a
  auditoria registra a ação.
- **Não dá pra verificar em produção ainda**: se a mudança aplicada realmente muda o
  comportamento da interface de rede (porque `networkd` não está no comando). Isso só é
  provável de verdade depois da migração `ifupdown`→`systemd-networkd`.
- A verificação funcional completa (edição realmente muda a rede) roda contra uma máquina de
  teste com `systemd-networkd` já ativo — não a produção — na Task 10 do plano desta fase.

## 5. Testes

Mesmo padrão do sub-projeto anterior: backend com `go test` (regras puras, `Render` comparado
contra arquivos golden `.network`/`.netdev`, `Apply` real dentro de um network namespace
descartável atrás de build tag — spec 19/07 §13 já descreve essa camada), frontend sem
framework de teste unitário (build por tarefa + verificação visual final via Playwright).
