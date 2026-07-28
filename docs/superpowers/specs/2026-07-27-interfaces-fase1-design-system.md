# Fase 1 de Gerenciamento de Interfaces + sistema de design

**Data:** 2026-07-27
**Status:** desenho aprovado, pronto para plano de implementação

---

## 1. Relação com specs existentes

Este documento é um adendo, não uma reescrita. A arquitetura de backend completa
(modelo `Iface`, regras de integridade, `Provider`, commit/confirm, importador, RBAC, API,
testes, as 4 fases de entrega) já está fechada em
`docs/superpowers/specs/2026-07-19-network-interface-management-design.md` — esse spec
continua sendo a fonte da verdade para tudo isso e não é reaberto aqui.

O que faltava decidir, e este documento resolve:

1. Como a Fase 1 (visão geral somente leitura) usa os componentes do sistema de design
   construído no sub-projeto 1 (`docs/superpowers/specs/2026-07-27-design-system-painel.md`)
2. Quanto do "chassi visual de portas físicas" do protótipo de referência (artifact
   `fd8b4815`) entra agora
3. Confirmar que a Fase 1, sozinha, é o primeiro plano de implementação a executar

## 2. Decisões

| Decisão | Razão |
|---|---|
| **Árvore + abas, sem chassi visual por enquanto** | O chassi (portas desenhadas, LED por interface, clique-para-identificar visual) não está na spec de 19/07 original — é ideia nova do protótipo. Construir do zero (layout de porta, estado de LED, interação de clique) é trabalho real sem consumidor validado ainda. A árvore de topologia (já especificada em §10.1 do spec original) mais um botão "Piscar LED" simples cobre a mesma necessidade funcional (identificação física) com menos código novo. Decisão tomada via comparativo visual (protótipo A vs B) — usuário escolheu A. Chassi fica candidato a melhoria visual futura, não descartado. |
| **Primeiro plano = só Fase 1** | Fases 2-4 da spec de 19/07 (edição+commit/confirm, VLAN/bridge, histórico/deriva) ficam para planos separados, na mesma ordem que a spec já definia. Fase 1 sozinha já entrega os itens #1 e #2 de prioridade do spec original ("o que está acontecendo", "qual porta é essa") com risco zero (nada é escrito na rede). |
| **`Tabs` é construído agora** | Foi deliberadamente **não** construído no sub-projeto 1 por falta de consumidor real (YAGNI). A Fase 1 de Interfaces é esse primeiro consumidor real: abas Visão geral / Interfaces / VLANs / Bridges / Tráfego, como já especificado em §10 do spec original. |
| **Reuso de `Panel`/`Tag`** | A árvore de topologia usa `Panel` para os agrupamentos e `Tag` para status (`ok`/`warn`/`crit`) nas portas com problema físico (100M numa gigabit, erro subindo) — mesmos componentes do Painel, nenhum componente novo além de `Tabs`. |

## 3. Escopo desta Fase 1 (= spec 19/07 §14, Fase 1, linha 1, reafirmado aqui por clareza)

**Dentro:**
- Modelo `Iface` (tipos físico/VLAN/bridge, campos completos — ver spec 19/07 §5.1)
- Importador (`internal/netif/importer`): `ip -j link`, `ip -j addr`, `networkctl -j`
- Classificação de ruído: interfaces de sistema (`lo`, `docker*`, `br-<hex>`, `veth*`, `tun*`,
  `tap*`, `wg*`) agrupadas e ocultas por padrão
- `GET /api/interfaces` (permissão `interfaces.read`)
- `GET /api/interfaces/drift` — rota reservada, sem implementação de detecção ainda (isso é
  Fase 4); retorna lista vazia por ora
- Frontend: `Interfaces.tsx` vira casca com abas (`Tabs`, novo); tráfego existente extraído
  para `components/InterfaceTraffic.tsx` sem mudar comportamento; aba "Visão geral" (árvore,
  `Panel`+`Tag`); aba "Interfaces" (listagem com busca, spec 19/07 §10.2)
- Diagnóstico físico ao vivo (carrier, velocidade/duplex, contadores de erro) — já parcialmente
  disponível via `/api/system/status`, mas sem tipo/pai/membros; a Fase 1 é o que adiciona isso
- Identificar porta (`ethtool -p`), permissão `interfaces.write` só para essa ação (é a única
  escrita desta fase — não mexe em config de rede, só pisca um LED)

**Fora (fica para as próprias fases 2-4 da spec original, sem mudança):**
- `Provider.Render`/`Apply`, commit/confirm, edição de qualquer interface
- VLAN, bridge, fluxos guiados de criação
- Histórico de versões, restauração, detecção de deriva de verdade
- Chassi visual de portas físicas (ver §2 acima)

## 4. Testes

Segue o mesmo padrão já estabelecido no sub-projeto 1: sem framework de teste unitário no
frontend (build/type-check por tarefa + verificação visual final com Playwright). Backend usa
o padrão já descrito na spec 19/07 §13 para a camada que se aplica à Fase 1: testes tabelados
para regras puras do modelo, e testes do importador com fixtures de `ip -j link` reais
(incluindo a máquina com 22 interfaces / zoo de bridges do Docker, já mencionada na spec
original).
