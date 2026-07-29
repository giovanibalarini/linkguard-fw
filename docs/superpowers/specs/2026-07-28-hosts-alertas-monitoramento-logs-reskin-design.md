# Reskin das telas Hosts, Alertas, Monitoramento e Logs

**Data:** 2026-07-28
**Status:** aprovado (grupo Operação, rodada 4 do sub-projeto 4 — usuário pediu pra seguir por todas
as rodadas restantes sem pausar; este documento registra a auto-revisão da rodada)

---

## 1. Escopo — reskin puro, zero mudança de comportamento

- `web/src/pages/Hosts.tsx`: card "Top consumidores" e o card da lista de hosts (sem título) →
  `Panel`; os 2 modais (apelido do host, confirmar bloqueio/desbloqueio) → `Modal`.
- `web/src/pages/Monitoring.tsx`: 4 cards titulados ("Latência por Link", "CPU e Memória", "Linha do
  tempo" — este com um grupo de botões 1h/6h/24h que vira `action` — e "Tráfego por Interface") →
  `Panel`.
- `web/src/pages/Logs.tsx`: 1 card sem título (tabela de auditoria) → `Panel`.
- `web/src/pages/Alerts.tsx`: **sem mudança nenhuma** — ver §2.

## 2. Achado: `Alerts.tsx` não precisa de nenhuma edição

Ao contrário de toda outra tela deste projeto, `Alerts.tsx` não tem nenhuma seção `.card` com título
que faça sentido virar `Panel`. Cada alerta é seu próprio `.card` numa lista (`space-y-2`), sem
título individual — o mesmo padrão de "cartão de item de lista compacto" que rodadas anteriores já
decidiram **não** converter (ex.: os cards de host por-link em `Monitoring.tsx`, os cards de reserva
em `Dhcp.tsx`). Os estados de carregamento/vazio também já seguem o padrão já estabelecido nas
rodadas 1-3 de não virar `Panel` (loading/empty states ficam como `.card` simples em toda tela já
convertida). O banner de erro já usa exatamente o padrão `card border ...` que as rodadas anteriores
estabeleceram — não precisa de ajuste. Por isso `Alerts.tsx` fica fora do escopo de edição desta
rodada, registrado aqui por transparência (não é um esquecimento).

## 3. Achado: dois modais do `Hosts.tsx` usam uma largura que `Modal` ainda não tem

Os modais de apelido e de confirmar bloqueio em `Hosts.tsx` usam `max-w-sm` — mais estreito que
qualquer tamanho hoje suportado pelo `Modal` (`sm` → `max-w-md`, `md` → `max-w-lg`, `lg` →
`max-w-2xl`). Forçar `size="sm"` (que hoje é `max-w-md`) deixaria esses dois modais visivelmente mais
largos do que são hoje — uma mudança de comportamento visual real, não um simples reskin.

**Decisão**: estender o tipo `size` do `Modal` com um novo valor `'xs'` → `max-w-sm`, mudança aditiva
(o union de tipos ganha mais uma opção; `'sm'`/`'md'`/`'lg'` continuam mapeando pro que já mapeavam).
Mesmo espírito da extensão da rodada 3 (`action`/`closeOnBackdropClick`) — um comportamento real que
já existe em produção e que a versão anterior do componente não conseguia representar.

## 4. Testes

Mesmo padrão: `npm run build` por tarefa, sem framework de teste no frontend. Verificação visual
final pendente de confirmação do usuário após deploy (Playwright indisponível neste ambiente).
