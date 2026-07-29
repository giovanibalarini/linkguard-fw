# Reskin das telas Admin e Configurações (Settings)

**Data:** 2026-07-29
**Status:** aprovado (grupo Sistema, rodada 5 e última do sub-projeto 4 — usuário pediu pra seguir
por todas as rodadas restantes sem pausar; este documento registra a auto-revisão da rodada, não é
gate de aprovação humana)

---

## 1. Escopo — reskin puro, zero mudança de comportamento

### `web/src/pages/Admin.tsx`

- `UsersTab()`: card da tabela de usuários (linha 182, `<div className="card">`, sem título) →
  `Panel`; modal criar/editar usuário (linhas 246-306, `max-w-lg`, título ternário "Editar
  Usuário"/"Novo Usuário") → `Modal size="md"`; modal confirmar exclusão (linhas 308-335, `max-w-md`,
  título "Excluir usuário") → `Modal size="sm"`.
- `RolesTab()`: card da grade de papéis (linha 476, `<div className="card">`, sem título) → `Panel`
  (os cards por-papel dentro do `.map()`, em `rounded-lg border border-gray-800 bg-gray-900/60 p-4`,
  são cartões de item de lista — **não** viram `Panel`, mesmo padrão já estabelecido pra cartões de
  item nas rodadas 2-4); modal criar/editar papel (linhas 527-611, `max-w-2xl`, título ternário
  "Editar Papel"/"Novo Papel", inclui a UI de permissões por área com `indeterminate` checkbox — essa
  lógica deve ser preservada exatamente como está) → `Modal size="lg"`; modal confirmar exclusão
  (linhas 613-640, `max-w-md`, título "Excluir papel") → `Modal size="sm"`.
- Os 2 banners `fetchError` de nível de página (linha 180 em `UsersTab`, linha 474 em `RolesTab`,
  hoje `px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20`) → padrão
  `card border border-red-500/30 bg-red-500/10 text-red-400` já estabelecido (ver §2).
- Os 4 banners internos de modal (`error` em ambos os modais de criar/editar, `deleteError` em ambos
  os modais de excluir) **ficam como estão** — ver §2.

### `web/src/pages/Settings.tsx`

- Card do menu lateral (linha 92, `<div className="card space-y-1">`, sem título) → `Panel`.
- 3 cards de seção com título próprio (linha 118 "Sobre o LinkGuard FW", linha 150 "Configurações
  Gerais", linha 177 "Retenção de tráfego (RRD)") → `Panel`.
- Dentro da seção "Retenção de tráfego": os 3 banners `loadError`/`profileError`/`profileSaved`
  **ficam como estão** (`px-4 py-3 rounded-lg`) — ver §2 (correção: na primeira leitura eu tinha
  classificado esses banners como "nível de página" iguais ao `fetchError` do Admin.tsx, mas na
  verdade eles ficam **dentro** do `<div className="card space-y-4">` da seção "Retenção de tráfego",
  ou seja, dentro do que vira o `children` do `Panel` — não são irmãos do `Panel` como o `fetchError`
  do Admin.tsx é. Isso os coloca na mesma categoria dos banners internos de modal: conteúdo aninhado
  dentro de um cartão que já tem seu próprio tratamento visual, não um banner de nível de página).
- Modal de confirmação "Reduzir retenção de tráfego" (linhas 256-293, `max-w-md`, título plano) →
  `Modal size="sm"`.
- 7 sub-componentes importados por `Settings.tsx`, cada um com exatamente 1 card titulado próprio →
  `Panel`:
  - `NotificationSettings.tsx` (linha 62, título "Notificações" em `<h3>`)
  - `MonitoringSettings.tsx` (linha 27, título "Vigilância" em `<h2>`)
  - `TwoFactorSettings.tsx` (linha 57, título "Verificação em duas etapas (2FA)" em `<h3>`)
  - `HttpsInfo.tsx` (linha 14, título "Acesso ao painel (HTTPS)" em `<h3>`)
  - `BackupRestore.tsx` (linha 63, título "Backup e restauração" em `<h3>`)
  - `UpdateChecker.tsx` (linha 78, título "Atualizações" em `<h3>`)
  - `AISettings.tsx` (linha 105, título "Assistente de IA" em `<h2>`)

  Mesmo padrão já usado em `WanBalancing.tsx`/`LinkStressTest.tsx`/`DnsQueryLog.tsx`/
  `PortForwarding.tsx` nas rodadas anteriores: o `<h2>`/`<h3>` do card vira a prop `title` do `Panel`
  (string simples, sem necessidade de `ReactNode` — `Panel` já aplica `text-white font-semibold`
  automaticamente a título string).

## 2. Achado: o padrão real é "banner aninhado dentro de um cartão não é convertido", não
"banner dentro de modal especificamente"

Ao revisar `Links.tsx` (rodada 1) via grep, confirmei que em nenhuma rodada anterior um banner de
erro **dentro** de um modal (ex.: `error`/`wizardError`/`deleteError` em `Links.tsx`, linhas
459/629/668) foi convertido para o padrão `card border` — só os banners de **nível de página**
(irmãos de `Panel`/modal na árvore, não filhos) receberam esse tratamento. Ao checar `Dhcp.tsx` e
`Dns.tsx` (onde o padrão `card border` foi introduzido, rodada 2) confirmei que essa regra é mais
ampla que só "dentro de modal": os banners `card border` ali (linhas 73/79/80 em `Dhcp.tsx`) ficam
**fora** de qualquer `Panel`, como irmãos diretos no `<div className="p-6 space-y-6">` da página — não
existe, em nenhuma rodada anterior, um banner `card border` aninhado dentro do `children` de um
`Panel`. A razão implícita: o padrão `card border` reaproveita o estilo de cartão de seção da página;
aninhado dentro de outro cartão (`Panel` ou `Modal`, tanto faz), outro "cartão" fica visualmente
redundante.

Esta rodada segue o mesmo padrão, agora entendido corretamente: os 4 banners internos de modal em
`Admin.tsx` (`error`/`deleteError` × 2 modais) **não são tocados** — são filhos do `Modal`. Os 2
banners `fetchError` do Admin.tsx **são** convertidos — são irmãos do `Panel` da tabela/grade, não
filhos. Os 3 banners de `Settings.tsx` na seção de retenção (`loadError`/`profileError`/
`profileSaved`) **não são tocados** — são filhos do `Panel` "Retenção de tráfego (RRD)", a mesma
categoria dos banners internos de modal (ver §1, correção registrada ali).

## 3. Achado: nenhuma extensão nova em `Panel`/`Modal` é necessária

Todos os 4 modais de `Admin.tsx` e o 1 modal de `Settings.tsx` usam larguras já suportadas
(`max-w-md`→`sm`, `max-w-lg`→`md`, `max-w-2xl`→`lg`) e nenhum precisa de `action` ou
`closeOnBackdropClick` (nenhum tem clique-fora-fecha ou botão X no cabeçalho — todos fecham só por
botão explícito "Cancelar"/"Fechar", mesmo padrão dos modais de Links.tsx criar/editar e excluir).
`Modal.tsx` e `Panel.tsx` **não são modificados** nesta rodada.

## 4. Testes

Mesmo padrão de todas as rodadas anteriores: `npm run build` por tarefa, sem framework de teste no
frontend. Verificação visual final pendente de confirmação do usuário após deploy (Playwright
indisponível neste ambiente).
