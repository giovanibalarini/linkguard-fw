# Reskin das telas DHCP e DNS

**Data:** 2026-07-28
**Status:** aprovado (rodada 2 do grupo Rede, mesmo padrão já validado na rodada 1 — Links WAN)

---

## 1. Relação com o roadmap

Sub-projeto 4, grupo Rede, rodada 2. Reaproveita 100% da infraestrutura já pronta da rodada 1
(`Panel`, `Modal` — nenhum componente novo é necessário aqui). Usuário pediu para seguir direto por
todas as rodadas restantes sem pausar pra aprovação intermediária — este documento existe para
manter o registro e a auto-revisão de cada rodada, não como gate de aprovação humana.

## 2. Escopo — reskin puro, zero mudança de comportamento

- `web/src/pages/Dhcp.tsx`: 3 `<div className="card">` (Configuração, Reservas, Leases ativos) →
  `Panel`; o modal de criar/editar reserva (`fixed inset-0`, hoje `max-w-md`) → `Modal size="sm"`;
  os banners de erro-de-carregamento/sucesso-ou-erro-de-ação/última-aplicação-falhou → o mesmo
  padrão `card border` já usado em `InterfaceEdit.tsx`/`Links.tsx`.
- `web/src/pages/Dns.tsx`: 2 `<div className="card">` (Resolução, Filtro/blocklist) → `Panel`;
  mesmos banners.
- `web/src/components/DnsQueryLog.tsx`: `<div className="card">` → `Panel`.

Nenhuma chamada de API, validação ou estado muda.

## 3. Mapeamento de banners (mesmo padrão desde a rodada 1)

| Hoje | Vira |
|---|---|
| `className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm"` (erro de carregamento) | sem mudança — já está no padrão certo |
| `className="px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10...' : 'bg-green-500/10...'}"` (mensagem de sucesso/erro de ação) | `className={\`card border ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'} text-sm\`}` |
| `className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400"` (última aplicação falhou) | `className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm"` |

## 4. Testes

Mesmo padrão: `npm run build` por tarefa, sem framework de teste no frontend. Verificação visual
final fica pendente de confirmação pelo usuário após deploy (mesma limitação de Playwright já
registrada nas rodadas anteriores).
