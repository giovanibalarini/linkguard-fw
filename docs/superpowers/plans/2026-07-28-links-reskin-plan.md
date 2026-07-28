# Reskin da tela Links WAN — Plano de Implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Trocar a casca visual de `Links.tsx`, `WanBalancing.tsx` e `LinkStressTest.tsx` pros
componentes `Panel`/`Tag`/`Modal` do sistema de design, sem alterar nenhum comportamento.

**Architecture:** Um componente novo (`ui/Modal.tsx`) extrai a casca de overlay/scroll/cabeçalho hoje
duplicada 3x em `Links.tsx`. `Panel` (já existente) envolve as seções que hoje são `<div
className="card">`. Nenhuma chamada de API, validação ou estado muda — só o wrapper visual.

**Tech Stack:** React + TypeScript + Vite + Tailwind (mesmo stack dos sub-projetos 1-3, sem
dependência nova).

## Global Constraints

- **Zero mudança de comportamento**: mesmas chamadas de API (`client.get/post/put/delete`), mesma
  lógica de validação do assistente 2-WAN, mesmos nomes e tipos de estado (`useState`). Só a marcação
  (JSX/classes) muda.
- `Panel` e `Tag` já existem em `web/src/components/ui/` — reaproveitar exatamente como estão
  (`web/src/components/ui/Panel.tsx`, `web/src/components/ui/Tag.tsx`), sem alterá-los.
- `StatusBadge.tsx` já usa `Tag` internamente — não precisa de nenhuma mudança.
- `Modal.tsx` (novo) NÃO deve introduzir clique-fora-fecha ou Esc-fecha — nenhum dos 3 modais atuais
  tem esse comportamento hoje, e adicionar seria mudança de comportamento, fora de escopo.
- Sem framework de teste unitário no frontend (decisão deliberada, mesma de todos os sub-projetos
  anteriores) — verificação por tarefa via `npm run build` (checagem de tipos + build de produção).
- Toda tarefa termina com `git commit` próprio.

---

### Task 1: Componente `ui/Modal.tsx`

**Files:**
- Create: `web/src/components/ui/Modal.tsx`

**Interfaces:**
- Produces: `Modal` (default export), props `{ open: boolean; onClose: () => void; title: ReactNode;
  children: ReactNode; size?: 'sm' | 'md' | 'lg'; className?: string }`. `size` mapeia pra
  `max-w-md`/`max-w-lg`/`max-w-2xl` (default `'md'`). `className` é aplicado ao card interno (depois
  das classes estruturais), pra permitir variações de cor/borda/gradiente por chamador — o overlay
  (`bg-black/60`) é fixo e igual pra todo uso, não é parametrizável (ver nota abaixo sobre o
  assistente 2-WAN). O componente retorna `null` quando `open` é `false` — quem usa não precisa mais
  fazer `{show && (...)}` por fora.

- [ ] **Step 1: Escrever o componente**

```tsx
import type { ReactNode } from 'react';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const sizeClass: Record<NonNullable<ModalProps['size']>, string> = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
};

export default function Modal({ open, onClose, title, children, size = 'md', className = '' }: ModalProps) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className={`w-full ${sizeClass[size]} max-h-[90vh] overflow-y-auto ${className}`}>
        <div className="px-6 py-4 border-b border-gray-800">
          {typeof title === 'string' ? <h2 className="text-white font-semibold">{title}</h2> : title}
        </div>
        {children}
      </div>
    </div>
  );
}
```

`onClose` fica declarado na interface mesmo sem uso interno neste componente (nenhum clique-fora ou
Esc) — é o chamador que decide quando chamar `onClose` (ex.: botão "Cancelar"), preservando o
comportamento atual exato de cada um dos 3 modais.

- [ ] **Step 2: Checar tipos e build**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript (o componente ainda não é usado em lugar nenhum, então
só precisa compilar sozinho).

- [ ] **Step 3: Commit**

```bash
git add web/src/components/ui/Modal.tsx
git commit -m "feat(web): componente Modal do sistema de design"
```

---

### Task 2: `Links.tsx` — tabela principal e banner de sucesso viram `Panel`

**Files:**
- Modify: `web/src/pages/Links.tsx:1-8` (imports)
- Modify: `web/src/pages/Links.tsx:331-333` (banner de sucesso)
- Modify: `web/src/pages/Links.tsx:339-399` (tabela)

**Interfaces:**
- Consumes: `Panel` de `web/src/components/ui/Panel.tsx` (`{ title?, action?, children, className? }`,
  já existente — ver Task 1 do sub-projeto 1 se precisar conferir a implementação).

- [ ] **Step 1: Adicionar o import do Panel**

Em `web/src/pages/Links.tsx`, linha 1-8, adicionar a linha de import (mantendo as demais):

```tsx
import { useEffect, useMemo, useState } from 'react';
import WanBalancing from '../components/WanBalancing';
import LinkStressTest from '../components/LinkStressTest';
import { useAuth } from '../context/AuthContext';
import { Plus, Pencil, Trash2, RefreshCw, Wifi, Wand2, Network } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import type { WanLink, SystemMetrics, InterfaceMetrics } from '../types';
```

- [ ] **Step 2: Trocar o banner de sucesso pelo padrão já usado em `InterfaceEdit.tsx`**

Trocar (linha 331-333):

```tsx
      {success && (
        <div className="px-4 py-3 rounded-lg text-sm bg-green-500/10 text-green-400 border border-green-500/20">{success}</div>
      )}
```

por:

```tsx
      {success && (
        <div className="card border border-green-500/30 bg-green-500/10 text-green-400 text-sm">{success}</div>
      )}
```

(Mesmo padrão de `web/src/pages/InterfaceEdit.tsx`, que usa `card border border-red-500/30
bg-red-500/10 text-red-400 text-sm` pro erro — aqui é a variante verde de sucesso.)

- [ ] **Step 3: Envolver a tabela em `Panel`**

Trocar o bloco (linha 339-399, o `<div className="card">` que envolve a tabela) — a estrutura interna
(loading / vazio / tabela) fica idêntica, só a tag externa muda:

```tsx
      <Panel title="Links WAN">
        {loading ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">Carregando...</div>
        ) : links.length === 0 ? (
          <div className="text-center py-12">
            <Wifi className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">Nenhum link configurado</p>
            <p className="text-gray-600 text-sm mt-1">Clique em "Novo Link" para começar</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4 font-medium">Nome</th>
                  <th className="pb-3 pr-4 font-medium">Interface</th>
                  <th className="pb-3 pr-4 font-medium">IP / Gateway</th>
                  <th className="pb-3 pr-4 font-medium">Peso</th>
                  <th className="pb-3 pr-4 font-medium">Latência</th>
                  <th className="pb-3 pr-4 font-medium">Perda</th>
                  <th className="pb-3 pr-4 font-medium">Status</th>
                  <th className="pb-3 font-medium">Ações</th>
                </tr>
              </thead>
              <tbody>
                {links.map(link => (
                  <tr key={link.id} className="table-row">
                    <td className="py-3 pr-4">
                      <div className="text-white font-medium">{link.name}</div>
                      {!link.enabled && <span className="text-gray-600 text-xs">desativado</span>}
                    </td>
                    <td className="py-3 pr-4 text-gray-400 font-mono">{formatInterfaceLabel(link.interface)}</td>
                    <td className="py-3 pr-4">
                      <div className="text-gray-400 font-mono text-xs">{link.ip_address || '—'}</div>
                      <div className="text-gray-600 font-mono text-xs">{link.gateway || '—'}</div>
                    </td>
                    <td className="py-3 pr-4 text-gray-400">{link.weight}</td>
                    <td className="py-3 pr-4 text-gray-400">
                      {link.latency_ms > 0 ? `${link.latency_ms.toFixed(1)} ms` : '—'}
                    </td>
                    <td className="py-3 pr-4 text-gray-400">
                      {link.packet_loss.toFixed(1)}%
                    </td>
                    <td className="py-3 pr-4"><StatusBadge status={link.status} /></td>
                    <td className="py-3">
                      <div className="flex gap-2">
                        <button onClick={() => openEdit(link)} className="text-gray-400 hover:text-blue-400 transition-colors">
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button onClick={() => requestDelete(link.id, link.name)} className="text-gray-400 hover:text-red-400 transition-colors">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
```

`Panel` já produz a mesma classe `card` internamente (ver `web/src/components/ui/Panel.tsx:12`), então
o visual do card em si não muda — o que muda é o título "Links WAN" agora vir do slot padronizado do
`Panel` em vez de só existir no `<h1>` acima da página (esse `<h1>` de topo continua existindo, sem
mudança — o título do Panel é redundante com ele por design, mesmo padrão inconsistente não existe
aqui já que nenhuma outra tela tem título de página + título de Panel iguais; está correto deixar os
dois, o `<h1>` é o título da página e o do Panel é o título daquele card específico).

- [ ] **Step 4: Checar tipos e build**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript.

- [ ] **Step 5: Commit**

```bash
git add web/src/pages/Links.tsx
git commit -m "refactor(web): Links.tsx usa Panel na tabela e no banner de sucesso"
```

---

### Task 3: `Links.tsx` — os 3 modais usam `Modal`

**Files:**
- Modify: `web/src/pages/Links.tsx:1-9` (import do Modal)
- Modify: `web/src/pages/Links.tsx` (os 3 blocos de modal, ver abaixo — os números de linha mudaram
  depois da Task 2; localizar pelos comentários `{/* Modal */}`, `{showWizard && (`, e `{/* Delete
  confirmation modal */}`)

**Interfaces:**
- Consumes: `Modal` de `web/src/components/ui/Modal.tsx` (Task 1) — `{ open, onClose, title, children,
  size?, className? }`.

- [ ] **Step 1: Adicionar o import do Modal**

Em `web/src/pages/Links.tsx`, junto do import do `Panel` adicionado na Task 2:

```tsx
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
```

- [ ] **Step 2: Modal de criar/editar link (`size="md"`, o `max-w-lg` de hoje)**

Trocar:

```tsx
      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">
                {isEditing ? 'Editar Link WAN' : 'Novo Link WAN'}
              </h2>
            </div>
            <form onSubmit={handleSave} className="p-6 space-y-4">
```

por:

```tsx
      {/* Modal */}
      <Modal
        open={showModal}
        onClose={() => setShowModal(false)}
        title={isEditing ? 'Editar Link WAN' : 'Novo Link WAN'}
        size="md"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        <form onSubmit={handleSave} className="p-6 space-y-4">
```

E fechar substituindo o fechamento correspondente:

```tsx
            </form>
          </div>
        </div>
      )}
```

por:

```tsx
        </form>
      </Modal>
```

(O cabeçalho com o `<h2>` que estava manual agora vem do `title` do `Modal` — o texto exibido é
idêntico, `isEditing ? 'Editar Link WAN' : 'Novo Link WAN'`.)

- [ ] **Step 3: Modal do assistente 2-WAN (`size="lg"`, o `max-w-2xl` de hoje, mantendo a borda azul/gradiente)**

Trocar:

```tsx
      {showWizard && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="w-full max-w-2xl rounded-2xl border border-blue-500/30 bg-gradient-to-b from-gray-900 to-gray-950 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
              <div>
                <h2 className="text-white font-semibold flex items-center gap-2">
                  <Network className="w-5 h-5 text-blue-400" />
                  Assistente Mágico de 2 WAN
                </h2>
                <p className="text-xs text-gray-400 mt-1">Configura failover rápido ou balanceamento por marcação de pacotes.</p>
              </div>
            </div>

            <div className="p-6 space-y-5">
```

por:

```tsx
      <Modal
        open={showWizard}
        onClose={() => setShowWizard(false)}
        size="lg"
        className="rounded-2xl border border-blue-500/30 bg-gradient-to-b from-gray-900 to-gray-950 shadow-2xl"
        title={
          <div>
            <span className="text-white font-semibold flex items-center gap-2">
              <Network className="w-5 h-5 text-blue-400" />
              Assistente Mágico de 2 WAN
            </span>
            <p className="text-xs text-gray-400 mt-1">Configura failover rápido ou balanceamento por marcação de pacotes.</p>
          </div>
        }
      >
        <div className="p-6 space-y-5">
```

Nota: o `Modal` (Task 1) só envolve `title` num `<h2>` automaticamente quando `title` é uma string
simples (mesma regra do `Panel`, ver `web/src/components/ui/Panel.tsx:15-20`) — como aqui o título é
um bloco com ícone + texto + subtítulo, ele entra como `ReactNode` puro, sem o `<h2>` automático.
Por isso o `text-white font-semibold` que antes vinha do `<h2>` original precisa estar explícito no
`<span>` acima, senão o título perde o destaque visual (branco, negrito) que tinha antes.

O overlay do assistente hoje é `bg-black/70 backdrop-blur-sm` (mais escuro e desfocado que os outros
dois modais, que usam `bg-black/60` liso) — o `Modal` (Task 1) usa `bg-black/60` fixo pra todo mundo,
então essa pequena diferença de overlay não é reproduzida. É uma simplificação deliberada dentro do
escopo de reskin (nenhum dos elementos de conteúdo muda, só o tom do fundo escurecido por trás do
modal) — não precisa perguntar de novo, já está coberto pela aprovação do spec.

E fechar substituindo o fechamento correspondente:

```tsx
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
```

por:

```tsx
        </div>
      </Modal>

      {/* Delete confirmation modal */}
```

- [ ] **Step 4: Modal de confirmar exclusão (`size="sm"`, o `max-w-md` de hoje)**

Trocar:

```tsx
      {/* Delete confirmation modal */}
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">Excluir Link WAN</h2>
            </div>
            <div className="p-6 space-y-4">
```

por:

```tsx
      {/* Delete confirmation modal */}
      <Modal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title="Excluir Link WAN"
        size="sm"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        <div className="p-6 space-y-4">
```

E fechar substituindo o fechamento correspondente:

```tsx
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
```

por:

```tsx
        </div>
      </Modal>
    </div>
  );
}
```

Atenção: o conteúdo interno deste modal referencia `deleteTarget.name` (ex.:
`Tem certeza que deseja excluir o link "{deleteTarget.name}"?`). Como o `Modal` agora renderiza
mesmo com `deleteTarget` momentaneamente `null` durante a transição de fechamento (`open =
deleteTarget !== null` controla só a visibilidade, não desmonta o acesso ao valor durante o mesmo
render em que `open` já é `false` e o componente retorna `null` antes de tentar ler
`deleteTarget.name`) — isso não muda o comportamento atual, porque o React já não renderiza os
`children` de um componente que retornou `null`. Não precisa de nenhum guard extra.

- [ ] **Step 5: Checar tipos e build**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript. Preste atenção especial a erros de JSX mal fechado —
essa é a tarefa com mais chance de parêntese/tag desalinhado por causa da remoção de 3 níveis de
`<div>` aninhados de cada modal.

- [ ] **Step 6: Commit**

```bash
git add web/src/pages/Links.tsx
git commit -m "refactor(web): Links.tsx usa Modal nos 3 diálogos (criar/editar, assistente, excluir)"
```

---

### Task 4: `WanBalancing.tsx` vira `Panel`

**Files:**
- Modify: `web/src/components/WanBalancing.tsx:1-8` (imports)
- Modify: `web/src/components/WanBalancing.tsx:137-148` (abertura do card + cabeçalho)
- Modify: `web/src/components/WanBalancing.tsx:340-342` (fechamento do card)

**Interfaces:**
- Consumes: `Panel` de `web/src/components/ui/Panel.tsx`.

- [ ] **Step 1: Adicionar o import do Panel**

```tsx
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Scale, Shield, AlertTriangle, Check, RotateCcw, Plus, Trash2, Clock,
  Loader2, ChevronDown, Info, Zap,
} from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import type { WanLink, BalanceStatus, BalanceSchedule } from '../types';
```

- [ ] **Step 2: Trocar a abertura do card pelo `Panel`, com o cabeçalho (ícone + título + HelpTip) como `title`**

Trocar (linha 137-148):

```tsx
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-1">
        <Scale className="w-5 h-5 text-blue-400" />
        <h2 className="text-white font-semibold">Balanceamento de saída (multi-WAN)</h2>
        <HelpTip title="Balanceamento vs. Failover">
          <><b>Failover</b>: usa um link por vez e troca se ele cair. <b>Balanceamento</b>: distribui as
          conexões entre os links ao mesmo tempo, na proporção dos <b>pesos</b> — e ainda tira um link
          do rodízio automaticamente se ele cair.</>
        </HelpTip>
      </div>
      <p className="text-gray-500 text-xs mb-4">Define como o tráfego geral sai pelas suas internets.</p>
```

por:

```tsx
  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <Scale className="w-5 h-5 text-blue-400" />
          <span className="text-white font-semibold">Balanceamento de saída (multi-WAN)</span>
          <HelpTip title="Balanceamento vs. Failover">
            <><b>Failover</b>: usa um link por vez e troca se ele cair. <b>Balanceamento</b>: distribui as
            conexões entre os links ao mesmo tempo, na proporção dos <b>pesos</b> — e ainda tira um link
            do rodízio automaticamente se ele cair.</>
          </HelpTip>
        </span>
      }
      className="mb-1"
    >
      <p className="text-gray-500 text-xs mb-4">Define como o tráfego geral sai pelas suas internets.</p>
```

(`Panel` já detecta que `title` não é `string` e renderiza o `ReactNode` como veio, sem envolver num
`<h2>` extra — ver `web/src/components/ui/Panel.tsx:15-20` — então o `<span className="flex
items-center gap-2">` acima é o que garante o alinhamento ícone+texto+HelpTip, igual ao `<div>`
original. Como o `Panel` não aplica `text-white font-semibold` automaticamente quando `title` não é
string, esse par de classes precisa estar explícito no `<span>` interno que envolve só o texto do
título — sem isso o título perde o destaque visual que tinha no `<h2>` original.)

- [ ] **Step 3: Trocar o fechamento do card**

Trocar (linha 340-342):

```tsx
      </div>
    </div>
  );
}
```

por:

```tsx
      </div>
    </Panel>
  );
}
```

(A última `</div>` antes do fechamento original é a do bloco "Schedules" — linha 320 em diante —, que
não muda; só a tag mais externa, que era `<div className="card">`, vira `</Panel>`.)

- [ ] **Step 4: Checar tipos e build**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/WanBalancing.tsx
git commit -m "refactor(web): WanBalancing.tsx usa Panel"
```

---

### Task 5: `LinkStressTest.tsx` vira `Panel`

**Files:**
- Modify: `web/src/components/LinkStressTest.tsx:1-7` (imports)
- Modify: `web/src/components/LinkStressTest.tsx:78-89` (abertura do card + cabeçalho)
- Modify: `web/src/components/LinkStressTest.tsx:202-205` (fechamento do card)

**Interfaces:**
- Consumes: `Panel` de `web/src/components/ui/Panel.tsx`.

- [ ] **Step 1: Adicionar o import do Panel**

```tsx
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  FlaskConical, Play, Square, Loader2, AlertTriangle, Check, X, Wifi, Globe,
} from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import type { WanLink, StressTest } from '../types';
```

- [ ] **Step 2: Trocar a abertura do card pelo `Panel`**

Trocar (linha 78-89):

```tsx
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-1">
        <FlaskConical className="w-5 h-5 text-amber-400" />
        <h2 className="text-white font-semibold">Stress-test dos links</h2>
        <HelpTip title="Stress-test">
          <>Valida o failover multi-WAN <b>sob demanda</b>: derruba ou degrada uma WAN de propósito,
          mede a continuidade (ping/DNS) enquanto o balanceador reage, e <b>restaura sozinho</b>.
          Assim você confirma que o failover funciona sem esperar o provedor cair.</>
        </HelpTip>
      </div>
      <p className="text-gray-500 text-xs mb-4">Testa uma WAN de cada vez, com restauração automática (à prova de falha do próprio painel).</p>
```

por:

```tsx
  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <FlaskConical className="w-5 h-5 text-amber-400" />
          <span className="text-white font-semibold">Stress-test dos links</span>
          <HelpTip title="Stress-test">
            <>Valida o failover multi-WAN <b>sob demanda</b>: derruba ou degrada uma WAN de propósito,
            mede a continuidade (ping/DNS) enquanto o balanceador reage, e <b>restaura sozinho</b>.
            Assim você confirma que o failover funciona sem esperar o provedor cair.</>
          </HelpTip>
        </span>
      }
      className="mb-1"
    >
      <p className="text-gray-500 text-xs mb-4">Testa uma WAN de cada vez, com restauração automática (à prova de falha do próprio painel).</p>
```

- [ ] **Step 3: Trocar o fechamento do card**

Trocar (linha 202-205):

```tsx
      {!canRun && <p className="text-gray-600 text-xs">Você não tem permissão para rodar testes (requer gestão de rotas).</p>}
    </div>
  );
}
```

por:

```tsx
      {!canRun && <p className="text-gray-600 text-xs">Você não tem permissão para rodar testes (requer gestão de rotas).</p>}
    </Panel>
  );
}
```

- [ ] **Step 4: Checar tipos e build**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/LinkStressTest.tsx
git commit -m "refactor(web): LinkStressTest.tsx usa Panel"
```

---

### Task 6: Verificação final

**Files:**
- Nenhum arquivo de produto — só verificação.

**Interfaces:**
- Consumes: build completo do frontend (Tasks 1-5).

- [ ] **Step 1: Build limpo de ponta a ponta**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript, sem warnings novos além do já existente aviso de
chunk size (pré-existente, não relacionado a este trabalho).

- [ ] **Step 2: Verificação visual**

Sem Playwright disponível neste ambiente (limitação já conhecida — ver histórico deste projeto). A
verificação visual final é: (a) tirar um screenshot manual se houver navegador disponível na sessão
de quem está executando esta tarefa, ou (b) descrever explicitamente no relatório que a verificação
ficou pendente de confirmação do usuário após deploy — não inventar uma confirmação visual que não
aconteceu. Se houver acesso a um navegador: abrir a tela de Links contra uma instância do LinkGuard
rodando com dado real (nunca semear link fake só pra preencher a tela — se não houver link
configurado, a tela vazia com o texto "Nenhum link configurado" também é uma verificação válida),
conferir:
- Tabela de links aparece dentro de um card com título "Links WAN" no topo.
- Banner de sucesso (ex.: depois de excluir um link) aparece com o mesmo visual do card de erro do
  formulário de editar interface (borda/fundo verde, sem chip arredondado solto).
- Painel de balanceamento (se houver 2+ links) e painel de stress-test aparecem como cards com título
  e ícone alinhados, mesmo estilo da tabela.
- Os 3 modais (criar/editar, assistente 2-WAN, confirmar exclusão) abrem com a largura certa (editar
  mais estreito, assistente mais largo, exclusão o mais estreito) e o assistente mantém a borda azul e
  o gradiente de fundo.

- [ ] **Step 3: Corrigir o que for encontrado, confirmar `git status` limpo**

Mesmo processo já estabelecido nas fases anteriores deste projeto.

- [ ] **Step 4: Commit (só se a verificação exigiu correções)**

---

## Auto-revisão do plano

**Cobertura do spec** (`docs/superpowers/specs/2026-07-28-links-reskin-design.md`): componente `Modal`
(Task 1) · tabela+banner de `Links.tsx` (Task 2) · os 3 modais de `Links.tsx` (Task 3) ·
`WanBalancing.tsx` (Task 4) · `LinkStressTest.tsx` (Task 5) · verificação visual (Task 6). `Tag`/
`StatusBadge` não precisam de tarefa — já estão no padrão, como o spec já observou.

**Desvio documentado do spec, sinalizado explicitamente no passo que o introduz**: o overlay do modal
do assistente 2-WAN (hoje `bg-black/70 backdrop-blur-sm`, mais escuro/desfocado que os outros dois)
fica padronizado pro `bg-black/60` fixo do `Modal` — simplificação visual pequena, não mencionada
explicitamente no spec (que só falava da borda/gradiente do card interno via `className`), mas
coerente com o espírito de "reskin com casca compartilhada" já aprovado. Não é mudança de
comportamento (é só o tom do fundo escurecido atrás do modal).

**Placeholders:** nenhum "TBD" — todo passo tem o código completo (antes/depois) a aplicar.

**Consistência de tipos:** `ModalProps` (Task 1) é usado com as mesmas props (`open`, `onClose`,
`title`, `size`, `className`) em todos os 3 usos na Task 3 — os valores de `size` (`"md"`, `"lg"`,
`"sm"`) batem com as três chaves definidas em `sizeClass` na Task 1. `Panel`'s `title`/`className`
(usado nas Tasks 2, 4, 5) já existem na implementação atual de `web/src/components/ui/Panel.tsx`, sem
necessidade de alteração nesse arquivo.

**Achado corrigido nesta auto-revisão:** a primeira versão deste plano copiava o padrão do `Panel`
(que só aplica `text-white font-semibold` quando `title` é uma string simples) pro `Modal` novo, mas
os títulos com ícone+HelpTip (Task 3 assistente, Task 4, Task 5) são todos `ReactNode`, não string —
sem correção, o texto do título perderia o destaque branco/negrito que tinha no `<h2>` original nos
3 lugares. Corrigido aplicando `text-white font-semibold` direto no `<span>` que envolve só o texto
do título, deixando ícone e `HelpTip` de fora dessas classes (igual ao `<h2>` original, que também só
envolvia o texto).
