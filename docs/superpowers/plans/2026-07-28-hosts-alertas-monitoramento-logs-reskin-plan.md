# Reskin Hosts + Monitoramento + Logs — Plano de Implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Trocar a casca visual de `Hosts.tsx`, `Monitoring.tsx` e `Logs.tsx` pros componentes
`Panel`/`Modal`, sem alterar nenhum comportamento. `Alerts.tsx` fica fora de escopo (ver spec §2 —
já está no padrão certo, nada pra converter).

**Architecture:** Mesmo padrão das rodadas 1-3. Task 1 estende `Modal` com um novo tamanho `'xs'`
antes de `Hosts.tsx` (Task 2) precisar dele.

**Tech Stack:** React + TypeScript + Vite + Tailwind.

## Global Constraints

- **Zero mudança de comportamento** — mesmas chamadas de API, mesmo estado, mesmos handlers.
- `Panel` já existe (`web/src/components/ui/Panel.tsx`) — não alterar.
- `Modal` (`web/src/components/ui/Modal.tsx`) — a única mudança permitida nele nesta rodada é a
  Task 1 (novo valor de `size`), aditiva e retrocompatível.
- Título como `ReactNode` (ícone + texto) precisa de `text-white font-semibold` explícito só no
  `<span>` do texto — mesma armadilha das rodadas 1-3.
- Cards de item de lista (um alerta, um host por-link no grid de Monitoramento) **não** viram
  `Panel` — só seções com título de página viram. Loading skeletons também ficam como estão.
- Sem framework de teste no frontend — verificação por tarefa via `npm run build`.
- Toda tarefa termina com `git commit` próprio.

---

### Task 1: Adicionar `size: 'xs'` ao `Modal`

**Files:**
- Modify: `web/src/components/ui/Modal.tsx`

**Interfaces:**
- Produces: `ModalProps['size']` ganha `'xs'` no union (`'xs' | 'sm' | 'md' | 'lg'`), mapeando pra
  `max-w-sm`. `'sm'`/`'md'`/`'lg'` continuam mapeando exatamente pro que já mapeavam.

- [ ] **Step 1: Editar `sizeClass` e o tipo**

Trocar:
```tsx
interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  action?: ReactNode;
  closeOnBackdropClick?: boolean;
}

const sizeClass: Record<NonNullable<ModalProps['size']>, string> = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
};
```
por:
```tsx
interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  size?: 'xs' | 'sm' | 'md' | 'lg';
  className?: string;
  action?: ReactNode;
  closeOnBackdropClick?: boolean;
}

const sizeClass: Record<NonNullable<ModalProps['size']>, string> = {
  xs: 'max-w-sm',
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
};
```

O resto do componente (`export default function Modal(...)`) não muda — `size = 'md'` continua o
default, e `sizeClass[size]` já resolve `'xs'` automaticamente pela extensão do `Record`.

- [ ] **Step 2: Build**

Run: `cd web && npm run build`
Expected: build limpo. Nenhum consumidor existente (Links ×3, Dhcp ×1, Firewall ×1, Vpn/
PeerConfigModal ×1 — todas as 6 chamadas de `Modal` já em produção ou já mergeadas) passa
`size="xs"`, então nada muda pra eles.

- [ ] **Step 3: Commit**

```bash
git add web/components/ui/Modal.tsx
git commit -m "feat(web): Modal ganha size=xs (aditivo, retrocompatível)"
```

(Corrigir o path do `git add` se necessário — é `web/src/components/ui/Modal.tsx`.)

---

### Task 2: `Hosts.tsx` — 2 cards viram `Panel`, 2 modais viram `Modal`

**Files:**
- Modify: `web/src/pages/Hosts.tsx`

**Interfaces:**
- Consumes: `Panel`, `Modal` (Task 1 — usa `size="xs"` nos dois modais).

- [ ] **Step 1: Import**

```tsx
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
```

- [ ] **Step 2: Card "Top consumidores" vira `Panel`**

Trocar:
```tsx
      {talkers.length > 0 && (
        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            <h3 className="text-white font-semibold">Top consumidores</h3>
            <span className="text-xs text-gray-600">— quem está usando a banda agora (fluxos ativos)</span>
          </div>
```
por:
```tsx
      {talkers.length > 0 && (
        <Panel title={<span className="flex items-center gap-2"><TrendingUp className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Top consumidores</span><span className="text-xs text-gray-600 font-normal">— quem está usando a banda agora (fluxos ativos)</span></span>}>
```

(O `<span className="text-xs text-gray-600">` de complemento do título ganha `font-normal` — no
original ele já não herdava `font-semibold` porque só o `<h3>` tinha essa classe, e agora que todo o
bloco do título é o `ReactNode` passado pro `Panel`, sem esse `font-normal` explícito ele herdaria o
peso de fonte do CSS padrão do body, que já é normal — mas declarar explicitamente evita depender de
um default implícito, mesmo padrão de cuidado já usado nas rodadas anteriores com o `text-white
font-semibold`.)

E o fechamento (a última linha antes do comentário `{/* Mobile: stacked cards */}`... na verdade
antes do próximo card, sem comentário explícito):
```tsx
            })}
          </div>
        </div>
      )}

      <div className="card">
```
por:
```tsx
            })}
          </div>
        </Panel>
      )}

      <div className="card">
```

- [ ] **Step 3: Card da lista de hosts vira `Panel` sem título**

Trocar:
```tsx
      <div className="card">
        {loading && hosts.length === 0 ? (
```
por:
```tsx
      <Panel>
        {loading && hosts.length === 0 ? (
```

E o fechamento (antes de `{aliasFor && (`):
```tsx
          </>
        )}
      </div>

      {aliasFor && (
```
por:
```tsx
          </>
        )}
      </Panel>

      {aliasFor && (
```

- [ ] **Step 4: Modal de apelido vira `Modal`**

Trocar:
```tsx
      {aliasFor && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-sm">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">Apelido do host</h2>
              <p className="text-gray-500 text-xs mt-1 font-mono">{aliasFor.mac}</p>
            </div>
            <div className="p-6 space-y-4">
```
por:
```tsx
      <Modal
        open={aliasFor !== null}
        onClose={() => setAliasFor(null)}
        title={<div><span className="text-white font-semibold">Apelido do host</span>{aliasFor && <p className="text-gray-500 text-xs mt-1 font-mono font-normal">{aliasFor.mac}</p>}</div>}
        size="xs"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {aliasFor && (
        <div className="p-6 space-y-4">
```

Nota: o título original tem duas linhas (nome + MAC em mono abaixo) — por isso vira um `ReactNode`
(`<div>` com duas linhas), não uma string simples, e por isso precisa do `text-white font-semibold`
explícito (só no texto "Apelido do host", não no MAC) e do guard `{aliasFor && ...}` dentro do
`title` também, pelo mesmo motivo do guard no corpo: `aliasFor` pode ser `null`, e o `title` é
avaliado pelo `Hosts` (quem chama `Modal`) independente do `open` do `Modal`.

E o fechamento:
```tsx
              <div className="flex gap-3">
                <button onClick={saveAlias} disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? 'Salvando...' : 'Salvar'}
                </button>
                <button onClick={() => setAliasFor(null)} className="btn-secondary flex-1">Cancelar</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {confirmFor && (
```
por:
```tsx
              <div className="flex gap-3">
                <button onClick={saveAlias} disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? 'Salvando...' : 'Salvar'}
                </button>
                <button onClick={() => setAliasFor(null)} className="btn-secondary flex-1">Cancelar</button>
              </div>
        </div>
        )}
      </Modal>

      {confirmFor && (
```

- [ ] **Step 5: Modal de confirmar bloqueio vira `Modal`**

Trocar:
```tsx
      {confirmFor && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-sm">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">
                {confirmFor.blocked ? 'Desbloquear host' : 'Bloquear host'}
              </h2>
              <p className="text-gray-500 text-xs mt-1 font-mono">{confirmFor.mac}</p>
            </div>
            <div className="p-6 space-y-4">
```
por:
```tsx
      <Modal
        open={confirmFor !== null}
        onClose={() => setConfirmFor(null)}
        title={<div><span className="text-white font-semibold">{confirmFor ? (confirmFor.blocked ? 'Desbloquear host' : 'Bloquear host') : ''}</span>{confirmFor && <p className="text-gray-500 text-xs mt-1 font-mono font-normal">{confirmFor.mac}</p>}</div>}
        size="xs"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {confirmFor && (
        <div className="p-6 space-y-4">
```

E o fechamento (o final do arquivo, depois dos botões Bloquear/Cancelar):
```tsx
                <button onClick={() => setConfirmFor(null)} disabled={confirming} className="btn-secondary flex-1 disabled:opacity-50">
                  Cancelar
                </button>
              </div>
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
                <button onClick={() => setConfirmFor(null)} disabled={confirming} className="btn-secondary flex-1 disabled:opacity-50">
                  Cancelar
                </button>
              </div>
        </div>
        )}
      </Modal>
    </div>
  );
}
```

- [ ] **Step 6: Build**

Run: `cd web && npm run build`
Expected: build limpo. Esta tarefa tem 2 modais com guard duplo (no `title` e no corpo) — preste
atenção especial a tags desalinhadas.

- [ ] **Step 7: Commit**

```bash
git add web/src/pages/Hosts.tsx
git commit -m "refactor(web): Hosts.tsx usa Panel/Modal"
```

---

### Task 3: `Monitoring.tsx` — 4 cards viram `Panel`

**Files:**
- Modify: `web/src/pages/Monitoring.tsx`

**Interfaces:**
- Consumes: `Panel`.

- [ ] **Step 1: Import**

```tsx
import Panel from '../components/ui/Panel';
```

- [ ] **Step 2: Card "Latência por Link" vira `Panel`**

Trocar:
```tsx
      {links.length > 0 && (
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-blue-400" />
            <h2 className="text-white font-semibold">Latência por Link (ms)</h2>
          </div>
```
por:
```tsx
      {links.length > 0 && (
        <Panel title={<span className="flex items-center gap-2"><Activity className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Latência por Link (ms)</span></span>}>
```

E o fechamento:
```tsx
          )}
        </div>
      )}

      {/* CPU / Memory chart */}
```
por:
```tsx
          )}
        </Panel>
      )}

      {/* CPU / Memory chart */}
```

- [ ] **Step 3: Card "CPU e Memória" vira `Panel`**

Trocar:
```tsx
      <div className="card">
        <div className="flex items-center gap-2 mb-4">
          <Activity className="w-4 h-4 text-purple-400" />
          <h2 className="text-white font-semibold">CPU e Memória (%)</h2>
        </div>
```
por:
```tsx
      <Panel title={<span className="flex items-center gap-2"><Activity className="w-4 h-4 text-purple-400" /><span className="text-white font-semibold">CPU e Memória (%)</span></span>}>
```

E o fechamento:
```tsx
        )}
      </div>

      {/* Correlated diagnostic timeline */}
```
por:
```tsx
        )}
      </Panel>

      {/* Correlated diagnostic timeline */}
```

- [ ] **Step 4: Card "Linha do tempo" vira `Panel` com `action`**

Trocar:
```tsx
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <h2 className="text-white font-semibold">Linha do tempo</h2>
          </div>
          <div className="flex gap-2">
            {[1, 6, 24].map(h => (
              <button
                key={h}
                onClick={() => setPeriodHours(h)}
                className={`px-3 py-1 rounded text-xs ${periodHours === h ? 'bg-blue-600 text-white' : 'btn-secondary'}`}
              >
                {h === 1 ? '1h' : h === 6 ? '6h' : '24h'}
              </button>
            ))}
          </div>
        </div>
```
por:
```tsx
      <Panel
        title={<span className="flex items-center gap-2"><Activity className="w-4 h-4 text-emerald-400" /><span className="text-white font-semibold">Linha do tempo</span></span>}
        action={
          <div className="flex gap-2">
            {[1, 6, 24].map(h => (
              <button
                key={h}
                onClick={() => setPeriodHours(h)}
                className={`px-3 py-1 rounded text-xs ${periodHours === h ? 'bg-blue-600 text-white' : 'btn-secondary'}`}
              >
                {h === 1 ? '1h' : h === 6 ? '6h' : '24h'}
              </button>
            ))}
          </div>
        }
      >
```

E o fechamento:
```tsx
          </div>
        )}
      </div>

      {/* Interface traffic */}
```
por:
```tsx
          </div>
        )}
      </Panel>

      {/* Interface traffic */}
```

- [ ] **Step 5: Card "Tráfego por Interface" vira `Panel`**

Trocar:
```tsx
        <div className="card">
          <h2 className="text-white font-semibold mb-4">Tráfego por Interface</h2>
```
por:
```tsx
        <Panel title="Tráfego por Interface">
```

(Título string simples — `Panel` aplica `text-white font-semibold` sozinho, igual fazia o `<h2>`
original. O `mb-4` do `<h2>` original não precisa ser reproduzido, `Panel` já aplica `mb-4` no
wrapper do cabeçalho quando há `title`.)

E o fechamento (a última linha antes de `)}` que fecha o `{sys && sys.interfaces...}`):
```tsx
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
        </Panel>
      )}
    </div>
  );
}
```

- [ ] **Step 6: Build**

Run: `cd web && npm run build`
Expected: build limpo.

- [ ] **Step 7: Commit**

```bash
git add web/src/pages/Monitoring.tsx
git commit -m "refactor(web): Monitoring.tsx usa Panel"
```

---

### Task 4: `Logs.tsx` vira `Panel` sem título

**Files:**
- Modify: `web/src/pages/Logs.tsx`

**Interfaces:**
- Consumes: `Panel`.

- [ ] **Step 1: Import**

```tsx
import Panel from '../components/ui/Panel';
```

- [ ] **Step 2: Card da tabela vira `Panel`**

Trocar:
```tsx
      <div className="card">
        {loading && logs.length === 0 ? (
```
por:
```tsx
      <Panel>
        {loading && logs.length === 0 ? (
```

E o fechamento (a última linha antes de `)}\n    </div>\n  );\n}`):
```tsx
          </div>
        )}
      </div>
    </div>
  );
}
```
por:
```tsx
          </div>
        )}
      </Panel>
    </div>
  );
}
```

- [ ] **Step 3: Build**

Run: `cd web && npm run build`
Expected: build limpo.

- [ ] **Step 4: Commit**

```bash
git add web/src/pages/Logs.tsx
git commit -m "refactor(web): Logs.tsx usa Panel"
```

---

### Task 5: Verificação final

**Files:**
- Nenhum arquivo de produto — só verificação.

- [ ] **Step 1: Build limpo de ponta a ponta**

Run: `cd web && npm run build`
Expected: build limpo, sem warnings novos além do já existente aviso de chunk size.

- [ ] **Step 2: Confirmar que `Alerts.tsx` não foi tocado**

Run: `git diff main --stat -- web/src/pages/Alerts.tsx` (deve estar vazio — nenhuma mudança).

- [ ] **Step 3: Verificação visual**

Sem Playwright disponível — confirmar `git status` limpo e descrever no relatório que a confirmação
visual (principalmente os 2 modais `size="xs"` do `Hosts.tsx`, com título de duas linhas) fica
pendente do usuário após deploy.

- [ ] **Step 4: Commit (só se a verificação exigiu correções)**

---

## Auto-revisão do plano

**Cobertura do spec**: `size="xs"` no `Modal` (Task 1) · `Hosts.tsx` (Task 2) · `Monitoring.tsx`
(Task 3) · `Logs.tsx` (Task 4) · verificação (Task 5). `Alerts.tsx` explicitamente fora de escopo
(spec §2), confirmado por um passo dedicado na Task 5.

**Placeholders**: nenhum — todo passo tem código completo antes/depois.

**Consistência de tipos**: `ModalProps['size']` ganha `'xs'` na Task 1; a Task 2 é a única que usa
`size="xs"` neste plano — nenhuma tarefa usa um valor de `size` que a Task 1 não tenha definido.

**Risco levado das rodadas 1-3**: título como `ReactNode` precisa de `text-white font-semibold`
explícito só no `<span>`/elemento de texto — replicado em todos os títulos com ícone deste plano
(Hosts "Top consumidores", os 2 modais de Hosts com título de duas linhas, Monitoring ×3 com ícone).
Guard de null em volta de conteúdo (e agora também dentro do `title`) que lê um valor que pode ser
`null` — replicado nos 2 modais de `Hosts.tsx`, seguindo o mesmo motivo já estabelecido na rodada 2
(DHCP) e rodada 3 (Firewall): `Modal`'s `children`/`title` são avaliados pelo componente que chama,
não pelo `Modal`.
