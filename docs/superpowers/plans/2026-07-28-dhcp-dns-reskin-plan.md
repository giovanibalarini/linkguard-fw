# Reskin DHCP + DNS — Plano de Implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Trocar a casca visual de `Dhcp.tsx`, `Dns.tsx` e `DnsQueryLog.tsx` pros componentes
`Panel`/`Modal` do sistema de design, sem alterar nenhum comportamento.

**Architecture:** Mesmo padrão da rodada 1 (Links WAN) — `Panel` envolve os cards, `Modal`
(já existente, `web/src/components/ui/Modal.tsx`) envolve o diálogo de reserva. Nenhum componente
novo.

**Tech Stack:** React + TypeScript + Vite + Tailwind.

## Global Constraints

- **Zero mudança de comportamento**: mesmas chamadas de API, mesma lógica de `run()`/`saveConfig`/
  `saveRes`/`delRes`/`addDomain`/`delDomain`/`apply`, mesmo estado. Só wrapper visual muda.
- `Panel`/`Modal` já existem (`web/src/components/ui/`) — não alterar.
- `Modal` só aplica `text-white font-semibold` automaticamente quando `title` é string simples —
  aqui todos os títulos usados são strings simples (`"Editar reserva"`/`"Nova reserva"`), então essa
  armadilha da rodada 1 não se aplica.
- Sem framework de teste no frontend — verificação por tarefa via `npm run build`.
- Toda tarefa termina com `git commit` próprio.

---

### Task 1: `Dhcp.tsx` — 3 cards viram `Panel` + banners

**Files:**
- Modify: `web/src/pages/Dhcp.tsx`

**Interfaces:**
- Consumes: `Panel` de `web/src/components/ui/Panel.tsx` (`{ title?, action?, children, className? }`).

- [ ] **Step 1: Import**

Adicionar ao topo (junto dos demais imports):
```tsx
import Panel from '../components/ui/Panel';
```

- [ ] **Step 2: Banner de última aplicação falhou**

Trocar:
```tsx
      {data?.last_apply && !data.last_apply.ok && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          Última aplicação automática falhou: {data.last_apply.error || 'erro desconhecido'}. Corrija e use "Aplicar agora".
        </div>
      )}
```
por:
```tsx
      {data?.last_apply && !data.last_apply.ok && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          Última aplicação automática falhou: {data.last_apply.error || 'erro desconhecido'}. Corrija e use "Aplicar agora".
        </div>
      )}
```

- [ ] **Step 3: Banner de mensagem (sucesso/erro de ação)**

Trocar:
```tsx
      {msg && <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>{msg}</div>}
```
por:
```tsx
      {msg && <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>}
```

(O banner de erro-de-carregamento, `{error && <div className="card border border-red-500/30 ...">`,
já está no padrão certo — não muda.)

- [ ] **Step 4: Card "Configuração" vira `Panel`**

Trocar:
```tsx
          <div className="card">
            <div className="flex items-center gap-2 mb-3"><Server className="w-4 h-4 text-blue-400" /><h3 className="text-white font-semibold">Configuração</h3></div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
```
por:
```tsx
          <Panel title={<span className="flex items-center gap-2"><Server className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Configuração</span></span>}>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
```
E o fechamento correspondente (é o primeiro `</div>` que fecha essa seção, logo depois do botão
"Salvar config" — identificar pelo comentário `{/* Reservations */}` que vem logo em seguida):
```tsx
            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">Salvar config</button></div>}
          </div>

          {/* Reservations */}
```
por:
```tsx
            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">Salvar config</button></div>}
          </Panel>

          {/* Reservations */}
```

- [ ] **Step 5: Card "Reservas" vira `Panel`**

Trocar:
```tsx
          <div className="card">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3">
              <div className="flex items-center gap-2"><ListChecks className="w-4 h-4 text-blue-400" /><h3 className="text-white font-semibold">Reservas (IP fixo por MAC)</h3></div>
              {canWrite && <button onClick={() => setResModal({ ...emptyRes, editing: false })} className="btn-primary flex items-center gap-2 w-full sm:w-auto justify-center"><Plus className="w-4 h-4" /> Nova reserva</button>}
            </div>
```
por:
```tsx
          <Panel
            title={<span className="flex items-center gap-2"><ListChecks className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Reservas (IP fixo por MAC)</span></span>}
            action={canWrite ? <button onClick={() => setResModal({ ...emptyRes, editing: false })} className="btn-primary flex items-center gap-2 justify-center"><Plus className="w-4 h-4" /> Nova reserva</button> : undefined}
          >
```
(`Panel` já tem um slot `action` pensado exatamente pra isso — botão no canto do cabeçalho, ver
`web/src/components/ui/Panel.tsx:5,13-22`. O `w-full sm:w-auto` do botão original existia porque ele
dividia o `flex flex-col sm:flex-row` do cabeçalho manual; dentro do slot `action` do `Panel` (que já
resolve o layout responsivo do cabeçalho) isso não é mais necessário — por isso a classe cai fora.)

E o fechamento correspondente (depois da tabela de reservas, antes do comentário `{/* Active
leases */}`):
```tsx
              </table></div>
            )}
          </div>

          {/* Active leases */}
```
por:
```tsx
              </table></div>
            )}
          </Panel>

          {/* Active leases */}
```

- [ ] **Step 6: Card "Leases ativos" vira `Panel`**

Trocar:
```tsx
          <div className="card">
            <div className="flex items-center gap-2 mb-3"><Network className="w-4 h-4 text-green-400" /><h3 className="text-white font-semibold">Leases ativos ({data?.leases.length ?? 0})</h3></div>
```
por:
```tsx
          <Panel title={<span className="flex items-center gap-2"><Network className="w-4 h-4 text-green-400" /><span className="text-white font-semibold">Leases ativos ({data?.leases.length ?? 0})</span></span>}>
```
E o fechamento correspondente (depois da tabela de leases, antes de `</>` que fecha o fragmento):
```tsx
              </table></div>
            )}
          </div>
        </>
      )}
```
por:
```tsx
              </table></div>
            )}
          </Panel>
        </>
      )}
```

- [ ] **Step 7: Modal de reserva vira `Modal`**

Adicionar ao import (junto do `Panel` do Step 1):
```tsx
import Modal from '../components/ui/Modal';
```

Trocar:
```tsx
      {/* Reservation modal */}
      {resModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-gray-800"><h2 className="text-white font-semibold">{resModal.editing ? 'Editar reserva' : 'Nova reserva'}</h2></div>
            <div className="p-6 space-y-4">
```
por:
```tsx
      {/* Reservation modal */}
      <Modal
        open={resModal !== null}
        onClose={() => setResModal(null)}
        title={resModal ? (resModal.editing ? 'Editar reserva' : 'Nova reserva') : ''}
        size="sm"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {resModal && (
        <div className="p-6 space-y-4">
```

**Atenção — mesma armadilha da rodada 1 (Task 3, modal de excluir em `Links.tsx`)**: o corpo do modal
lê `resModal.mac`/`resModal.editing`/etc., e `resModal` pode ser `null`. `Modal`'s `children` são
avaliados pelo componente que chama (`Dhcp`), não pelo `Modal` — um guard em volta do conteúdo que lê
`resModal.*` é obrigatório, não opcional. O `{resModal && (...)}` acima já cobre isso.

E o fechamento correspondente:
```tsx
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
              </div>
        </div>
        )}
      </Modal>
    </div>
  );
}
```

- [ ] **Step 8: Build**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript. Atenção especial a tags desalinhadas — mesmo risco
já visto na rodada 1.

- [ ] **Step 9: Commit**

```bash
git add web/src/pages/Dhcp.tsx
git commit -m "refactor(web): Dhcp.tsx usa Panel/Modal"
```

---

### Task 2: `Dns.tsx` — 2 cards viram `Panel` + banners

**Files:**
- Modify: `web/src/pages/Dns.tsx`

**Interfaces:**
- Consumes: `Panel` de `web/src/components/ui/Panel.tsx`.

- [ ] **Step 1: Import**

```tsx
import Panel from '../components/ui/Panel';
```

- [ ] **Step 2: Banner de última aplicação falhou**

Trocar:
```tsx
      {data?.last_apply && !data.last_apply.ok && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          Última aplicação automática falhou: {data.last_apply.error || 'erro desconhecido'}. Corrija e use "Aplicar agora".
        </div>
      )}
```
por:
```tsx
      {data?.last_apply && !data.last_apply.ok && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          Última aplicação automática falhou: {data.last_apply.error || 'erro desconhecido'}. Corrija e use "Aplicar agora".
        </div>
      )}
```

- [ ] **Step 3: Banner de mensagem**

Trocar:
```tsx
      {msg && <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>{msg}</div>}
```
por:
```tsx
      {msg && <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>}
```

- [ ] **Step 4: Card "Resolução" vira `Panel`**

Trocar:
```tsx
          <div className="card">
            <div className="flex items-center gap-2 mb-3"><Globe className="w-4 h-4 text-blue-400" /><h3 className="text-white font-semibold">Resolução</h3></div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
```
por:
```tsx
          <Panel title={<span className="flex items-center gap-2"><Globe className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Resolução</span></span>}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
```
E o fechamento correspondente (depois do botão "Salvar config", antes do próximo `<div className="card">`):
```tsx
            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">Salvar config</button></div>}
          </div>

          <div className="card">
            <div className="flex items-center gap-2 mb-1"><Ban className="w-4 h-4 text-red-400" /><h3 className="text-white font-semibold">Filtro / blocklist</h3></div>
```
por (já resolve o Step 5 abaixo no mesmo replace, já que os dois blocos estão colados um no outro):
```tsx
            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">Salvar config</button></div>}
          </Panel>

          <Panel title={<span className="flex items-center gap-2"><Ban className="w-4 h-4 text-red-400" /><span className="text-white font-semibold">Filtro / blocklist</span></span>}>
```

- [ ] **Step 5: Fechamento do card "Filtro / blocklist"**

Trocar (logo antes do componente `<DnsQueryLog`):
```tsx
            </div>
          </div>

          <DnsQueryLog
```
por:
```tsx
            </div>
          </Panel>

          <DnsQueryLog
```

- [ ] **Step 6: Build**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript.

- [ ] **Step 7: Commit**

```bash
git add web/src/pages/Dns.tsx
git commit -m "refactor(web): Dns.tsx usa Panel"
```

---

### Task 3: `DnsQueryLog.tsx` vira `Panel`

**Files:**
- Modify: `web/src/components/DnsQueryLog.tsx`

**Interfaces:**
- Consumes: `Panel` de `web/src/components/ui/Panel.tsx`.

- [ ] **Step 1: Ler o cabeçalho atual do componente**

Antes de editar, ler `web/src/components/DnsQueryLog.tsx` linhas 1-45 pra confirmar o texto exato do
título/ícone/subtítulo (este plano não tem o conteúdo exato porque o arquivo não foi lido linha a
linha antes de escrever o plano — diferente das Tasks 1-2, que vieram de leitura direta do arquivo).
O padrão a aplicar é o mesmo das Tasks 1-2 e da rodada 1: `<div className="card">` → `<Panel
title={<span className="flex items-center gap-2">{ícone}<span className="text-white
font-semibold">{texto do título}</span></span>}>`, com `text-white font-semibold` só no `<span>` do
texto (não no ícone), fechamento `</div>` final → `</Panel>`.

- [ ] **Step 2: Adicionar o import**

```tsx
import Panel from './ui/Panel';
```

- [ ] **Step 3: Aplicar a troca conforme identificado no Step 1**

- [ ] **Step 4: Build**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/DnsQueryLog.tsx
git commit -m "refactor(web): DnsQueryLog.tsx usa Panel"
```

---

### Task 4: Verificação final

**Files:**
- Nenhum arquivo de produto — só verificação.

- [ ] **Step 1: Build limpo de ponta a ponta**

Run: `cd web && npm run build`
Expected: build limpo, sem erros de TypeScript, sem warnings novos além do já existente aviso de
chunk size.

- [ ] **Step 2: Verificação visual**

Mesma limitação já registrada nas rodadas anteriores (sem Playwright neste ambiente) — confirmar
`git status` limpo e descrever no relatório que a confirmação visual fica pendente do usuário após
deploy.

- [ ] **Step 3: Commit (só se a verificação exigiu correções)**

---

## Auto-revisão do plano

**Cobertura do spec**: `Dhcp.tsx` (Task 1) · `Dns.tsx` (Task 2) · `DnsQueryLog.tsx` (Task 3) ·
verificação (Task 4). Mapeamento de banners do spec §3 aplicado nas Tasks 1-2.

**Placeholders**: Task 3 é a única com um passo não-mecânico ("ler o arquivo antes de editar") —
não é um placeholder de conteúdo, é uma instrução real porque este plano foi escrito sem ler
`DnsQueryLog.tsx` linha a linha (diferente das Tasks 1-2). Sinalizado explicitamente pro
implementador, com o padrão exato a seguir já descrito.

**Consistência de tipos**: `Modal`/`Panel` usados com a mesma assinatura de props já estabelecida e
testada na rodada 1 (`web/src/components/ui/Modal.tsx`, `web/src/components/ui/Panel.tsx`) — nenhuma
mudança nesses dois arquivos é necessária ou permitida neste plano.

**Risco levado da rodada 1**: título como `ReactNode` (ícone + texto) precisa de `text-white
font-semibold` explícito só no `<span>` do texto — replicado em todas as Tasks 1-3 deste plano.
