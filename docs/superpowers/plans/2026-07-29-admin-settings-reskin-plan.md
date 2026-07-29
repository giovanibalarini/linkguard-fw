# Reskin Admin + Settings (rodada 5/5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Converter `web/src/pages/Admin.tsx`, `web/src/pages/Settings.tsx` e os 7 sub-componentes que
`Settings.tsx` importa pros componentes `Panel`/`Modal` do sistema de design, sem nenhuma mudança de
comportamento — última rodada (5/5) do sub-projeto 4 de reskin.

**Architecture:** Reskin puro por substituição estrutural: `<div className="card ...">` com `<h2>`/
`<h3>` de título vira `<Panel title="...">`; `<div className="fixed inset-0 bg-black/60 ...">` vira
`<Modal open={...} onClose={...} title="..." size="...">`. `Panel.tsx` e `Modal.tsx` não são
modificados — todas as larguras e formatos já existem. Nenhuma extração de handler/estado, nenhum
componente novo além do que já existe.

**Tech Stack:** React 18 + TypeScript + Vite + Tailwind. Sem framework de teste no frontend.

## Global Constraints

- Zero mudança de comportamento — nenhuma lógica de estado, handler, chamada de API ou validação é
  alterada. Só a casca visual.
- `Panel`/`Modal` **não são modificados** nesta rodada (já suportam todas as larguras e formatos
  necessários: `xs`/`sm`/`md`/`lg`).
- Banners de erro/sucesso **aninhados dentro** de um `Panel` ou `Modal` (seus `children`) **não são
  convertidos** para o padrão `card border` — ficam exatamente como estão hoje
  (`px-4 py-3 rounded-lg ...` ou `px-3 py-2 rounded-lg ...`). Só banners de **nível de página**
  (irmãos diretos de `Panel`/modal, fora de qualquer cartão) viram `card border
  border-{cor}-500/30 bg-{cor}-500/10 text-{cor}-400 text-sm`.
- Cartões de item de lista (ex.: os cards por-papel dentro do `.map()` em `RolesTab`) **não** viram
  `Panel` — só cartões de seção com cabeçalho próprio (ou sem título, mas representando uma seção
  inteira) viram `Panel`.
- Título de `Modal`/`Panel` que lê estado anulável (`deleteTarget?.username`, etc.) precisa de
  optional chaining no `children` — `Modal`/`Panel` só deixam de renderizar o próprio conteúdo
  quando fechados; o `children`/`title` continua sendo avaliado pelo React como argumento JSX
  normal do componente pai, independente do `if (!open) return null` interno do `Modal`.
- Verificação por tarefa: `npm run build` (type-check + build de produção). O PATH do sandbox não
  inclui Node por padrão — prefixar com:
  `export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH"`.
- Sem framework de teste no frontend — não criar testes automatizados novos.

---

### Task 1: `Admin.tsx` — aba Usuários (`UsersTab`)

**Files:**
- Modify: `web/src/pages/Admin.tsx:1-5` (imports), `:180-244` (banner + tabela → `Panel`),
  `:246-306` (modal criar/editar → `Modal`), `:308-335` (modal excluir → `Modal`)

**Interfaces:**
- Consumes: `Panel` (`web/src/components/ui/Panel.tsx`, props `title?`, `action?`, `children`,
  `className?`) e `Modal` (`web/src/components/ui/Modal.tsx`, props `open`, `onClose`, `title`,
  `children`, `size?: 'xs'|'sm'|'md'|'lg'`, `className?`, `action?`, `closeOnBackdropClick?`) — já
  existem, não são alterados.
- Produces: os imports de `Panel`/`Modal` adicionados a `Admin.tsx` neste task são reaproveitados
  pelo Task 2 (mesma aba de imports, mesmo arquivo) — Task 2 assume que já existem.

- [ ] **Step 1: Adicionar imports de `Panel` e `Modal`**

Em `web/src/pages/Admin.tsx`, linhas 1-5, troque:

```tsx
import { useEffect, useMemo, useState } from 'react';
import { Plus, Pencil, Trash2, RefreshCw, Users, ShieldCheck, Lock } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { AppUser, AppRole, PermissionCatalogEntry } from '../types';
```

por:

```tsx
import { useEffect, useMemo, useState } from 'react';
import { Plus, Pencil, Trash2, RefreshCw, Users, ShieldCheck, Lock } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
import type { AppUser, AppRole, PermissionCatalogEntry } from '../types';
```

- [ ] **Step 2: Banner `fetchError` e tabela → `Panel`**

Na função `UsersTab`, troque o trecho (linhas ~180-182):

```tsx
      {fetchError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{fetchError}</div>}

      <div className="card">
```

por:

```tsx
      {fetchError && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{fetchError}</div>}

      <Panel>
```

E o fechamento correspondente (linhas ~242-244), troque:

```tsx
          </div>
        )}
      </div>

      {showModal && (
```

por:

```tsx
          </div>
        )}
      </Panel>

      {showModal && (
```

(O conteúdo entre a abertura e o fechamento — o `loading`/`fetchError`/`users.length === 0`/tabela —
fica exatamente como está, não precisa tocar.)

- [ ] **Step 3: Modal criar/editar usuário → `Modal size="md"`**

Troque todo o bloco (linhas ~246-306):

```tsx
      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-lg max-h-[90vh] flex flex-col">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">{isEditing ? 'Editar Usuário' : 'Novo Usuário'}</h2>
            </div>
            <form onSubmit={handleSave} className="p-6 space-y-4 overflow-y-auto">
              <div>
                <label className="label">Nome de usuário *</label>
                <input
                  className="input w-full disabled:opacity-50"
                  value={form.username}
                  disabled={isEditing}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  required
                />
              </div>
              <div>
                <label className="label">{isEditing ? 'Nova senha (deixe vazio para manter)' : 'Senha *'}</label>
                <input
                  type="password"
                  className="input w-full"
                  value={form.password}
                  placeholder={isEditing ? '••••••••' : 'mínimo 8 caracteres'}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  required={!isEditing}
                  minLength={!isEditing || form.password ? 8 : undefined}
                />
              </div>
              <div>
                <label className="label">Papéis</label>
                <div className="space-y-2 mt-1 max-h-48 overflow-y-auto">
                  {roles.map((r) => (
                    <label key={r.id} className="flex items-start gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        className="w-4 h-4 mt-0.5"
                        checked={form.role_ids.includes(r.id)}
                        onChange={() => toggleRole(r.id)}
                      />
                      <span>
                        <span className="text-gray-200 text-sm">{r.name}</span>
                        {r.description && <span className="text-gray-600 text-xs block">{r.description}</span>}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
              {error && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{error}</div>}
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? 'Salvando...' : 'Salvar'}
                </button>
                <button type="button" onClick={() => setShowModal(false)} className="btn-secondary flex-1">
                  Cancelar
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
```

por:

```tsx
      <Modal open={showModal} onClose={() => setShowModal(false)} title={isEditing ? 'Editar Usuário' : 'Novo Usuário'} size="md">
        <form onSubmit={handleSave} className="p-6 space-y-4">
          <div>
            <label className="label">Nome de usuário *</label>
            <input
              className="input w-full disabled:opacity-50"
              value={form.username}
              disabled={isEditing}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              required
            />
          </div>
          <div>
            <label className="label">{isEditing ? 'Nova senha (deixe vazio para manter)' : 'Senha *'}</label>
            <input
              type="password"
              className="input w-full"
              value={form.password}
              placeholder={isEditing ? '••••••••' : 'mínimo 8 caracteres'}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              required={!isEditing}
              minLength={!isEditing || form.password ? 8 : undefined}
            />
          </div>
          <div>
            <label className="label">Papéis</label>
            <div className="space-y-2 mt-1 max-h-48 overflow-y-auto">
              {roles.map((r) => (
                <label key={r.id} className="flex items-start gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    className="w-4 h-4 mt-0.5"
                    checked={form.role_ids.includes(r.id)}
                    onChange={() => toggleRole(r.id)}
                  />
                  <span>
                    <span className="text-gray-200 text-sm">{r.name}</span>
                    {r.description && <span className="text-gray-600 text-xs block">{r.description}</span>}
                  </span>
                </label>
              ))}
            </div>
          </div>
          {error && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{error}</div>}
          <div className="flex gap-3 pt-2">
            <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
              {saving ? 'Salvando...' : 'Salvar'}
            </button>
            <button type="button" onClick={() => setShowModal(false)} className="btn-secondary flex-1">
              Cancelar
            </button>
          </div>
        </form>
      </Modal>
```

Note: o `overflow-y-auto` que estava no `<form>` foi removido — o `Modal` já aplica
`max-h-[90vh] overflow-y-auto` no seu próprio wrapper, então o scroll do formulário continua
funcionando igual (mesmo padrão já usado em `Links.tsx` desde a rodada 1).

- [ ] **Step 4: Modal excluir usuário → `Modal size="sm"`**

Troque todo o bloco (linhas ~308-335):

```tsx
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">Excluir usuário</h2>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-gray-300 text-sm">
                Tem certeza que deseja excluir o usuário <span className="font-medium text-white">"{deleteTarget.username}"</span>? Esta ação não pode ser desfeita.
              </p>
              {deleteError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{deleteError}</div>}
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  disabled={deleting}
                  onClick={handleDelete}
                  className="btn-primary flex-1 bg-red-600 hover:bg-red-500 border-red-600 disabled:opacity-50"
                >
                  {deleting ? 'Excluindo...' : 'Excluir'}
                </button>
                <button type="button" onClick={() => setDeleteTarget(null)} className="btn-secondary flex-1">
                  Cancelar
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
```

por:

```tsx
      <Modal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="Excluir usuário" size="sm">
        <div className="p-6 space-y-4">
          <p className="text-gray-300 text-sm">
            Tem certeza que deseja excluir o usuário <span className="font-medium text-white">"{deleteTarget?.username}"</span>? Esta ação não pode ser desfeita.
          </p>
          {deleteError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{deleteError}</div>}
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              disabled={deleting}
              onClick={handleDelete}
              className="btn-primary flex-1 bg-red-600 hover:bg-red-500 border-red-600 disabled:opacity-50"
            >
              {deleting ? 'Excluindo...' : 'Excluir'}
            </button>
            <button type="button" onClick={() => setDeleteTarget(null)} className="btn-secondary flex-1">
              Cancelar
            </button>
          </div>
        </div>
      </Modal>
```

Note o `deleteTarget?.username` (era `deleteTarget.username`) — necessário porque o `children` do
`Modal` é avaliado pelo React mesmo quando `open={false}` (quando `deleteTarget` volta a `null`
depois de fechar), então acessar `.username` direto quebraria com `Cannot read properties of null`.
O `title="Excluir usuário"` é uma string fixa, não lê `deleteTarget`, então não precisa de guarda.

- [ ] **Step 5: Rodar build**

```bash
export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH"
cd web && npm run build
```

Esperado: build conclui sem erros de TypeScript.

- [ ] **Step 6: Commit**

```bash
git add web/src/pages/Admin.tsx
git commit -m "refactor(admin): reskin aba Usuários com Panel/Modal"
```

---

### Task 2: `Admin.tsx` — aba Papéis (`RolesTab`)

**Files:**
- Modify: `web/src/pages/Admin.tsx:474-525` (banner + grade → `Panel`), `:527-611` (modal
  criar/editar → `Modal`), `:613-640` (modal excluir → `Modal`)

**Interfaces:**
- Consumes: `Panel`/`Modal` já importados no Task 1 (mesmo arquivo).

- [ ] **Step 1: Banner `fetchError` e grade de papéis → `Panel`**

Troque (linhas ~474-476):

```tsx
      {fetchError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{fetchError}</div>}

      <div className="card">
```

por:

```tsx
      {fetchError && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{fetchError}</div>}

      <Panel>
```

E o fechamento (linhas ~523-525), troque:

```tsx
          </div>
        )}
      </div>

      {showModal && (
```

por:

```tsx
          </div>
        )}
      </Panel>

      {showModal && (
```

(O `.map()` dos cards por-papel dentro do grid, em `rounded-lg border border-gray-800
bg-gray-900/60 p-4`, fica exatamente como está — não vira `Panel`, é um cartão de item de lista.)

- [ ] **Step 2: Modal criar/editar papel → `Modal size="lg"`**

Troque todo o bloco (linhas ~527-611):

```tsx
      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">{isEditing ? 'Editar Papel' : 'Novo Papel'}</h2>
            </div>
            <form onSubmit={handleSave} className="p-6 space-y-4 overflow-y-auto">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">Nome *</label>
                  <input
                    className="input w-full"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label className="label">Descrição</label>
                  <input
                    className="input w-full"
                    value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                  />
                </div>
              </div>

              <div>
                <label className="label">Permissões por funcionalidade</label>
                <div className="space-y-4 mt-2">
                  {areas.map(({ area, entries }) => {
                    const keys = entries.map((e) => e.key);
                    const selectedCount = keys.filter((k) => form.permissions.includes(k)).length;
                    const allSelected = selectedCount === keys.length && keys.length > 0;
                    return (
                      <div key={area}>
                        <div className="flex items-center justify-between mb-2 gap-2">
                          <label className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              className="w-4 h-4"
                              checked={allSelected}
                              ref={(el) => {
                                if (el) el.indeterminate = selectedCount > 0 && !allSelected;
                              }}
                              onChange={() => toggleArea(keys, !allSelected)}
                              aria-label={`${allSelected ? 'Limpar' : 'Marcar tudo'} em ${area}`}
                              title={allSelected ? 'Limpar' : 'Marcar tudo'}
                            />
                            <span className="text-gray-400 text-xs font-semibold uppercase tracking-wide">{area}</span>
                          </label>
                          <span className="text-gray-600 text-xs whitespace-nowrap">{selectedCount}/{keys.length} selecionadas</span>
                        </div>
                        <div className="grid sm:grid-cols-2 gap-2">
                          {entries.map((e) => (
                            <label key={e.key} className="flex items-start gap-2 cursor-pointer" title={e.description}>
                              <input
                                type="checkbox"
                                className="w-4 h-4 mt-0.5"
                                checked={form.permissions.includes(e.key)}
                                onChange={() => togglePerm(e.key)}
                              />
                              <span className="text-gray-200 text-sm">{e.label}</span>
                            </label>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {error && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{error}</div>}
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? 'Salvando...' : 'Salvar'}
                </button>
                <button type="button" onClick={() => setShowModal(false)} className="btn-secondary flex-1">
                  Cancelar
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
```

por:

```tsx
      <Modal open={showModal} onClose={() => setShowModal(false)} title={isEditing ? 'Editar Papel' : 'Novo Papel'} size="lg">
        <form onSubmit={handleSave} className="p-6 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="label">Nome *</label>
              <input
                className="input w-full"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
              />
            </div>
            <div>
              <label className="label">Descrição</label>
              <input
                className="input w-full"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
            </div>
          </div>

          <div>
            <label className="label">Permissões por funcionalidade</label>
            <div className="space-y-4 mt-2">
              {areas.map(({ area, entries }) => {
                const keys = entries.map((e) => e.key);
                const selectedCount = keys.filter((k) => form.permissions.includes(k)).length;
                const allSelected = selectedCount === keys.length && keys.length > 0;
                return (
                  <div key={area}>
                    <div className="flex items-center justify-between mb-2 gap-2">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          className="w-4 h-4"
                          checked={allSelected}
                          ref={(el) => {
                            if (el) el.indeterminate = selectedCount > 0 && !allSelected;
                          }}
                          onChange={() => toggleArea(keys, !allSelected)}
                          aria-label={`${allSelected ? 'Limpar' : 'Marcar tudo'} em ${area}`}
                          title={allSelected ? 'Limpar' : 'Marcar tudo'}
                        />
                        <span className="text-gray-400 text-xs font-semibold uppercase tracking-wide">{area}</span>
                      </label>
                      <span className="text-gray-600 text-xs whitespace-nowrap">{selectedCount}/{keys.length} selecionadas</span>
                    </div>
                    <div className="grid sm:grid-cols-2 gap-2">
                      {entries.map((e) => (
                        <label key={e.key} className="flex items-start gap-2 cursor-pointer" title={e.description}>
                          <input
                            type="checkbox"
                            className="w-4 h-4 mt-0.5"
                            checked={form.permissions.includes(e.key)}
                            onChange={() => togglePerm(e.key)}
                          />
                          <span className="text-gray-200 text-sm">{e.label}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {error && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{error}</div>}
          <div className="flex gap-3 pt-2">
            <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
              {saving ? 'Salvando...' : 'Salvar'}
            </button>
            <button type="button" onClick={() => setShowModal(false)} className="btn-secondary flex-1">
              Cancelar
            </button>
          </div>
        </form>
      </Modal>
```

**Atenção:** o `ref={(el) => { if (el) el.indeterminate = selectedCount > 0 && !allSelected; }}` no
checkbox de "marcar tudo" da área precisa ser preservado exatamente — é o que dá o estado visual
"indeterminado" (nem todo, nem nenhum selecionado) ao checkbox nativo do navegador. Não mexa nessa
lógica, só mova o bloco inteiro pra dentro do `Modal`.

- [ ] **Step 3: Modal excluir papel → `Modal size="sm"`**

Troque todo o bloco (linhas ~613-640):

```tsx
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">Excluir papel</h2>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-gray-300 text-sm">
                Tem certeza que deseja excluir o papel <span className="font-medium text-white">"{deleteTarget.name}"</span>? Esta ação não pode ser desfeita.
              </p>
              {deleteError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{deleteError}</div>}
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  disabled={deleting}
                  onClick={handleDelete}
                  className="btn-primary flex-1 bg-red-600 hover:bg-red-500 border-red-600 disabled:opacity-50"
                >
                  {deleting ? 'Excluindo...' : 'Excluir'}
                </button>
                <button type="button" onClick={() => setDeleteTarget(null)} className="btn-secondary flex-1">
                  Cancelar
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
```

por:

```tsx
      <Modal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="Excluir papel" size="sm">
        <div className="p-6 space-y-4">
          <p className="text-gray-300 text-sm">
            Tem certeza que deseja excluir o papel <span className="font-medium text-white">"{deleteTarget?.name}"</span>? Esta ação não pode ser desfeita.
          </p>
          {deleteError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{deleteError}</div>}
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              disabled={deleting}
              onClick={handleDelete}
              className="btn-primary flex-1 bg-red-600 hover:bg-red-500 border-red-600 disabled:opacity-50"
            >
              {deleting ? 'Excluindo...' : 'Excluir'}
            </button>
            <button type="button" onClick={() => setDeleteTarget(null)} className="btn-secondary flex-1">
              Cancelar
            </button>
          </div>
        </div>
      </Modal>
```

Note o `deleteTarget?.name` (era `deleteTarget.name`) — mesmo motivo do Task 1 Step 4.

- [ ] **Step 4: Rodar build**

```bash
export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH"
cd web && npm run build
```

Esperado: build conclui sem erros.

- [ ] **Step 5: Commit**

```bash
git add web/src/pages/Admin.tsx
git commit -m "refactor(admin): reskin aba Papéis com Panel/Modal"
```

---

### Task 3: `Settings.tsx` — página principal

**Files:**
- Modify: `web/src/pages/Settings.tsx:1-10` (imports), `:91-114` (menu lateral → `Panel`),
  `:117-231` (3 seções tituladas → `Panel`), `:255-293` (modal reduzir retenção → `Modal`)

**Interfaces:**
- Consumes: `Panel`/`Modal` (mesmas interfaces do Task 1).

- [ ] **Step 1: Adicionar imports**

Troque (linhas 1-11):

```tsx
import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Info, Database, Bell, ShieldCheck, Download, RefreshCw, Sparkles } from 'lucide-react';
import client from '../api/client';
import NotificationSettings from '../components/NotificationSettings';
import MonitoringSettings from '../components/MonitoringSettings';
import TwoFactorSettings from '../components/TwoFactorSettings';
import HttpsInfo from '../components/HttpsInfo';
import BackupRestore from '../components/BackupRestore';
import UpdateChecker from '../components/UpdateChecker';
import AISettings from '../components/AISettings';
import type { TrafficRetentionResponse } from '../types';
```

por:

```tsx
import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Info, Database, Bell, ShieldCheck, Download, RefreshCw, Sparkles } from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
import NotificationSettings from '../components/NotificationSettings';
import MonitoringSettings from '../components/MonitoringSettings';
import TwoFactorSettings from '../components/TwoFactorSettings';
import HttpsInfo from '../components/HttpsInfo';
import BackupRestore from '../components/BackupRestore';
import UpdateChecker from '../components/UpdateChecker';
import AISettings from '../components/AISettings';
import type { TrafficRetentionResponse } from '../types';
```

- [ ] **Step 2: Menu lateral → `Panel` sem título**

Troque (linha 92):

```tsx
        <div className="card space-y-1">
```

por:

```tsx
        <Panel className="space-y-1">
```

E o fechamento correspondente (linha 114), troque:

```tsx
        </div>

        <div className="md:col-span-3">
```

por:

```tsx
        </Panel>

        <div className="md:col-span-3">
```

- [ ] **Step 3: Seção "Sobre" → `Panel title="Sobre o LinkGuard FW"`**

Troque (linhas 118-119):

```tsx
            <div className="card space-y-4">
              <h2 className="text-white font-semibold">Sobre o LinkGuard FW</h2>
```

por:

```tsx
            <Panel title="Sobre o LinkGuard FW" className="space-y-4">
```

E o fechamento (linha 146), troque:

```tsx
            </div>
          )}

          {activeSection === 'general' && (
```

por:

```tsx
            </Panel>
          )}

          {activeSection === 'general' && (
```

- [ ] **Step 4: Seção "Configurações Gerais" → `Panel title="Configurações Gerais"`**

Troque (linhas 150-151):

```tsx
            <div className="card space-y-4">
              <h2 className="text-white font-semibold">Configurações Gerais</h2>
```

por:

```tsx
            <Panel title="Configurações Gerais" className="space-y-4">
```

E o fechamento (linha 173), troque:

```tsx
            </div>
          )}

          {activeSection === 'traffic-retention' && (
```

por:

```tsx
            </Panel>
          )}

          {activeSection === 'traffic-retention' && (
```

- [ ] **Step 5: Seção "Retenção de tráfego (RRD)" → `Panel title="Retenção de tráfego (RRD)"`**

Troque (linhas 177-178):

```tsx
            <div className="card space-y-4">
              <h2 className="text-white font-semibold">Retenção de tráfego (RRD)</h2>
```

por:

```tsx
            <Panel title="Retenção de tráfego (RRD)" className="space-y-4">
```

E o fechamento (linha 230), troque:

```tsx
            </div>
          )}

          {activeSection === 'security' && (
```

por:

```tsx
            </Panel>
          )}

          {activeSection === 'security' && (
```

**Não mexer** nos 3 banners `loadError`/`profileError`/`profileSaved` (linhas ~184-192) — ficam
exatamente como estão (`px-4 py-3 rounded-lg ...`), são conteúdo aninhado dentro do `Panel`, mesma
categoria dos banners internos de modal (ver Global Constraints).

- [ ] **Step 6: Modal "Reduzir retenção de tráfego" → `Modal size="sm"`**

Troque todo o bloco (linhas ~255-293):

```tsx
      {pendingShorten && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">Reduzir retenção de tráfego</h2>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-gray-300 text-sm">
                Reduzir a retenção pode descartar amostras antigas. Continuar?
              </p>
              <p className="text-gray-500 text-xs">
                Perfil atual: <span className="font-mono text-gray-300">{retentionProfile}</span> →{' '}
                novo perfil: <span className="font-mono text-gray-300">{pendingShorten}</span>
              </p>
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  disabled={savingProfile}
                  onClick={() => {
                    const target = pendingShorten;
                    setPendingShorten(null);
                    if (target) persistRetentionProfile(target);
                  }}
                  className="btn-primary flex-1 disabled:opacity-50"
                >
                  Continuar
                </button>
                <button
                  type="button"
                  onClick={() => setPendingShorten(null)}
                  className="btn-secondary flex-1"
                >
                  Cancelar
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
```

por:

```tsx
      <Modal open={!!pendingShorten} onClose={() => setPendingShorten(null)} title="Reduzir retenção de tráfego" size="sm">
        <div className="p-6 space-y-4">
          <p className="text-gray-300 text-sm">
            Reduzir a retenção pode descartar amostras antigas. Continuar?
          </p>
          <p className="text-gray-500 text-xs">
            Perfil atual: <span className="font-mono text-gray-300">{retentionProfile}</span> →{' '}
            novo perfil: <span className="font-mono text-gray-300">{pendingShorten}</span>
          </p>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              disabled={savingProfile}
              onClick={() => {
                const target = pendingShorten;
                setPendingShorten(null);
                if (target) persistRetentionProfile(target);
              }}
              className="btn-primary flex-1 disabled:opacity-50"
            >
              Continuar
            </button>
            <button
              type="button"
              onClick={() => setPendingShorten(null)}
              className="btn-secondary flex-1"
            >
              Cancelar
            </button>
          </div>
        </div>
      </Modal>
```

O título `"Reduzir retenção de tráfego"` é uma string fixa (não lê `pendingShorten`), não precisa de
guarda. O `{pendingShorten}` dentro do texto do corpo já é seguro sem guarda — interpolar `null` em
JSX simplesmente não renderiza nada, não quebra.

- [ ] **Step 7: Rodar build**

```bash
export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH"
cd web && npm run build
```

Esperado: build conclui sem erros.

- [ ] **Step 8: Commit**

```bash
git add web/src/pages/Settings.tsx
git commit -m "refactor(settings): reskin página principal com Panel/Modal"
```

---

### Task 4: 7 sub-componentes de `Settings.tsx` → `Panel`

**Files:**
- Modify: `web/src/components/NotificationSettings.tsx`, `MonitoringSettings.tsx`,
  `TwoFactorSettings.tsx`, `HttpsInfo.tsx`, `BackupRestore.tsx`, `UpdateChecker.tsx`,
  `AISettings.tsx`

**Interfaces:**
- Consumes: `Panel` (`web/src/components/ui/Panel.tsx`), import relativo `'./ui/Panel'` a partir de
  `web/src/components/*.tsx`.

Cada sub-componente tem exatamente 1 card titulado que vira `Panel`. Mesmo padrão já usado em
`WanBalancing.tsx`/`LinkStressTest.tsx`/`DnsQueryLog.tsx`/`PortForwarding.tsx` nas rodadas
anteriores: quando o cabeçalho do card tem ícone + texto (+ eventualmente `HelpTip`), vira um
`title` `ReactNode` com `<span className="flex items-center gap-2">` envolvendo tudo, e um
`<span className="text-white font-semibold">` só em volta do texto (nunca no ícone). Quando o card
original usava `space-y-N` para espaçar múltiplos elementos-irmãos abaixo do título, esse
espaçamento é preservado envolvendo o conteúdo (exceto o título) numa `<div className="space-y-N">`
— o espaço entre o título e o primeiro elemento de conteúdo passa a ser o `mb-4` padrão que o
`Panel` já aplica ao próprio cabeçalho (normalização visual já aceita em todas as rodadas
anteriores, nenhum card convertido usou `space-y-N` como `className` do `Panel` pra esse fim).

- [ ] **Step 1: `NotificationSettings.tsx`**

Adicione o import, trocando (linha 4):

```tsx
import HelpTip from './HelpTip';
```

por:

```tsx
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
```

Troque a abertura (linhas 61-72):

```tsx
  return (
    <div className="card space-y-5">
      <div className="flex items-center gap-2">
        <Bell className="w-5 h-5 text-blue-400" />
        <h3 className="text-white font-semibold">Notificações</h3>
        <HelpTip title="Notificações">
          <>Avise você fora do painel quando algo importante acontecer (um link cair, falha de regra...).
          Escolha um ou mais canais e o nível mínimo de severidade.</>
        </HelpTip>
      </div>

      {msg && (
```

por:

```tsx
  return (
    <Panel title={<span className="flex items-center gap-2"><Bell className="w-5 h-5 text-blue-400" /><span className="text-white font-semibold">Notificações</span><HelpTip title="Notificações">
          <>Avise você fora do painel quando algo importante acontecer (um link cair, falha de regra...).
          Escolha um ou mais canais e o nível mínimo de severidade.</>
        </HelpTip></span>}>
      <div className="space-y-5">
      {msg && (
```

Troque o fechamento (linhas 135-138):

```tsx
      <button onClick={save} disabled={busy} className="btn-primary flex items-center gap-2">
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} Salvar
      </button>
    </div>
  );
```

por:

```tsx
      <button onClick={save} disabled={busy} className="btn-primary flex items-center gap-2">
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} Salvar
      </button>
      </div>
    </Panel>
  );
```

O restante do conteúdo entre a abertura e o fechamento (select de severidade, os 4 blocos
`<Channel>`) fica exatamente como está.

- [ ] **Step 2: `MonitoringSettings.tsx`**

Adicione o import, trocando (linha 2):

```tsx
import client from '../api/client';
```

por:

```tsx
import client from '../api/client';
import Panel from './ui/Panel';
```

Troque (linhas 26-28):

```tsx
  return (
    <div className="card">
      <h2 className="text-white font-semibold mb-1">Vigilância</h2>
      <p className="text-gray-500 text-xs mb-3">Avisa no seu canal de notificação quando algo cai (e quando volta).</p>
```

por:

```tsx
  return (
    <Panel title="Vigilância">
      <p className="text-gray-500 text-xs mb-3">Avisa no seu canal de notificação quando algo cai (e quando volta).</p>
```

Troque o fechamento (linhas 46-48):

```tsx
      {msg && <div className="mt-2 text-xs text-gray-400">{msg}</div>}
    </div>
  );
```

por:

```tsx
      {msg && <div className="mt-2 text-xs text-gray-400">{msg}</div>}
    </Panel>
  );
```

Este card não usa `space-y-N` (usa `mb-1`/`mb-3`/`mt-3`/`mt-2` individuais por elemento) — não
precisa de `<div>` intermediária, só troca a casca.

- [ ] **Step 3: `TwoFactorSettings.tsx`**

Adicione o import, trocando (linha 4):

```tsx
import HelpTip from './HelpTip';
```

por:

```tsx
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
```

Troque a abertura (linhas 56-67):

```tsx
  return (
    <div className="card space-y-4">
      <div className="flex items-center gap-2">
        {enabled ? <ShieldCheck className="w-5 h-5 text-green-400" /> : <ShieldAlert className="w-5 h-5 text-amber-400" />}
        <h3 className="text-white font-semibold">Verificação em duas etapas (2FA)</h3>
        <HelpTip title="2FA">
          <>Além da senha, pede um <b>código que muda a cada 30s</b> gerado por um app autenticador
          (Google Authenticator, Authy, etc.). Mesmo que descubram sua senha, não entram sem o código.</>
        </HelpTip>
      </div>

      {msg && <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>}
```

por:

```tsx
  return (
    <Panel title={<span className="flex items-center gap-2">{enabled ? <ShieldCheck className="w-5 h-5 text-green-400" /> : <ShieldAlert className="w-5 h-5 text-amber-400" />}<span className="text-white font-semibold">Verificação em duas etapas (2FA)</span><HelpTip title="2FA">
          <>Além da senha, pede um <b>código que muda a cada 30s</b> gerado por um app autenticador
          (Google Authenticator, Authy, etc.). Mesmo que descubram sua senha, não entram sem o código.</>
        </HelpTip></span>}>
      <div className="space-y-4">
      {msg && <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>}
```

Troque o fechamento (linhas 109-111):

```tsx
      )}
    </div>
  );
```

por:

```tsx
      )}
      </div>
    </Panel>
  );
```

- [ ] **Step 4: `HttpsInfo.tsx`**

Adicione o import, trocando (linha 2):

```tsx
import HelpTip from './HelpTip';
```

por:

```tsx
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
```

Troque a abertura (linhas 13-24):

```tsx
  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        {secure ? <Lock className="w-5 h-5 text-green-400" /> : <ShieldAlert className="w-5 h-5 text-amber-400" />}
        <h3 className="text-white font-semibold">Acesso ao painel (HTTPS)</h3>
        <HelpTip title="HTTPS">
          <>HTTPS criptografa o tráfego entre o seu navegador e o painel. Importante se o painel
          for acessível pela internet ou por uma rede não confiável.</>
        </HelpTip>
      </div>

      <p className={`text-sm ${secure ? 'text-green-400' : 'text-amber-300'}`}>
```

por:

```tsx
  return (
    <Panel title={<span className="flex items-center gap-2">{secure ? <Lock className="w-5 h-5 text-green-400" /> : <ShieldAlert className="w-5 h-5 text-amber-400" />}<span className="text-white font-semibold">Acesso ao painel (HTTPS)</span><HelpTip title="HTTPS">
          <>HTTPS criptografa o tráfego entre o seu navegador e o painel. Importante se o painel
          for acessível pela internet ou por uma rede não confiável.</>
        </HelpTip></span>}>
      <div className="space-y-3">
      <p className={`text-sm ${secure ? 'text-green-400' : 'text-amber-300'}`}>
```

Troque o fechamento (linhas 40-44):

```tsx
      )}
    </div>
  );
}
```

por:

```tsx
      )}
      </div>
    </Panel>
  );
}
```

- [ ] **Step 5: `BackupRestore.tsx`**

Adicione o import, trocando (linha 4):

```tsx
import HelpTip from './HelpTip';
```

por:

```tsx
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
```

Troque a abertura (linhas 62-73):

```tsx
  return (
    <div className="card space-y-4">
      <div className="flex items-center gap-2">
        <Download className="w-5 h-5 text-blue-400" />
        <h3 className="text-white font-semibold">Backup e restauração</h3>
        <HelpTip title="Backup">
          <>Salva num arquivo todas as suas configurações (links, firewall, DHCP/DNS, VPN, balanceamento,
          notificações...). Útil antes de mexer em algo ou para migrar de máquina.</>
        </HelpTip>
      </div>

      {msg && <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>}
```

por:

```tsx
  return (
    <Panel title={<span className="flex items-center gap-2"><Download className="w-5 h-5 text-blue-400" /><span className="text-white font-semibold">Backup e restauração</span><HelpTip title="Backup">
          <>Salva num arquivo todas as suas configurações (links, firewall, DHCP/DNS, VPN, balanceamento,
          notificações...). Útil antes de mexer em algo ou para migrar de máquina.</>
        </HelpTip></span>}>
      <div className="space-y-4">
      {msg && <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>}
```

Troque o fechamento (linhas 130-133):

```tsx
      )}
    </div>
  );
}
```

por:

```tsx
      )}
      </div>
    </Panel>
  );
}
```

- [ ] **Step 6: `UpdateChecker.tsx`**

Adicione o import, trocando (linha 3):

```tsx
import client from '../api/client';
```

por:

```tsx
import client from '../api/client';
import Panel from './ui/Panel';
```

Troque a abertura (linhas 77-86):

```tsx
  return (
    <div className="card space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-white font-semibold">Atualizações</h3>
        <button onClick={check} disabled={checking || applying} className="btn-secondary text-sm flex items-center gap-1.5">
          <RefreshCw className={`w-4 h-4 ${checking ? 'animate-spin' : ''}`} /> Verificar
        </button>
      </div>

      {msg && (
```

por:

```tsx
  return (
    <Panel
      title="Atualizações"
      action={
        <button onClick={check} disabled={checking || applying} className="btn-secondary text-sm flex items-center gap-1.5">
          <RefreshCw className={`w-4 h-4 ${checking ? 'animate-spin' : ''}`} /> Verificar
        </button>
      }
    >
      <div className="space-y-4">
      {msg && (
```

Troque o fechamento (linhas 147-150):

```tsx
      )}
    </div>
  );
}
```

por:

```tsx
      )}
      </div>
    </Panel>
  );
}
```

- [ ] **Step 7: `AISettings.tsx`**

Adicione o import, trocando (linha 3):

```tsx
import client from '../api/client';
```

por:

```tsx
import client from '../api/client';
import Panel from './ui/Panel';
```

Troque a abertura (linhas 104-114):

```tsx
  return (
    <div className="card space-y-4">
      <div className="flex items-center gap-2">
        <Sparkles className="w-4 h-4 text-purple-400" />
        <h2 className="text-white font-semibold">Assistente de IA</h2>
      </div>
      <p className="text-gray-500 text-sm">
        Análise opcional de padrões de degradação usando sua própria chave da API do Claude.
        Nunca decide failover, peso ou expulsão de link — só explica e sugere.
      </p>

      {!status?.configured ? (
```

por:

```tsx
  return (
    <Panel title={<span className="flex items-center gap-2"><Sparkles className="w-4 h-4 text-purple-400" /><span className="text-white font-semibold">Assistente de IA</span></span>}>
      <div className="space-y-4">
      <p className="text-gray-500 text-sm">
        Análise opcional de padrões de degradação usando sua própria chave da API do Claude.
        Nunca decide failover, peso ou expulsão de link — só explica e sugere.
      </p>

      {!status?.configured ? (
```

Troque o fechamento (linhas 199-202):

```tsx
      )}
    </div>
  );
}
```

por:

```tsx
      )}
      </div>
    </Panel>
  );
}
```

- [ ] **Step 8: Rodar build**

```bash
export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH"
cd web && npm run build
```

Esperado: build conclui sem erros de TypeScript nos 7 arquivos.

- [ ] **Step 9: Commit**

```bash
git add web/src/components/NotificationSettings.tsx web/src/components/MonitoringSettings.tsx web/src/components/TwoFactorSettings.tsx web/src/components/HttpsInfo.tsx web/src/components/BackupRestore.tsx web/src/components/UpdateChecker.tsx web/src/components/AISettings.tsx
git commit -m "refactor(settings): reskin sub-componentes com Panel"
```

---

## Ordem de execução

Task 1 → Task 2 (mesmo arquivo `Admin.tsx`, Task 2 depende dos imports do Task 1) → Task 3 → Task 4
(arquivos totalmente independentes de `Admin.tsx`, podem rodar em qualquer ordem relativa a ele, mas
seguem em sequência por simplicidade do ledger).

Após as 4 tasks: revisão final de branch inteira (whole-branch review) no modelo mais capaz
disponível, depois `finishing-a-development-branch` (merge local em `main`), deploy manual (build →
`.deb` → scp → instalar em produção → verificar `/api/health`), tag `vX.Y.Z` + push.
