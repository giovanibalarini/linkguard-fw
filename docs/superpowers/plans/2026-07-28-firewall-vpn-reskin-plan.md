# Reskin Firewall + VPN — Plano de Implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Trocar a casca visual de `Firewall.tsx`, `PortForwarding.tsx` e `Vpn.tsx` pros componentes
`Panel`/`Modal`, sem alterar nenhum comportamento — incluindo o clique-fora-fecha e o botão X do
`PeerConfigModal`, que exigem estender `Modal.tsx` (mudança aditiva, retrocompatível).

**Architecture:** Mesmo padrão das rodadas 1-2. Task 1 estende `Modal.tsx` com duas props opcionais
antes de qualquer consumidor novo precisar delas.

**Tech Stack:** React + TypeScript + Vite + Tailwind.

## Global Constraints

- **Zero mudança de comportamento observável pro usuário** — inclusive comportamentos que hoje só
  existem no `PeerConfigModal` (clique fora fecha, botão X) precisam sobreviver à conversão.
- `Panel` já existe (`web/src/components/ui/Panel.tsx`) — não alterar.
- `Modal` (`web/src/components/ui/Modal.tsx`) — a ÚNICA mudança permitida nele nesta rodada é a
  extensão aditiva da Task 1; nenhuma outra alteração de comportamento ou remoção de prop existente.
- Título como `ReactNode` (ícone + texto) precisa de `text-white font-semibold` explícito só no
  `<span>` do texto — mesma armadilha das rodadas 1-2.
- Sem framework de teste no frontend — verificação por tarefa via `npm run build`.
- Toda tarefa termina com `git commit` próprio.

---

### Task 1: Estender `Modal.tsx` com `action` e `closeOnBackdropClick`

**Files:**
- Modify: `web/src/components/ui/Modal.tsx`

**Interfaces:**
- Produces: `ModalProps` ganha dois campos opcionais — `action?: ReactNode` e
  `closeOnBackdropClick?: boolean` (default `false`). Tasks 2-4 (nenhuma delas usa essas props —
  só a Task 5, `PeerConfigModal`) continuam chamando `Modal` exatamente como hoje, sem quebrar.

- [ ] **Step 1: Escrever a versão estendida**

```tsx
import type { ReactNode } from 'react';

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

export default function Modal({
  open, onClose, title, children, size = 'md', className = '', action, closeOnBackdropClick = false,
}: ModalProps) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
      onClick={closeOnBackdropClick ? onClose : undefined}
    >
      <div
        className={`w-full ${sizeClass[size]} max-h-[90vh] overflow-y-auto ${className}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className={`px-6 py-4 border-b border-gray-800 ${action ? 'flex items-center justify-between' : ''}`}>
          {typeof title === 'string' ? <h2 className="text-white font-semibold">{title}</h2> : title}
          {action}
        </div>
        {children}
      </div>
    </div>
  );
}
```

Duas mudanças em relação à versão atual: (1) o `onClick` do overlay só existe quando
`closeOnBackdropClick` é `true` — pros 4 usos já em produção (que não passam essa prop), o overlay
continua sem `onClick` nenhum, igual está hoje; (2) o card interno sempre para a propagação do
clique (`onClick={(e) => e.stopPropagation()}`), incondicional — isso não muda nada pra quem não tem
listener no overlay (não tem nada pra propagação interromper), só passa a importar quando
`closeOnBackdropClick=true` estiver em uso.

- [ ] **Step 2: Build**

Run: `cd web && npm run build`
Expected: build limpo. Como nenhum consumidor existente passa as props novas, o comportamento visual
de todo o resto do app não muda — só o `Modal.tsx` em si foi tocado nesta tarefa.

- [ ] **Step 3: Commit**

```bash
git add web/src/components/ui/Modal.tsx
git commit -m "feat(web): Modal ganha action e closeOnBackdropClick (aditivo, retrocompatível)"
```

---

### Task 2: `Firewall.tsx` — 6 seções viram `Panel` + modal de regra vira `Modal`

**Files:**
- Modify: `web/src/pages/Firewall.tsx`

**Interfaces:**
- Consumes: `Panel` (`web/src/components/ui/Panel.tsx`), `Modal` (Task 1 — mas esta tarefa usa só as
  props já existentes: `open`, `onClose`, `title`, `children`, `size`, `className`; não usa `action`
  nem `closeOnBackdropClick`, porque o modal de regra do Firewall não tem clique-fora-fecha nem botão
  X — mesmo formato do modal do assistente 2-WAN da rodada 1).

- [ ] **Step 1: Import**

```tsx
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
```

- [ ] **Step 2: Banner de mensagem**

Trocar:
```tsx
      {msg && (
        <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>{msg}</div>
      )}
```
por:
```tsx
      {msg && (
        <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>
      )}
```

- [ ] **Step 3: Card "Regras personalizadas" vira `Panel`**

Trocar:
```tsx
          <div className="card">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <ListChecks className="w-4 h-4 text-blue-400" />
                <h3 className="text-white font-semibold">Regras personalizadas</h3>
              </div>
              {canWrite && <button onClick={openCreate} className="btn-primary flex items-center gap-2 w-full sm:w-auto justify-center"><Plus className="w-4 h-4" /> Nova regra</button>}
            </div>
```
por:
```tsx
          <Panel
            title={<span className="flex items-center gap-2"><ListChecks className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Regras personalizadas</span></span>}
            action={canWrite ? <button onClick={openCreate} className="btn-primary flex items-center gap-2 justify-center"><Plus className="w-4 h-4" /> Nova regra</button> : undefined}
          >
```

E o fechamento (logo antes do comentário `{/* WAN steering */}`):
```tsx
              </div>
            )}
          </div>

          {/* WAN steering */}
```
por:
```tsx
              </div>
            )}
          </Panel>

          {/* WAN steering */}
```

- [ ] **Step 4: Card "Direcionamento por WAN" vira `Panel`**

Trocar:
```tsx
          <div className="card">
            <div className="flex items-center gap-2 mb-1"><Network className="w-4 h-4 text-blue-400" /><h3 className="text-white font-semibold">Direcionamento por WAN</h3></div>
```
por:
```tsx
          <Panel title={<span className="flex items-center gap-2"><Network className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Direcionamento por WAN</span></span>}>
```

E o fechamento (antes do comentário `{/* Blocklist */}`):
```tsx
            </div>
          </div>

          {/* Blocklist */}
```
por:
```tsx
            </div>
          </Panel>

          {/* Blocklist */}
```

- [ ] **Step 5: Card "Destinos bloqueados" vira `Panel`**

Trocar:
```tsx
          <div className="card">
            <div className="flex items-center gap-2 mb-1"><Ban className="w-4 h-4 text-red-400" /><h3 className="text-white font-semibold">Destinos bloqueados</h3></div>
```
por:
```tsx
          <Panel title={<span className="flex items-center gap-2"><Ban className="w-4 h-4 text-red-400" /><span className="text-white font-semibold">Destinos bloqueados</span></span>}>
```

E o fechamento (antes do comentário `{/* Blocked hosts (read-only) */}`):
```tsx
            </div>
          </div>

          {/* Blocked hosts (read-only) */}
```
por:
```tsx
            </div>
          </Panel>

          {/* Blocked hosts (read-only) */}
```

- [ ] **Step 6: Card "Hosts bloqueados" vira `Panel`**

Trocar:
```tsx
          <div className="card">
            <div className="flex items-center gap-2 mb-1"><ShieldOff className="w-4 h-4 text-orange-400" /><h3 className="text-white font-semibold">Hosts bloqueados</h3></div>
```
por:
```tsx
          <Panel title={<span className="flex items-center gap-2"><ShieldOff className="w-4 h-4 text-orange-400" /><span className="text-white font-semibold">Hosts bloqueados</span></span>}>
```

E o fechamento (antes de `</div>\n      ) : activeTab === 'portforward'`):
```tsx
            </div>
          </div>
        </div>
      ) : activeTab === 'portforward' ? (
```
por:
```tsx
            </div>
          </Panel>
        </div>
      ) : activeTab === 'portforward' ? (
```

(O `</div>` logo antes desse trecho, que fecha o `<div className="space-y-4">` que envolve as 4
seções, NÃO muda — só o `</div>` do card "Hosts bloqueados" vira `</Panel>`.)

- [ ] **Step 7: Card do visualizador de ruleset vira `Panel` sem título**

Trocar:
```tsx
        <div className="card p-0 overflow-hidden">
          <div className="px-4 py-2 border-b border-gray-800 flex items-center gap-2 text-xs text-gray-500"><Terminal className="w-3.5 h-3.5" /><span className="font-mono">nft list ruleset</span></div>
          {ruleset.trim() ? <pre className="p-4 overflow-x-auto text-xs font-mono text-gray-300 leading-relaxed whitespace-pre">{ruleset}</pre> : <p className="p-8 text-center text-gray-600 text-sm">Ruleset vazio.</p>}
        </div>
```
por:
```tsx
        <Panel className="p-0 overflow-hidden">
          <div className="px-4 py-2 border-b border-gray-800 flex items-center gap-2 text-xs text-gray-500"><Terminal className="w-3.5 h-3.5" /><span className="font-mono">nft list ruleset</span></div>
          {ruleset.trim() ? <pre className="p-4 overflow-x-auto text-xs font-mono text-gray-300 leading-relaxed whitespace-pre">{ruleset}</pre> : <p className="p-8 text-center text-gray-600 text-sm">Ruleset vazio.</p>}
        </Panel>
```

(Sem `title`/`action`, `Panel` não renderiza nenhum cabeçalho extra — o cabeçalho customizado
`nft list ruleset` já presente no conteúdo continua sendo o único cabeçalho visível, exatamente como
hoje. `Panel`'s `className` é concatenada depois de `card` (ver `web/src/components/ui/Panel.tsx:12`,
`` `card ${className}` ``), então `p-0 overflow-hidden` sobrescreve o padding padrão do `.card` do
jeito que já sobrescrevia antes.)

- [ ] **Step 8: Card da tabela de snapshots vira `Panel` sem título**

Trocar:
```tsx
        <div className="card">
          {backups.length === 0 ? (
```
por:
```tsx
        <Panel>
          {backups.length === 0 ? (
```

E o fechamento (a última linha antes do comentário `{/* Rule modal */}`):
```tsx
          )}
        </div>
      )}

      {/* Rule modal */}
```
por:
```tsx
          )}
        </Panel>
      )}

      {/* Rule modal */}
```

- [ ] **Step 9: Modal de regra vira `Modal`**

Trocar:
```tsx
      {/* Rule modal */}
      {modal.open && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="w-full max-w-lg rounded-xl border border-gray-700 bg-gray-900 shadow-2xl max-h-[90vh] flex flex-col">
            <div className="px-6 py-4 border-b border-gray-800">
              <h3 className="text-white font-semibold">{modal.handle > 0 ? 'Editar regra' : 'Nova regra'}</h3>
            </div>
            <div className="p-6 space-y-4 overflow-y-auto">
```
por:
```tsx
      {/* Rule modal */}
      <Modal
        open={modal.open}
        onClose={closeModal}
        title={modal.handle > 0 ? 'Editar regra' : 'Nova regra'}
        size="md"
        className="rounded-xl border border-gray-700 bg-gray-900 shadow-2xl flex flex-col"
      >
            <div className="p-6 space-y-4 overflow-y-auto">
```

Nota: o card original tinha `max-h-[90vh]` no próprio wrapper (porque o `flex flex-col` dividia
cabeçalho/corpo/rodapé em três blocos, com só o corpo rolando via `overflow-y-auto`). O `Modal` já
aplica `max-h-[90vh] overflow-y-auto` no seu próprio wrapper — aqui isso duplica com o
`overflow-y-auto` do corpo interno, mas não conflita: o wrapper do `Modal` vira o limite de altura
(`max-h-[90vh]`), e o `overflow-y-auto` do corpo interno (`<div className="p-6 space-y-4
overflow-y-auto">`) só entra em jogo se o conteúdo ainda for maior que o espaço restante depois do
cabeçalho/rodapé fixos — mesmo efeito visual de antes (cabeçalho e rodapé sempre visíveis, corpo
rola). `flex flex-col` precisa continuar no `className` passado pro `Modal` pra manter esse
comportamento de layout.

E o fechamento (a única mudança é a mesma estrutura de fechamento — 2 `</div>` a menos porque
removemos o wrapper `fixed inset-0` e o card `w-full max-w-lg...`):
```tsx
            </div>
            <div className="px-6 py-4 border-t border-gray-800 flex gap-3">
              <button onClick={saveRule} disabled={busy} className="btn-primary flex-1 disabled:opacity-50">{busy ? 'Salvando...' : 'Salvar'}</button>
              <button onClick={closeModal} className="btn-secondary flex-1">Cancelar</button>
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
            <div className="px-6 py-4 border-t border-gray-800 flex gap-3">
              <button onClick={saveRule} disabled={busy} className="btn-primary flex-1 disabled:opacity-50">{busy ? 'Salvando...' : 'Salvar'}</button>
              <button onClick={closeModal} className="btn-secondary flex-1">Cancelar</button>
            </div>
      </Modal>
    </div>
  );
}
```

Diferente dos modais das rodadas anteriores, este não tem um `{modal.open && (...)}` condicional por
fora — o controle de visibilidade já era feito só por `modal.open` (que nunca é `null`/`undefined`,
é sempre um objeto com `open: boolean`), então `open={modal.open}` no `Modal` já basta; não precisa
de guard adicional porque nada dentro do corpo lê um valor que pudesse ser `null`.

- [ ] **Step 10: Build**

Run: `cd web && npm run build`
Expected: build limpo. Esta é a tarefa com mais pontos de edição do plano inteiro — preste atenção
especial a tags desalinhadas.

- [ ] **Step 11: Commit**

```bash
git add web/src/pages/Firewall.tsx
git commit -m "refactor(web): Firewall.tsx usa Panel/Modal"
```

---

### Task 3: `PortForwarding.tsx` vira `Panel`

**Files:**
- Modify: `web/src/components/PortForwarding.tsx`

**Interfaces:**
- Consumes: `Panel` (`web/src/components/ui/Panel.tsx`).

- [ ] **Step 1: Ler o arquivo antes de editar**

Ler `web/src/components/PortForwarding.tsx` por completo (73 linhas até o `return`, mais o corpo do
JSX) — este plano só viu o cabeçalho (linhas 73-84) ao ser escrito, não o arquivo inteiro. O padrão a
aplicar é idêntico ao já usado em `WanBalancing.tsx`/`LinkStressTest.tsx`/`DnsQueryLog.tsx` nas
rodadas 1-2: `<div className="card">` → `<Panel title={<span className="flex items-center
gap-2">{ícone}<span className="text-white font-semibold">{texto}</span>{eventual HelpTip}</span>}>`,
fechamento final `</div>` → `</Panel>`. O cabeçalho conhecido (linhas 75-83) é:
```tsx
      <div className="flex items-center gap-2 mb-1">
        <Network className="w-4 h-4 text-blue-400" />
        <h3 className="text-white font-semibold">Encaminhamento de portas</h3>
        <HelpTip title="O que é encaminhar uma porta?">
          <>Permite que algo de <b>fora</b> (internet) alcance um <b>serviço dentro da sua rede</b> —
          como um servidor, câmera ou jogo. Você diz: "conexões que chegam na porta X da minha internet
          devem ir para o aparelho Y na porta Z". Abra só o necessário.</>
        </HelpTip>
      </div>
```
vira o `title` do `Panel` (icon + span com `text-white font-semibold` só no texto + `HelpTip` como
irmão, mesmo padrão de `WanBalancing.tsx`/`LinkStressTest.tsx`), e a linha seguinte (`<p
className="text-gray-500 text-xs mb-4">Redireciona...`) vira o primeiro filho do `Panel`.

- [ ] **Step 2: Import**

```tsx
import Panel from './ui/Panel';
```

- [ ] **Step 3: Aplicar a troca conforme identificado no Step 1**

- [ ] **Step 4: Build**

Run: `cd web && npm run build`
Expected: build limpo.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/PortForwarding.tsx
git commit -m "refactor(web): PortForwarding.tsx usa Panel"
```

---

### Task 4: `Vpn.tsx` — 3 cards viram `Panel` + banner

**Files:**
- Modify: `web/src/pages/Vpn.tsx`

**Interfaces:**
- Consumes: `Panel` (`web/src/components/ui/Panel.tsx`).

- [ ] **Step 1: Import**

```tsx
import Panel from '../components/ui/Panel';
```

- [ ] **Step 2: Banner de mensagem**

Trocar:
```tsx
      {msg && <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>{msg}</div>}
```
por:
```tsx
      {msg && <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>}
```

- [ ] **Step 3: Card "Status" vira `Panel` sem título**

Trocar:
```tsx
      {/* Status */}
      <div className="card">
        <div className="flex items-center gap-2">
```
por:
```tsx
      {/* Status */}
      <Panel>
        <div className="flex items-center gap-2">
```

E o fechamento (antes do comentário `{/* Server settings */}`):
```tsx
        {online && <pre className="mt-3 text-xs font-mono text-gray-400 overflow-x-auto whitespace-pre-wrap">{view.status}</pre>}
      </div>

      {/* Server settings */}
```
por:
```tsx
        {online && <pre className="mt-3 text-xs font-mono text-gray-400 overflow-x-auto whitespace-pre-wrap">{view.status}</pre>}
      </Panel>

      {/* Server settings */}
```

(Este card não tem `<h3>` — o "título" visual dele já é o texto de status dinâmico dentro do corpo,
não um cabeçalho fixo. Por isso vira `Panel` sem `title`, igual ao card de snapshots do Firewall.)

- [ ] **Step 4: Card "Servidor" vira `Panel`**

Trocar:
```tsx
      {/* Server settings */}
      <div className="card">
        <h3 className="text-white font-semibold mb-3">Servidor</h3>
```
por:
```tsx
      {/* Server settings */}
      <Panel title="Servidor">
```

(Título aqui é string simples — `Panel` já aplica `text-white font-semibold` sozinho, igual fazia o
`<h3>` original. Note que o `mb-3` do `<h3>` original não precisa ser reproduzido: `Panel` já aplica
`mb-4` no wrapper do cabeçalho quando há `title`/`action`, ver `web/src/components/ui/Panel.tsx:14`.)

E o fechamento (antes do comentário `{/* Clients */}`):
```tsx
        <p className="text-gray-600 text-xs mt-2">A porta {form.listen_port ?? 51820}/UDP precisa chegar ao firewall (encaminhe no modem se houver).</p>
      </div>

      {/* Clients */}
```
por:
```tsx
        <p className="text-gray-600 text-xs mt-2">A porta {form.listen_port ?? 51820}/UDP precisa chegar ao firewall (encaminhe no modem se houver).</p>
      </Panel>

      {/* Clients */}
```

- [ ] **Step 5: Card "Clientes" vira `Panel`**

Trocar:
```tsx
      {/* Clients */}
      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-white font-semibold flex items-center gap-2"><Smartphone className="w-4 h-4 text-blue-400" /> Clientes ({cfg.peers.length})</h3>
        </div>
```
por:
```tsx
      {/* Clients */}
      <Panel title={<span className="flex items-center gap-2"><Smartphone className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Clientes ({cfg.peers.length})</span></span>}>
```

E o fechamento (a última linha antes de `{reveal && <PeerConfigModal ...}`):
```tsx
          </div>
        )}
      </div>

      {reveal && <PeerConfigModal name={reveal.name} config={reveal.config} onClose={() => setReveal(null)} />}
```
por:
```tsx
          </div>
        )}
      </Panel>

      {reveal && <PeerConfigModal name={reveal.name} config={reveal.config} onClose={() => setReveal(null)} />}
```

- [ ] **Step 6: Build**

Run: `cd web && npm run build`
Expected: build limpo. `PeerConfigModal` (função separada, linhas 199-227 do arquivo original) fica
intocado nesta tarefa — é a Task 5.

- [ ] **Step 7: Commit**

```bash
git add web/src/pages/Vpn.tsx
git commit -m "refactor(web): Vpn.tsx usa Panel (cards Status/Servidor/Clientes)"
```

---

### Task 5: `PeerConfigModal` (dentro de `Vpn.tsx`) vira `Modal` com `action` e `closeOnBackdropClick`

**Files:**
- Modify: `web/src/pages/Vpn.tsx` (função `PeerConfigModal`, já isolada no mesmo arquivo)

**Interfaces:**
- Consumes: `Modal` (Task 1) — desta vez usando as duas props novas: `action` (botão X) e
  `closeOnBackdropClick={true}`.

- [ ] **Step 1: Import**

Adicionar ao import já existente do `Panel` (Task 4):
```tsx
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
```

- [ ] **Step 2: Converter `PeerConfigModal`**

Trocar:
```tsx
function PeerConfigModal({ name, config, onClose }: { name: string; config: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard.writeText(config); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  const download = () => {
    const blob = new Blob([config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${name.replace(/\s+/g, '-').toLowerCase()}.conf`;
    a.click(); URL.revokeObjectURL(url);
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-lg p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-white font-semibold">Configuração de "{name}"</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="w-5 h-5" /></button>
        </div>
        <p className="text-gray-500 text-xs mb-3">Importe este arquivo no app WireGuard do aparelho (ou cole o conteúdo). Guarde com cuidado: contém a chave privada do cliente.</p>
        <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre max-h-60">{config}</pre>
        <div className="flex gap-2 mt-4">
          <button onClick={copy} className="btn-secondary flex items-center gap-1.5 text-sm">
            {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />} {copied ? 'Copiado' : 'Copiar'}
          </button>
          <button onClick={download} className="btn-primary flex items-center gap-1.5 text-sm"><Download className="w-4 h-4" /> Baixar .conf</button>
        </div>
      </div>
    </div>
  );
}
```
por:
```tsx
function PeerConfigModal({ name, config, onClose }: { name: string; config: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard.writeText(config); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  const download = () => {
    const blob = new Blob([config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${name.replace(/\s+/g, '-').toLowerCase()}.conf`;
    a.click(); URL.revokeObjectURL(url);
  };
  return (
    <Modal
      open
      onClose={onClose}
      closeOnBackdropClick
      title={`Configuração de "${name}"`}
      size="md"
      className="bg-gray-900 border border-gray-800 rounded-xl p-5"
      action={<button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="w-5 h-5" /></button>}
    >
      <p className="text-gray-500 text-xs mb-3">Importe este arquivo no app WireGuard do aparelho (ou cole o conteúdo). Guarde com cuidado: contém a chave privada do cliente.</p>
      <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre max-h-60">{config}</pre>
      <div className="flex gap-2 mt-4">
        <button onClick={copy} className="btn-secondary flex items-center gap-1.5 text-sm">
          {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />} {copied ? 'Copiado' : 'Copiar'}
        </button>
        <button onClick={download} className="btn-primary flex items-center gap-1.5 text-sm"><Download className="w-4 h-4" /> Baixar .conf</button>
      </div>
    </Modal>
  );
}
```

Atenção a duas diferenças estruturais importantes em relação a todo modal já convertido antes:
1. `open` é passado sem valor (`open` sozinho, equivale a `open={true}`) — `PeerConfigModal` só é
   renderizado quando `reveal` já não é `null` (`{reveal && <PeerConfigModal ...>}`, no componente
   pai `Vpn`), então dentro de `PeerConfigModal` não existe um booleano de "aberto" — o componente
   inteiro só existe quando deveria estar visível. Isso é diferente do modal de reserva do DHCP ou do
   modal de regra do Firewall, que controlam visibilidade com um campo de estado (`resModal`/
   `modal.open`) dentro do MESMO componente que sempre renderiza.
2. `title` vira um **template string** (`` `Configuração de "${name}"` ``) em vez do `<h3>` original —
   ainda é uma **string simples** em tempo de execução (`typeof title === 'string'` continua `true`
   pra um template string sem interpolação de `ReactNode`, já que `name` é sempre `string`), então
   `Modal` aplica `text-white font-semibold` sozinho — sem precisar do `<span>` manual usado nos
   títulos com ícone.
3. `className` ganha `p-5` no final — o card original tinha `p-5` (padding do card inteiro, sem
   cabeçalho separado com sua própria borda); como o `Modal` agora sempre renderiza um cabeçalho com
   `px-6 py-4 border-b`, esse padding do card original (que também envolvia o cabeçalho) não é mais
   idêntico byte-a-byte — mas como cabeçalho e corpo aqui sempre tiveram o mesmo fundo/borda visual
   (não havia diferença de estilo entre os dois no design original, só um `mb-3` separando), o
   resultado visual fica equivalente ao original dentro da margem de simplificação já aceita nas
   rodadas anteriores (mesmo espírito da rodada 1, que já documentou simplificar o overlay do
   assistente 2-WAN).

- [ ] **Step 3: Build**

Run: `cd web && npm run build`
Expected: build limpo.

- [ ] **Step 4: Commit**

```bash
git add web/src/pages/Vpn.tsx
git commit -m "refactor(web): PeerConfigModal usa Modal (closeOnBackdropClick + action)"
```

---

### Task 6: Verificação final

**Files:**
- Nenhum arquivo de produto — só verificação.

- [ ] **Step 1: Build limpo de ponta a ponta**

Run: `cd web && npm run build`
Expected: build limpo, sem warnings novos além do já existente aviso de chunk size.

- [ ] **Step 2: Verificação visual**

Sem Playwright disponível — confirmar `git status` limpo e descrever no relatório que a confirmação
visual (**principalmente o clique-fora-fecha e o botão X do `PeerConfigModal`, e as 5 seções
convertidas do Firewall**) fica pendente do usuário após deploy.

- [ ] **Step 3: Commit (só se a verificação exigiu correções)**

---

## Auto-revisão do plano

**Cobertura do spec**: extensão do `Modal` (Task 1) · `Firewall.tsx` (Task 2) ·
`PortForwarding.tsx` (Task 3) · `Vpn.tsx` cards (Task 4) · `PeerConfigModal` (Task 5) ·
verificação (Task 6).

**Placeholders**: Task 3 tem um passo de leitura prévia do arquivo, mesmo padrão já usado na Task 3
da rodada 2 (`DnsQueryLog.tsx`) — não é um placeholder de conteúdo, é uma instrução real porque o
arquivo não foi lido linha a linha ao escrever este plano.

**Consistência de tipos**: `ModalProps` ganha `action`/`closeOnBackdropClick` na Task 1; a Task 2
usa `Modal` sem essas duas props novas (comportamento idêntico ao já existente), a Task 5 é a única
que usa as duas — nenhuma tarefa usa uma prop que a Task 1 não tenha definido.

**Risco levado das rodadas 1-2**: título como `ReactNode` precisa de `text-white font-semibold`
explícito só no `<span>` do texto — replicado em todos os títulos com ícone deste plano (Firewall
×3 com ícone, Vpn "Clientes"). Os títulos que são string simples (Vpn "Servidor",
`PeerConfigModal`) não precisam disso — `Panel`/`Modal` já cuidam sozinhos.

**Achado específico desta rodada, já registrado no spec**: `PeerConfigModal` tinha
clique-fora-fecha e botão X que nenhum modal das rodadas 1-2 tinha — resolvido estendendo `Modal`
de forma aditiva (Task 1) em vez de perder o comportamento ou duplicar uma segunda casca de modal
bespoke.
