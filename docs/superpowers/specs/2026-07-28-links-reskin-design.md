# Reskin da tela Links WAN

**Data:** 2026-07-28
**Status:** desenho aprovado, pronto para plano de implementação

---

## 1. Relação com o roadmap de reforma de UI

Sub-projeto 4 da reforma visual do LinkGuard ([[ui-redesign-multi-subproject]] na memória de projeto),
primeira rodada do grupo "Rede" (Links, DHCP, DNS — decidido fatiar por domínio de navegação, mesma
agrupação já usada na nav lateral desde o sub-projeto 1). Links foi isolada em spec própria porque é
desproporcionalmente maior e mais complexa que DHCP/DNS (682 linhas contra 166 e 112), com modal de
CRUD, assistente de configuração 2-WAN, teste de estresse e painel de balanceamento embutidos.

Reaproveita os componentes do sistema de design já prontos dos sub-projetos 1-3: `Panel`, `Tag`
(via `StatusBadge`, que já usa `Tag` — sem mudança necessária ali).

## 2. Escopo

**Dentro — reskin puro, zero mudança de comportamento:**
- `web/src/pages/Links.tsx`: tabela principal de links, banner de sucesso, os 3 modais (criar/editar
  link, assistente mágico de 2 WAN, confirmar exclusão).
- `web/src/components/WanBalancing.tsx`: painel de balanceamento multi-WAN (banner de commit/confirm
  com contagem regressiva).
- `web/src/components/LinkStressTest.tsx`: painel de teste de estresse de link.
- Novo componente `web/src/components/ui/Modal.tsx` — extrai a casca (overlay, scroll, cabeçalho com
  título) hoje duplicada 3x como `<div className="fixed inset-0...">` dentro de `Links.tsx`.

**Fora de escopo:**
- Qualquer mudança de comportamento: chamadas de API, validação do assistente, lógica de
  balanceamento/stress-test permanecem exatamente como estão.
- DHCP e DNS (próxima rodada do grupo Rede, spec separado).
- Qualquer ajuste funcional que o usuário já ache incômodo no fluxo atual — explicitamente descartado
  nesta rodada (decisão tomada no brainstorming: "só reskin visual").

## 3. Componente novo: `ui/Modal.tsx`

```tsx
interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  size?: 'sm' | 'md' | 'lg';   // max-w-md / max-w-lg / max-w-2xl
  className?: string;          // para o visual especial do assistente (borda azul, gradiente)
}
```

Cuida de: overlay (`fixed inset-0 bg-black/60`), centralização, `max-h-[90vh] overflow-y-auto`,
cabeçalho com título (`border-b`). O assistente de 2 WAN mantém seu visual distinto (borda azul,
fundo em gradiente, ícone) via `className` — a casca compartilhada não impõe um único visual, só
resolve a duplicação estrutural (overlay/scroll/cabeçalho) que hoje está copiada 3 vezes.

Tamanhos mapeados das larguras atuais: modal de criar/editar usa `max-w-lg` → `size="md"`; modal de
confirmar exclusão usa `max-w-md` → `size="sm"`; assistente usa `max-w-2xl` → `size="lg"`.

## 4. Mapeamento de reskin por arquivo

| Arquivo | Elemento atual | Vira |
|---|---|---|
| `Links.tsx` | `<div className="card">` (tabela) | `<Panel title="Links WAN">` |
| `Links.tsx` | banner de sucesso (`div` verde solta) | mesmo padrão de card de aviso já usado em `InterfaceEdit.tsx` (`card border border-{cor}-500/30 bg-{cor}-500/10`) |
| `Links.tsx` | 3x `<div className="fixed inset-0...">` | `<Modal>` |
| `WanBalancing.tsx` | `<div className="card">` | `<Panel title="Balanceamento WAN">` (título já existe no componente, só muda o wrapper) |
| `LinkStressTest.tsx` | `<div className="card">` | `<Panel title="Teste de Estresse">` |
| `StatusBadge.tsx` | já usa `Tag` | sem mudança |

Nenhum novo campo de dado é exibido — este spec é puramente sobre o componente que envolve o dado
que já é mostrado hoje. (Não se aplica aqui a classe de bug encontrada na Fase 2 de Interfaces —
não há campo condicionalmente populado sendo adicionado à tela.)

## 5. Testes

Mesmo padrão já estabelecido: sem framework de teste unitário no frontend (decisão deliberada desde
o sub-projeto 1). Verificação por tarefa via `npm run build` (checagem de tipos + build de produção).
Verificação visual final: contra a API real do LinkGuard (local, com os links WAN reais já
configurados nesta máquina de dev, se houver, ou contra produção em modo leitura) — sem Playwright
disponível neste ambiente por ora, a confirmação visual final fica por conta de screenshot manual ou
validação direta pelo usuário após deploy, como já aconteceu nas últimas correções da Fase 2 de
Interfaces.
