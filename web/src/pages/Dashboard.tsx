import { useCallback, useEffect, useMemo, useState } from 'react';
import { Check, LayoutGrid, Plus, RotateCcw, Sliders } from 'lucide-react';
import client from '../api/client';
import Modal from '../components/ui/Modal';
import WidgetGrid, { useNarrowScreen } from '../components/WidgetGrid';
import WidgetView from '../components/widgets/registry';
import { DISMISS_KEY, useOnboardingSteps } from '../components/GettingStarted';
import { nextFreeSpot, normalize } from '../lib/grid';
import type { LayoutItem } from '../lib/grid';
import {
  DEFAULT_LAYOUT,
  WIDGET_CATALOG,
  keepRenderable,
  widgetMinSize,
  widgetSpec,
  widgetTitle,
} from '../lib/widgets';
import { useI18n } from '../i18n';

// O painel que cada admin monta (spec §4).
//
// O que esta tela deixou de ser: uma lista fixa em que "Primeiros passos"
// ocupava os primeiros 60% da altura — parado em 5 de 6 há meses, por causa do
// usuário padrão — e a informação operacional só começava abaixo da dobra. Numa
// máquina que roda há meses, isso é tratar quem a usa como quem acabou de
// instalar.
//
// Quem decide o que aparece é o backend: `GET /api/dashboard/layout` devolve o
// layout DESTE usuário e, em `available`, o catálogo que ELE pode ver. O painel
// não recalcula permissão — uma segunda fonte de verdade fica livre para
// divergir da primeira, e o sintoma seria um widget oferecido no catálogo que
// só sabe mostrar um 403.

interface LayoutResponse {
  items: LayoutItem[];
  available: string[];
}

type SaveState = 'idle' | 'saving' | 'saved' | 'error';

export default function Dashboard() {
  const { t } = useI18n();
  const narrow = useNarrowScreen();

  const [layout, setLayout] = useState<LayoutItem[] | null>(null);
  const [available, setAvailable] = useState<string[]>([]);
  const [loadFailed, setLoadFailed] = useState(false);
  const [editing, setEditing] = useState(false);
  const [catalogOpen, setCatalogOpen] = useState(false);
  const [saveState, setSaveState] = useState<SaveState>('idle');

  const onboarding = useOnboardingSteps();
  const [onboardingDismissed, setOnboardingDismissed] = useState(
    () => localStorage.getItem(DISMISS_KEY) === '1',
  );

  const availableSet = useMemo(() => new Set(available), [available]);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { data } = await client.get<LayoutResponse>('/api/dashboard/layout');
        if (!alive) return;
        setAvailable(data.available ?? []);
        setLayout(normalize(data.items ?? []));
        setLoadFailed(false);
      } catch {
        if (!alive) return;
        // Layout de fábrica é melhor que uma tela em branco com uma mensagem de
        // erro (spec §6): o operador ainda vê o estado da máquina, que é o que
        // ele veio ver. O aviso fica discreto, e nada é gravado por cima do que
        // ele tinha salvo.
        setAvailable(WIDGET_CATALOG.map((w) => w.name));
        setLayout(normalize(DEFAULT_LAYOUT));
        setLoadFailed(true);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  /**
   * O que a grade desenha.
   *
   * "Primeiros passos" **sai do painel quando os 6 passos terminam** (spec
   * §4.5): numa instalação nova ele aparece no topo, como hoje; numa máquina
   * que já foi configurada ele não entra, e some de um layout salvo que o
   * contenha. Ele não está no layout de fábrica de propósito.
   */
  const items = useMemo(() => {
    const base = keepRenderable(layout ?? [], availableSet);
    const mostrarOnboarding = onboarding.ready && !onboarding.allDone && !onboardingDismissed;

    if (!mostrarOnboarding) {
      return normalize(base.filter((it) => it.widget !== 'onboarding'));
    }
    if (base.some((it) => it.widget === 'onboarding')) return normalize(base);

    const spec = widgetSpec('onboarding');
    const novo: LayoutItem = {
      widget: 'onboarding',
      x: 0,
      y: 0,
      w: spec?.defaultW ?? 12,
      h: spec?.defaultH ?? 5,
    };
    // Entra como "quem invadiu": ganha o topo, e o resto do painel desce em
    // cascata em vez de ficar por baixo dele.
    return normalize([novo, ...base], novo);
  }, [layout, availableSet, onboarding.ready, onboarding.allDone, onboardingDismissed]);

  const save = useCallback(async (next: LayoutItem[]) => {
    setSaveState('saving');
    try {
      const { data } = await client.put<LayoutResponse>('/api/dashboard/layout', { items: next });
      setAvailable(data.available ?? []);
      setSaveState('saved');
    } catch {
      setSaveState('error');
    }
  }, []);

  /**
   * Grava a cada gesto concluído, e não num botão "Salvar".
   *
   * Um painel que só grava quando o operador se lembra de apertar um botão é um
   * painel que ele perde ao fechar a aba — e o projeto já tem a decisão tomada
   * para o mesmo problema em DHCP/DNS: salvar aplica.
   */
  const aplicar = useCallback(
    (next: LayoutItem[]) => {
      setLayout(next);
      void save(next);
    },
    [save],
  );

  const remover = useCallback(
    (widget: string) => {
      if (widget === 'onboarding') {
        // Tirar "Primeiros passos" é o mesmo gesto que o X antigo do cartão: ele
        // não volta sozinho na próxima abertura.
        localStorage.setItem(DISMISS_KEY, '1');
        setOnboardingDismissed(true);
      }
      aplicar(normalize(items.filter((it) => it.widget !== widget)));
    },
    [items, aplicar],
  );

  const adicionar = useCallback(
    (widget: string) => {
      const spec = widgetSpec(widget);
      if (!spec) return;
      if (widget === 'onboarding') {
        localStorage.removeItem(DISMISS_KEY);
        setOnboardingDismissed(false);
      }
      const spot = nextFreeSpot(items, spec.defaultW, spec.defaultH);
      aplicar(
        normalize([...items, { widget, x: spot.x, y: spot.y, w: spec.defaultW, h: spec.defaultH }]),
      );
      setCatalogOpen(false);
    },
    [items, aplicar],
  );

  const restaurarPadrao = useCallback(async () => {
    setSaveState('saving');
    try {
      const { data } = await client.delete<LayoutResponse>('/api/dashboard/layout');
      setAvailable(data.available ?? []);
      setLayout(normalize(data.items ?? []));
      setSaveState('saved');
    } catch {
      setSaveState('error');
    }
  }, []);

  // O catálogo oferece só o que este usuário pode ver e ainda não tem no
  // painel. "Primeiros passos" não é oferecido depois dos 6 passos concluídos:
  // seria oferecer um widget que já não tem o que mostrar.
  const paraAdicionar = WIDGET_CATALOG.filter(
    (w) =>
      availableSet.has(w.name) &&
      !items.some((it) => it.widget === w.name) &&
      !(w.name === 'onboarding' && onboarding.allDone),
  );

  if (layout === null) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="animate-pulse text-gray-500">Carregando…</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">{t('dashboard.title')}</h1>
          <p className="mt-0.5 text-sm text-gray-500">
            {editing ? 'Arraste para mover, use o canto para redimensionar.' : t('dashboard.subtitle')}
          </p>
        </div>

        {/* Em tela estreita não há edição: o layout é uma coluna na ordem que o
            admin definiu no desktop, e não existe um segundo layout para
            manter (spec §4.4). Oferecer alças aqui seria oferecer um gesto que
            não muda nada. */}
        {!narrow && (
          <div className="flex flex-wrap items-center gap-2">
            {saveState === 'saving' && <span className="text-xs text-gray-500">salvando…</span>}
            {saveState === 'saved' && <span className="text-xs text-gray-600">painel salvo</span>}
            {saveState === 'error' && <span className="text-xs text-crit">não consegui salvar o painel</span>}

            {editing && (
              <>
                <button
                  type="button"
                  data-testid="add-widget"
                  onClick={() => setCatalogOpen(true)}
                  className="btn-secondary inline-flex items-center gap-1.5 py-1.5 text-sm"
                >
                  <Plus className="h-4 w-4" /> Adicionar widget
                </button>
                <button
                  type="button"
                  data-testid="restore-default"
                  onClick={restaurarPadrao}
                  title="Volta ao painel de fábrica"
                  className="btn-secondary inline-flex items-center gap-1.5 py-1.5 text-sm"
                >
                  <RotateCcw className="h-4 w-4" /> Restaurar padrão
                </button>
              </>
            )}

            <button
              type="button"
              data-testid="toggle-edit"
              onClick={() => setEditing((v) => !v)}
              className={`${editing ? 'btn-primary' : 'btn-secondary'} inline-flex items-center gap-1.5 py-1.5 text-sm`}
            >
              {editing ? (
                <>
                  <Check className="h-4 w-4" /> Concluir
                </>
              ) : (
                <>
                  <Sliders className="h-4 w-4" /> Personalizar
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {loadFailed && (
        <div className="rounded-xl border border-warn-border bg-warn-bg px-4 py-2.5 text-sm text-warn">
          Não consegui ler o seu painel salvo. Isto aqui é o layout de fábrica — nada do que você montou foi perdido.
        </div>
      )}

      {items.length === 0 ? (
        <div className="card flex flex-col items-center gap-3 py-10 text-center">
          <LayoutGrid className="h-8 w-8 text-gray-600" />
          <div>
            <p className="text-white">Seu painel está vazio.</p>
            <p className="mt-0.5 text-sm text-gray-500">
              Escolha os widgets que te interessam — ou volte ao painel de fábrica.
            </p>
          </div>
          {!narrow && (
            <div className="flex flex-wrap justify-center gap-2">
              <button
                type="button"
                data-testid="add-widget-empty"
                onClick={() => {
                  setEditing(true);
                  setCatalogOpen(true);
                }}
                className="btn-primary inline-flex items-center gap-1.5 py-1.5 text-sm"
              >
                <Plus className="h-4 w-4" /> Adicionar widget
              </button>
              <button type="button" onClick={restaurarPadrao} className="btn-secondary py-1.5 text-sm">
                Restaurar padrão
              </button>
            </div>
          )}
        </div>
      ) : (
        <WidgetGrid
          items={items}
          editing={editing}
          onChange={aplicar}
          onRemove={remover}
          titleOf={widgetTitle}
          minSizeOf={widgetMinSize}
          renderItem={(item) => <WidgetView item={item} onSelfRemove={() => remover(item.widget)} />}
        />
      )}

      <Modal
        open={catalogOpen}
        onClose={() => setCatalogOpen(false)}
        closeOnBackdropClick
        title="Adicionar widget"
        className="rounded-xl border border-gray-800 bg-gray-900"
      >
        <div className="space-y-2 p-4">
          {paraAdicionar.length === 0 ? (
            <p className="py-2 text-sm text-gray-500">
              Todos os widgets disponíveis para você já estão no painel.
            </p>
          ) : (
            paraAdicionar.map((w) => (
              <button
                key={w.name}
                type="button"
                data-testid={`add-${w.name}`}
                onClick={() => adicionar(w.name)}
                className="flex w-full items-start gap-3 rounded-lg border border-gray-800 bg-gray-800/40 p-3 text-left transition-colors hover:border-blue-500/40 hover:bg-gray-800"
              >
                <Plus className="mt-0.5 h-4 w-4 shrink-0 text-blue-400" />
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-white">{w.title}</span>
                  <span className="block text-xs text-gray-500">{w.description}</span>
                </span>
              </button>
            ))
          )}
        </div>
      </Modal>
    </div>
  );
}
