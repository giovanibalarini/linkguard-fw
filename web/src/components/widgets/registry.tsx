import GettingStarted from '../GettingStarted';
import Recipes from '../Recipes';
import SystemHealth from '../SystemHealth';
import InterfaceTrafficWidget from './InterfaceTrafficWidget';
import LanHostsWidget from './LanHostsWidget';
import OpenAlertsWidget from './OpenAlertsWidget';
import SystemResourcesWidget from './SystemResourcesWidget';
import TopTalkersWidget from './TopTalkersWidget';
import WanLinksWidget from './WanLinksWidget';
import { WidgetNote } from './WidgetCard';
import { GRID_GAP, ROW_HEIGHT } from '../WidgetGrid';
import type { LayoutItem } from '../../lib/grid';

// De nome de widget para componente. Este arquivo é a única ponte entre o
// catálogo (`lib/widgets.ts`, sem JSX para poder ser conferido por asserção) e
// o que aparece na tela.
//
// Três widgets reusam componentes que já existiam e que já rodam em produção —
// "Saúde do sistema", "Primeiros passos" e "O que você quer fazer". Eles trazem
// o próprio cartão, então entram na célula inteiros, sem uma segunda moldura em
// volta. Reescrevê-los para caber numa moldura nova seria trocar código testado
// por código novo sem ganho nenhum para o operador.

/** Altura em pixels de uma célula de `h` linhas, incluindo os vãos internos. */
function alturaDaCelula(h: number): number {
  return h * ROW_HEIGHT + (h - 1) * GRID_GAP;
}

/**
 * O que sobra da célula para a área de plotagem do gráfico, depois do cartão
 * (padding) e do cabeçalho com o nome da interface, os picos e o linear/log.
 */
const CROMO_DO_GRAFICO = 118;

export default function WidgetView({
  item,
  onSelfRemove,
}: {
  item: LayoutItem;
  /** O widget que já tinha o próprio "ocultar" usa isto para virar remoção. */
  onSelfRemove: () => void;
}) {
  switch (item.widget) {
    case 'system_health':
      return <SystemHealth />;
    case 'wan_links':
      return <WanLinksWidget />;
    case 'interface_traffic':
      return <InterfaceTrafficWidget height={Math.max(120, alturaDaCelula(item.h) - CROMO_DO_GRAFICO)} />;
    case 'top_talkers':
      return <TopTalkersWidget />;
    case 'open_alerts':
      return <OpenAlertsWidget />;
    case 'system_resources':
      return <SystemResourcesWidget />;
    case 'lan_hosts':
      return <LanHostsWidget />;
    case 'onboarding':
      return <GettingStarted onDismiss={onSelfRemove} />;
    case 'quick_actions':
      return <Recipes onDismiss={onSelfRemove} />;
    default:
      // Não deveria chegar aqui: `keepRenderable` já descarta o desconhecido
      // item a item. Se chegar, o painel diz o que houve em vez de quebrar.
      return (
        <div className="card h-full">
          <WidgetNote>Widget desconhecido: <span className="font-mono">{item.widget}</span></WidgetNote>
        </div>
      );
  }
}
