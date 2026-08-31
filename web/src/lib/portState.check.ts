import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { portIsAbnormal, portState } from './portState.ts';
import type { IfaceKind, IfaceView } from '../types/index.ts';

let n = 0;
const check = (c: unknown, m: string) => { assert.ok(c, m); n++; };
const ler = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');

const iface = (over: {
  kind?: IfaceKind;
  carrier?: boolean;
  rx?: number;
  tx?: number;
}): IfaceView => ({
  name: 'enp1s0',
  kind: over.kind ?? 'physical',
  addr_mode: 'dhcp',
  role: 'wan',
  managed: true,
  live: {
    carrier: over.carrier ?? true,
    rx_errors: over.rx ?? 0,
    tx_errors: over.tx ?? 0,
    rx_dropped: 0,
    tx_dropped: 0,
    system: false,
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// OS LEDS SÓ PODEM DIZER O QUE O KERNEL DISSE.
//
// O desenho do jack não tem o que testar; a leitura dos contadores tem. Cada
// asserção aqui corresponde a uma forma de o painel mentir sobre o fio.
// ─────────────────────────────────────────────────────────────────────────────

{
  const s = portState(iface({ carrier: true }));
  check(s.physical && s.link && !s.degraded, 'porta com portadora e sem erro: os dois LEDs verdes');
}

{
  const s = portState(iface({ carrier: false }));
  check(s.physical && !s.link, 'sem portadora, LED de link apagado');
  check(!s.degraded, 'sem portadora o âmbar NÃO acende: o problema já é o link, e dois avisos escondem qual importa');
}

{
  check(portState(iface({ carrier: true, rx: 3 })).degraded, 'erro de recepção acende o âmbar');
  check(portState(iface({ carrier: true, tx: 3 })).degraded, 'erro de transmissão TAMBÉM acende — era o buraco da visão geral antiga');
}

{
  // Descarte não é erro. Sob carga ele acontece em link saudável, e um âmbar
  // que acende sozinho ensina o admin a ignorar o painel.
  const comDescarte = iface({ carrier: true });
  comDescarte.live.rx_dropped = 9999;
  comDescarte.live.tx_dropped = 9999;
  check(!portState(comDescarte).degraded, 'descarte não acende LED: acontece em operação normal');
}

{
  for (const kind of ['vlan', 'bridge'] as IfaceKind[]) {
    const s = portState(iface({ kind }));
    check(!s.physical, `${kind} não é porta física`);
    check(!s.link && !s.degraded, `${kind} não acende LED: não existe tomada atrás dela`);
  }
  check(!portIsAbnormal(iface({ kind: 'vlan', carrier: false })), 'VLAN sem portadora não é anomalia de porta — ela não tem porta');
}

{
  check(portIsAbnormal(iface({ carrier: false })), 'link caído é anomalia');
  check(portIsAbnormal(iface({ carrier: true, tx: 1 })), 'erro só na transmissão é anomalia');
  check(!portIsAbnormal(iface({ carrier: true })), 'porta saudável não é anomalia');
}

// ─────────────────────────────────────────────────────────────────────────────
// FIAÇÃO. Um estado que ninguém liga na tela não adianta existir.
// ─────────────────────────────────────────────────────────────────────────────

const interfaces = ler('../pages/Interfaces.tsx');
const painel = ler('../components/BackPanel.tsx');
const icone = ler('../components/ui/PortIcon.tsx');
const rede = ler('../i18n/strings/rede.yaml');

check(interfaces.includes('<PortIcon'), 'a tela de interfaces desenha o jack');
check(interfaces.includes('<BackPanel'), 'a visão geral monta o painel traseiro');
check(interfaces.includes('portIsAbnormal(i)'), 'as duas abas usam o MESMO critério de anomalia');
check(!/!i\.live\.carrier \|\| i\.live\.rx_errors/.test(interfaces), 'nenhuma cópia solta do critério antigo sobrou');

check(interfaces.includes('openSettings'), 'clicar na interface entra nas configurações');
check(/kind === 'physical'\s*\?\s*`\/interfaces\//.test(interfaces), 'só interface física navega: a tela de edição recusa VLAN e bridge');
check(interfaces.includes("closest('a,button')"), 'o clique da linha não rouba o clique de quem já é clicável');

check(painel.includes("i.kind === 'physical'"), 'o painel traseiro só desenha porta que existe no metal');
check(painel.includes('onIdentify'), 'o painel pisca a porta de verdade pelo ethtool');
check(icone.includes('animate-pulse'), 'os LEDs piscam durante o identify');
check(!/animate-(bounce|ping|spin)/.test(icone), 'nenhuma outra animação: LED que se mexe sem comando atrás afirma tráfego não medido');

for (const chave of [
  'net.if.port.up',
  'net.if.port.down',
  'net.if.port.degraded',
  'net.if.port.virtual',
  'net.if.port.noAddress',
  'net.if.openSettings',
  'net.if.panel.hint',
]) {
  check(rede.includes(`${chave}:`), `a chave ${chave} existe no YAML`);
  check(interfaces.includes(chave) || painel.includes(chave), `a chave ${chave} é usada na tela`);
}
check(!/["'>][A-Za-zÀ-ú][^<>{}]*porta[^<>{}]*["'<]/.test(painel.replace(/\/\*[\s\S]*?\*\//g, '')), 'nenhum texto cravado no TSX do painel');

console.log(`portState.check: ${n} asserções OK`);
