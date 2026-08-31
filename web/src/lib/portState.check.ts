import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { ATIVIDADE_MIN, portIsAbnormal, portState } from './portState.ts';
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
// O LED DE ATIVIDADE TEM TRÊS ESTADOS, E O TERCEIRO É O QUE IMPORTA.
//
// `false` e `null` levam a leituras opostas: "ninguém está usando este cabo" e
// "não estou medindo este cabo". Confundi-las é o defeito que o alvo por
// domínio já pagou (#123), e num painel de portas ele reapareceria como um LED
// apagado afirmando silêncio que ninguém observou.
// ─────────────────────────────────────────────────────────────────────────────

{
  const parada = portState(iface({ carrier: true }), { rx: 0, tx: 0 });
  check(parada.activity === false, 'medido e sem tráfego: apagado, e isso é uma AFIRMAÇÃO');

  const semMedir = portState(iface({ carrier: true }));
  check(semMedir.activity === null, 'chamador que não mede não vira "parada"');

  const semAmostra = portState(iface({ carrier: true }), null);
  check(semAmostra.activity === null, 'coleta sem duas amostras não vira "parada"');

  check(semMedir.activity !== parada.activity, 'não medido e parado NÃO são o mesmo estado');
}

{
  const chiado = portState(iface({ carrier: true }), { rx: ATIVIDADE_MIN / 4, tx: 0 });
  check(chiado.activity === false, 'ARP e descoberta de vizinho não acendem o LED');

  const real = portState(iface({ carrier: true }), { rx: ATIVIDADE_MIN, tx: 0 });
  check(real.activity === true, 'tráfego no piso acende');

  const somado = portState(iface({ carrier: true }), { rx: ATIVIDADE_MIN / 2, tx: ATIVIDADE_MIN / 2 });
  check(somado.activity === true, 'o piso vale para rx + tx, não para cada direção');

  check(ATIVIDADE_MIN > 0, 'zero não serve de piso: o LED piscaria sempre e viraria enfeite');
}

{
  // VLAN não tem porta, e portanto não tem o que reportar — nem parada.
  check(portState(iface({ kind: 'vlan' }), { rx: 9e9, tx: 9e9 }).activity === null,
    'interface virtual não afirma atividade nem com taxa alta no mapa');
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
check(!/animate-(bounce|ping|spin)/.test(icone), 'nenhuma outra animação além do pisca');
check(icone.includes("activity === null"), 'o ícone trata "não medido" como estado próprio, não como apagado');
check(/rightBlinks\s*=\s*!degraded/.test(icone), 'erro no contador ganha do pisca de atividade: é o único estado acionável');

const painelSrc = painel;
check(painelSrc.includes('deriveRate'), 'a taxa vem da MESMA fórmula do resto do app, não de uma segunda conta');
check(painelSrc.includes("'/api/system/status'"), 'a atividade vem de contador medido, não de adivinhação');
check(/catch[\s\S]{0,220}setTaxas\(\{\}\)/.test(painelSrc), 'coleta que falha volta para "não medido", nunca para "parada"');

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
