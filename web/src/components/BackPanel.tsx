import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import client from '../api/client';
import { useI18n } from '../i18n';
import PortIcon from './ui/PortIcon';
import { portState } from '../lib/portState';
import { deriveRate, type InterfaceRate, type RateCounter } from '../lib/interfaceRates';
import type { IfaceView, SystemMetrics } from '../types';

interface BackPanelProps {
  ifaces: IfaceView[];
  identifying: string | null;
  onIdentify: (name: string) => void;
}

// A cor da tarja embaixo da porta é o papel que o BACKEND já calculou. A tela
// não rederiva papel (spec §5.1) — ela só pinta o que recebeu.
const ROLE_ACCENT: Record<string, string> = {
  wan: 'bg-emerald-500/70',
  lan: 'bg-blue-500/70',
  unassigned: 'bg-gray-700',
};

/**
 * BackPanel desenha as portas físicas como elas são na traseira da máquina.
 *
 * A aba já se chamava "Painel traseiro" e mostrava uma lista de texto. Um
 * painel que se parece com o painel serve a uma coisa que lista nenhuma faz:
 * o admin que está com a máquina na frente dele compara o que vê na tela com
 * o que vê no metal, e a porta certa é a que tem os mesmos LEDs acesos.
 *
 * Só interface FÍSICA entra. VLAN e bridge continuam na lista abaixo, porque
 * não têm tomada atrás — desenhá-las aqui seria inventar hardware.
 */
// useTaxas coleta os contadores e devolve bits/s por interface.
//
// Uma interface só aparece no mapa depois da SEGUNDA amostra — `deriveRate`
// devolve null com uma só, e é isso que mantém o LED de atividade honesto nos
// primeiros segundos: ausente do mapa significa "não medido", nunca "parada".
// Se a coleta falhar, o mapa é zerado pelo mesmo motivo.
function useTaxas(): Record<string, InterfaceRate> {
  const [taxas, setTaxas] = useState<Record<string, InterfaceRate>>({});
  const anterior = useRef<Record<string, RateCounter>>({});

  useEffect(() => {
    let vivo = true;
    const ler = async () => {
      try {
        const { data } = await client.get<SystemMetrics>('/api/system/status');
        if (!vivo) return;
        const agora = Date.now();
        const novas: Record<string, InterfaceRate> = {};
        for (const m of data.interfaces ?? []) {
          const taxa = deriveRate(anterior.current[m.name], m, agora);
          if (taxa) novas[m.name] = taxa;
          anterior.current[m.name] = { ts: agora, rx: m.rx_bytes, tx: m.tx_bytes };
        }
        setTaxas(novas);
      } catch {
        // Sem medição não se afirma silêncio: o mapa esvazia e todo LED de
        // atividade volta para "não medido".
        if (vivo) {
          anterior.current = {};
          setTaxas({});
        }
      }
    };
    ler();
    const t = setInterval(ler, 3000);
    return () => {
      vivo = false;
      clearInterval(t);
    };
  }, []);

  return taxas;
}

export default function BackPanel({ ifaces, identifying, onIdentify }: BackPanelProps) {
  const { t } = useI18n();
  const taxas = useTaxas();
  const ports = ifaces.filter((i) => i.kind === 'physical');
  if (ports.length === 0) return null;

  return (
    <div className="rounded-xl border border-gray-800 bg-gradient-to-b from-gray-950 to-black/60 p-4">
      <div className="flex flex-wrap gap-2.5">
        {ports.map((i) => {
          const s = portState(i, taxas[i.name] ?? null);
          const ipv4 = i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr;
          const accent = ROLE_ACCENT[i.role] ?? ROLE_ACCENT.unassigned;
          const blinking = identifying === i.name;
          return (
            <div key={i.name} className="group relative">
              <Link
                to={`/interfaces/${encodeURIComponent(i.name)}/edit`}
                aria-label={t('net.if.openSettings', { name: i.alias || i.name })}
                className={`flex w-[76px] flex-col items-center gap-1 rounded-lg border px-2 py-2.5 transition-all
                  ${blinking ? 'border-blue-500/60 bg-blue-500/10' : 'border-gray-800 bg-gray-900/40 hover:border-gray-600 hover:bg-gray-800/60'}
                  focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500`}
              >
                <PortIcon state={s} label={''} blink={blinking} className="w-9 h-9 text-gray-400" />
                <span className="w-full truncate text-center font-mono text-[10px] text-gray-300">
                  {i.name}
                </span>
                <span className={`h-1 w-8 rounded-full ${accent}`} />
              </Link>

              {/* Etiqueta no hover: o que a porta é, sem ocupar o painel o
                  tempo todo. `pointer-events-none` para ela não engolir o
                  clique que a levou até ali. */}
              <div className="pointer-events-none absolute left-1/2 top-full z-10 mt-1 hidden -translate-x-1/2 whitespace-nowrap rounded-lg border border-gray-700 bg-gray-950 px-2.5 py-1.5 text-[11px] shadow-xl group-hover:block">
                <div className="text-white">{i.alias || i.name}</div>
                <div className="font-mono text-gray-400">{ipv4 ?? t('net.if.port.noAddress')}</div>
                <div className={s.link ? 'text-emerald-400' : 'text-gray-500'}>
                  {s.degraded
                    ? t('net.if.port.degraded')
                    : s.link
                      ? t('net.if.port.up')
                      : t('net.if.port.down')}
                </div>
                {s.link && !s.degraded && (
                  <div className="text-gray-500">
                    {s.activity === null
                      ? t('net.if.port.act.unknown')
                      : s.activity
                        ? t('net.if.port.act.busy')
                        : t('net.if.port.act.idle')}
                  </div>
                )}
              </div>

              {/* Piscar a porta é do lado do metal: chama ethtool --identify.
                  Fora do <Link> de propósito — botão dentro de âncora é HTML
                  inválido, e o clique de um roubaria o do outro. */}
              <button
                type="button"
                onClick={() => onIdentify(i.name)}
                disabled={blinking}
                className="mt-1 w-full text-center text-[10px] text-gray-600 transition-colors hover:text-blue-400 disabled:text-blue-400"
              >
                {blinking ? t('net.if.blinking') : t('net.if.identify')}
              </button>
            </div>
          );
        })}
      </div>

      <p className="mt-3 text-[11px] text-gray-600">{t('net.if.panel.hint')}</p>
    </div>
  );
}
