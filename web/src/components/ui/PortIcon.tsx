import type { PortState } from '../../lib/portState';

interface PortIconProps {
  state: PortState;
  /**
   * Texto acessível: o que esta porta está dizendo. Vem de fora, como no
   * IconButton. Omitir marca o desenho como DECORATIVO — é o caso certo
   * quando quem envolve o ícone já tem rótulo próprio, e repetir ali faria
   * o leitor de tela anunciar a mesma porta duas vezes.
   */
  label?: string;
  /**
   * Pisca os LEDs enquanto o `ethtool --identify` está piscando os de verdade.
   * É a ÚNICA animação daqui, e ela é honesta: existe um comando rodando na
   * placa naquele instante, e a tela está espelhando esse comando.
   */
  blink?: boolean;
  className?: string;
}

// Oito contatos, como na tomada de verdade. Em 20px eles leem como textura,
// não como oito linhas contáveis — que é exatamente o efeito de olhar um
// switch de perto.
const PIN_X = Array.from({ length: 8 }, (_, i) => 7.3 + i * (9.4 / 7));

/**
 * PortIcon desenha a tomada RJ45 da interface, com os dois LEDs do painel.
 *
 * Verde aceso = portadora no fio. Âmbar = link de pé com erro no contador.
 * Apagado = sem link. VLAN e bridge saem tracejadas e SEM LED: elas não têm
 * uma tomada atrás, e acender um LED nelas seria desenhar um cabo que não
 * existe.
 *
 * Os LEDs não piscam. Um LED de atividade exigiria taxa, o /api/interfaces
 * não devolve taxa nenhuma, e piscar sem medir é afirmar tráfego.
 */
export default function PortIcon({ state, label, blink = false, className = 'w-5 h-5' }: PortIconProps) {
  const decorative = !label;
  const { physical, link, degraded } = state;
  const bodyOpacity = physical ? (link ? 'opacity-90' : 'opacity-50') : 'opacity-40';
  const leftLed = link ? 'fill-emerald-400' : 'fill-gray-700';
  const rightLed = degraded ? 'fill-amber-400' : link ? 'fill-emerald-400' : 'fill-gray-700';

  return (
    <svg
      viewBox="0 0 24 24"
      className={`shrink-0 ${className}`}
      role={decorative ? undefined : 'img'}
      aria-hidden={decorative || undefined}
      aria-label={decorative ? undefined : label}
    >
      {!decorative && <title>{label}</title>}
      <g
        className={bodyOpacity}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinejoin="round"
        strokeDasharray={physical ? undefined : '2.5 2'}
      >
        {/* Espelho da tomada */}
        <rect x="2.6" y="4.6" width="18.8" height="14.8" rx="2" />
        {/* Boca do jack, com a fenda da trava embaixo */}
        <path d="M6.5 10.2 H17.5 V16 H14.2 V18 H9.8 V16 H6.5 Z" />
      </g>

      {/* Contatos */}
      <g className={physical ? 'opacity-60' : 'opacity-25'} stroke="currentColor" strokeWidth="0.7" strokeLinecap="round">
        {PIN_X.map((x) => (
          <line key={x} x1={x} y1="10.9" x2={x} y2="12.7" />
        ))}
      </g>

      {/* Os dois LEDs. O brilho é um círculo atrás, não um filtro: filtro de
          SVG não herda o tema e some no modo claro. */}
      {physical && (
        <g className={blink ? 'animate-pulse' : undefined}>
          {link && <circle cx="6.4" cy="7.4" r="2.6" className="fill-emerald-400 opacity-25" />}
          {link && <circle cx="17.6" cy="7.4" r="2.6" className={`${degraded ? 'fill-amber-400' : 'fill-emerald-400'} opacity-25`} />}
          <circle cx="6.4" cy="7.4" r="1.3" className={leftLed} />
          <circle cx="17.6" cy="7.4" r="1.3" className={rightLed} />
        </g>
      )}
    </svg>
  );
}
