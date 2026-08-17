import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

/**
 * Rede de segurança para erro de render.
 *
 * Sem isto, um único componente que lance derruba a árvore inteira e o
 * navegador fica com uma página em branco — e este painel é o único caminho de
 * clique para confirmar/reverter regra, self-update, DHCP/DNS e interfaces.
 * Tela branca num firewall é o administrador sem acesso à própria máquina.
 *
 * Duas decisões deliberadas neste arquivo:
 *
 *  1. Zero dependência além do React. Nada de axios, i18n, router ou contexto.
 *     A tela de último recurso não pode depender de nada que possa ser a causa
 *     da queda — inclusive de uma requisição que também falharia.
 *
 *  2. Estilo inline, não classe do Tailwind. Esta tela precisa continuar
 *     legível mesmo que a folha de estilo não tenha carregado ou que um upgrade
 *     de Tailwind renomeie utilitários debaixo dela. Ela nasceu junto com a
 *     migração para o Tailwind 4 justamente por isso.
 */

interface Props {
  children: ReactNode;
  /**
   * 'page' fica dentro do Layout: o menu e a faixa do confirmar-ou-reverte
   * continuam de pé, então dá para sair andando para outra tela.
   * 'app' é a borda externa: se caiu aqui, não sobrou navegação.
   */
  variant: 'app' | 'page';
}

interface State {
  error: Error | null;
  stack: string;
  copied: boolean;
}

const S = {
  wrap: {
    minHeight: '100%',
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'center',
    padding: '2rem 1rem',
    backgroundColor: '#030712',
    color: '#f3f4f6',
    fontFamily: "'Inter Variable', ui-sans-serif, system-ui, -apple-system, sans-serif",
  },
  card: {
    width: '100%',
    maxWidth: '46rem',
    backgroundColor: '#111827',
    border: '1px solid #1f2937',
    borderRadius: '0.75rem',
    padding: '1.5rem',
  },
  h1: { fontSize: '1.125rem', fontWeight: 600, margin: '0 0 0.75rem' },
  p: { fontSize: '0.875rem', lineHeight: 1.6, color: '#d1d5db', margin: '0 0 0.75rem' },
  calm: {
    fontSize: '0.875rem',
    lineHeight: 1.6,
    color: '#a7f3d0',
    backgroundColor: 'rgba(52, 211, 153, 0.1)',
    border: '1px solid rgba(52, 211, 153, 0.2)',
    borderRadius: '0.5rem',
    padding: '0.75rem',
    margin: '0 0 1rem',
  },
  row: { display: 'flex', flexWrap: 'wrap' as const, gap: '0.5rem', margin: '0 0 1.25rem' },
  btn: {
    appearance: 'none' as const,
    border: '1px solid #374151',
    backgroundColor: '#1f2937',
    color: '#e5e7eb',
    borderRadius: '0.5rem',
    padding: '0.5rem 1rem',
    fontSize: '0.875rem',
    fontWeight: 500,
    cursor: 'pointer',
  },
  btnPrimary: {
    appearance: 'none' as const,
    border: '1px solid #2563eb',
    backgroundColor: '#2563eb',
    color: '#fff',
    borderRadius: '0.5rem',
    padding: '0.5rem 1rem',
    fontSize: '0.875rem',
    fontWeight: 500,
    cursor: 'pointer',
  },
  h2: {
    fontSize: '0.75rem',
    fontWeight: 600,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.05em',
    color: '#9ca3af',
    margin: '0 0 0.5rem',
  },
  pre: {
    backgroundColor: '#030712',
    border: '1px solid #1f2937',
    borderRadius: '0.5rem',
    padding: '0.75rem',
    fontSize: '0.75rem',
    lineHeight: 1.5,
    color: '#d1d5db',
    fontFamily: "'JetBrains Mono Variable', ui-monospace, SFMono-Regular, Menlo, monospace",
    overflowX: 'auto' as const,
    whiteSpace: 'pre' as const,
    margin: '0 0 1.25rem',
  },
  detailPre: {
    backgroundColor: '#030712',
    border: '1px solid #1f2937',
    borderRadius: '0.5rem',
    padding: '0.75rem',
    fontSize: '0.6875rem',
    lineHeight: 1.5,
    color: '#9ca3af',
    fontFamily: "'JetBrains Mono Variable', ui-monospace, SFMono-Regular, Menlo, monospace",
    overflowX: 'auto' as const,
    maxHeight: '14rem',
    overflowY: 'auto' as const,
    margin: '0.5rem 0 0',
  },
};

/** O que dá para fazer por SSH quando o painel não é mais uma opção. */
const SSH_STEPS = `ssh <admin>@<ip-do-firewall>
systemctl status linkguard-fw
journalctl -u linkguard-fw -n 100 --no-pager
systemctl restart linkguard-fw   # só o painel/serviço; não mexe nas regras já aplicadas`;

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, stack: '', copied: false };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Deixa o registro no console do navegador — é o que o admin consegue
    // copiar sem precisar de mais nenhuma ferramenta.
    console.error('[LinkGuard] erro de render capturado pelo ErrorBoundary', error, info);
    this.setState({ stack: info.componentStack ?? '' });
  }

  private details(): string {
    const { error, stack } = this.state;
    return [
      `LinkGuard FW — erro de painel`,
      `quando: ${new Date().toISOString()}`,
      `tela:   ${window.location.pathname}`,
      `erro:   ${error?.name}: ${error?.message}`,
      ``,
      `pilha do componente:${stack || ' (indisponível)'}`,
      ``,
      `pilha do erro:`,
      error?.stack ?? '(indisponível)',
    ].join('\n');
  }

  private copy = () => {
    const text = this.details();
    const done = () => {
      this.setState({ copied: true });
      window.setTimeout(() => this.setState({ copied: false }), 2000);
    };
    // clipboard só existe em contexto seguro; sem ele, cai no seletor de texto.
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).then(done, () => window.prompt('Copie os detalhes:', text));
    } else {
      window.prompt('Copie os detalhes:', text);
    }
  };

  render() {
    const { error, copied } = this.state;
    if (!error) return this.props.children;

    const isPage = this.props.variant === 'page';

    return (
      <div style={S.wrap} role="alert">
        <div style={S.card}>
          <h1 style={S.h1}>
            {isPage ? 'Esta tela do painel travou.' : 'O painel travou.'}
          </h1>

          <p style={S.p}>
            Um erro de programação interrompeu o desenho{isPage ? ' desta tela' : ' da interface'}.
            Não é uma falha de rede nem de configuração — e não foi causado pelo que você acabou de clicar.
          </p>

          <div style={S.calm}>
            <strong>O firewall continua rodando.</strong> Regras, NAT, roteamento e failover são
            aplicados pelo serviço <code>linkguard-fw</code>, não por esta tela. Nada foi desfeito e
            nada parou de valer por causa deste erro.
            <br />
            <br />
            <strong>Se você tinha uma mudança aguardando confirmação, ela não ficou presa:</strong> o
            serviço reverte sozinho ao fim dos 90 segundos quando ninguém confirma. Não fazer nada é
            o caminho seguro — a rede volta ao estado anterior por conta própria.
          </div>

          <div style={S.row}>
            <button style={S.btnPrimary} onClick={() => this.setState({ error: null, stack: '' })}>
              Tentar desenhar de novo
            </button>
            <button style={S.btn} onClick={() => window.location.reload()}>
              Recarregar o painel
            </button>
            {isPage && (
              <button style={S.btn} onClick={() => window.location.assign('/')}>
                Ir para o Painel
              </button>
            )}
            <button style={S.btn} onClick={this.copy}>
              {copied ? 'Copiado!' : 'Copiar detalhes do erro'}
            </button>
          </div>

          {isPage && (
            <p style={S.p}>
              O menu lateral e a faixa de confirmar-ou-reverter continuam funcionando: dá para ir
              para outra tela por ali sem recarregar nada.
            </p>
          )}

          <h2 style={S.h2}>Se o painel não voltar</h2>
          <pre style={S.pre}>{SSH_STEPS}</pre>

          <h2 style={S.h2}>Detalhes técnicos</h2>
          <p style={{ ...S.p, margin: 0 }}>
            Leve isto para o relatório do problema — sozinho, ele costuma bastar para achar a causa.
          </p>
          <pre style={S.detailPre}>{this.details()}</pre>
        </div>
      </div>
    );
  }
}
