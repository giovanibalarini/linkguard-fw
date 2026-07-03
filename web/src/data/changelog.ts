// Curated release history shown on the in-app "Novidades" (changelog) page.
// Keep newest first. Write user-facing bullets in plain language (no jargon) —
// the audience is home/prosumer admins, not developers.

export type ChangeType = 'feat' | 'fix' | 'security';

export interface ChangelogEntry {
  version: string;
  date: string; // ISO date (YYYY-MM-DD)
  title?: string;
  changes: { type: ChangeType; text: string }[];
}

export const CHANGELOG: ChangelogEntry[] = [
  {
    version: '1.0.57',
    date: '2026-07-03',
    title: 'Página de novidades',
    changes: [
      { type: 'feat', text: 'Nova página "Novidades" com o histórico de versões e o que mudou em cada uma.' },
    ],
  },
  {
    version: '1.0.56',
    date: '2026-07-03',
    title: 'Vigia: monitoramento e alertas de queda',
    changes: [
      { type: 'feat', text: 'Vigilância automática (sem configurar nada) do DHCP, DNS, firewall, das conexões WAN e do próprio LinkGuard.' },
      { type: 'feat', text: 'Painel "Saúde do sistema" no Dashboard: veja num relance se está tudo no ar.' },
      { type: 'feat', text: 'Avisos de queda e de recuperação no seu WhatsApp, sem encher o celular com repetições.' },
      { type: 'feat', text: 'Alerta também de disco cheio e quando o próprio serviço do LinkGuard cai.' },
      { type: 'fix', text: 'O teste de queda de link agora dispara o alerta corretamente (a queda simulada passou a notificar).' },
    ],
  },
  {
    version: '1.0.55',
    date: '2026-07-01',
    title: 'Correção do teste de queda',
    changes: [
      { type: 'fix', text: 'Corrigida a tela preta ao rodar o teste de queda de link (stress-test) na aba Links.' },
    ],
  },
  {
    version: '1.0.54',
    date: '2026-07-01',
    title: 'Tráfego por host e roteamento',
    changes: [
      { type: 'fix', text: 'O consumo de banda por host (aba Hosts) voltou a ser calculado.' },
      { type: 'feat', text: 'O LinkGuard garante o encaminhamento de pacotes (roteamento LAN↔internet) sozinho no boot.' },
      { type: 'feat', text: 'O instalador (.deb) passa a puxar as dependências automaticamente num servidor novo.' },
    ],
  },
  {
    version: '1.0.53',
    date: '2026-07-01',
    title: 'Segurança e teste de failover',
    changes: [
      { type: 'feat', text: 'Teste de failover sob demanda: derrube ou degrade uma WAN de propósito e veja o failover reagir, com restauração automática.' },
      { type: 'feat', text: 'O LinkGuard passou a ser dono do roteamento por WAN (steering), aplicado sozinho no boot.' },
      { type: 'security', text: 'Validação de entradas que chegam ao firewall/roteamento e verificação de integridade (SHA-256) das atualizações.' },
    ],
  },
];
