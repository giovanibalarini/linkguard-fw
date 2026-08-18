// O catálogo de serviços: porta com nome, para quem não decora número.
//
// POR QUE ISTO EXISTE. Criar uma regra exigia saber que "área de trabalho
// remota" é 3389 e que "compartilhamento de arquivos do Windows" é 445 — e essa
// é a parte que manda o admin abrir uma busca no navegador no meio da tarefa.
//
// A lista é curta de propósito. Ela não tenta ser /etc/services (que tem
// milhares de entradas, quase todas irrelevantes numa LAN e várias com nomes
// que só confundem): são os serviços que aparecem de verdade numa rede
// doméstica ou de escritório pequeno, que é o público deste produto.
//
// A busca casa pelo NOME, pela DESCRIÇÃO e pela PORTA, porque as três são
// formas legítimas de procurar: quem sabe "3389" digita 3389, quem não sabe
// digita "remoto".

export interface Service {
  /** Sigla conhecida — o que aparece em negrito na lista. */
  name: string;
  /** O que ele faz, em português claro. É por aqui que a busca salva quem não sabe a sigla. */
  what: string;
  port: string;
  proto: 'tcp' | 'udp';
  /** Termos extras de busca: como a pessoa chamaria a coisa. */
  aka?: string[];
}

export const SERVICES: Service[] = [
  { name: 'HTTP', what: 'sites sem criptografia', port: '80', proto: 'tcp', aka: ['site', 'web'] },
  { name: 'HTTPS', what: 'sites (o normal da internet)', port: '443', proto: 'tcp', aka: ['site', 'web', 'seguro'] },
  { name: 'DNS', what: 'tradução de nomes de site', port: '53', proto: 'udp', aka: ['nome', 'resolucao'] },
  { name: 'DNS (TCP)', what: 'tradução de nomes, transferência de zona', port: '53', proto: 'tcp' },
  { name: 'SSH', what: 'terminal remoto', port: '22', proto: 'tcp', aka: ['terminal', 'remoto', 'shell'] },
  { name: 'RDP', what: 'área de trabalho remota do Windows', port: '3389', proto: 'tcp', aka: ['remoto', 'desktop', 'windows'] },
  { name: 'VNC', what: 'acesso remoto à tela', port: '5900', proto: 'tcp', aka: ['remoto', 'tela'] },
  { name: 'SMB', what: 'compartilhamento de arquivos do Windows', port: '445', proto: 'tcp', aka: ['arquivo', 'rede', 'compartilhamento', 'samba'] },
  { name: 'SMTP', what: 'envio de e-mail', port: '25', proto: 'tcp', aka: ['email', 'correio'] },
  { name: 'SMTP (envio)', what: 'envio de e-mail autenticado', port: '587', proto: 'tcp', aka: ['email'] },
  { name: 'IMAP', what: 'leitura de e-mail', port: '993', proto: 'tcp', aka: ['email', 'correio'] },
  { name: 'FTP', what: 'transferência de arquivos antiga', port: '21', proto: 'tcp', aka: ['arquivo'] },
  { name: 'NTP', what: 'relógio da rede', port: '123', proto: 'udp', aka: ['hora', 'relogio', 'tempo'] },
  { name: 'DHCP', what: 'distribuição de IP', port: '67', proto: 'udp', aka: ['ip', 'endereco'] },
  { name: 'MySQL', what: 'banco de dados MySQL/MariaDB', port: '3306', proto: 'tcp', aka: ['banco', 'database'] },
  { name: 'PostgreSQL', what: 'banco de dados PostgreSQL', port: '5432', proto: 'tcp', aka: ['banco', 'database'] },
  { name: 'Redis', what: 'cache Redis', port: '6379', proto: 'tcp', aka: ['banco', 'cache'] },
  { name: 'RTMP', what: 'transmissão de vídeo ao vivo', port: '1935', proto: 'tcp', aka: ['video', 'live', 'stream'] },
  { name: 'Impressão', what: 'impressora de rede (IPP)', port: '631', proto: 'tcp', aka: ['impressora', 'printer'] },
  { name: 'Impressão (RAW)', what: 'impressora de rede (JetDirect)', port: '9100', proto: 'tcp', aka: ['impressora', 'printer'] },
  { name: 'Minecraft', what: 'servidor de Minecraft', port: '25565', proto: 'tcp', aka: ['jogo', 'game'] },
  { name: 'WireGuard', what: 'VPN WireGuard', port: '51820', proto: 'udp', aka: ['vpn'] },
  { name: 'OpenVPN', what: 'VPN OpenVPN', port: '1194', proto: 'udp', aka: ['vpn'] },
  { name: 'Telnet', what: 'terminal remoto sem criptografia', port: '23', proto: 'tcp', aka: ['terminal', 'inseguro'] },
];

/** normaliza para busca: minúsculas e sem acento, para "trafego" achar "tráfego". */
export function foldSearch(s: string): string {
  return (s || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim();
}

/**
 * searchServices devolve os serviços que casam com a busca.
 *
 * A ordem importa mais do que parece: quem digita "53" quer o DNS no topo, não
 * o Minecraft (25565 CONTÉM "55"). Por isso a porta exata vem primeiro, depois
 * o nome que começa com o termo, e só então o resto.
 */
export function searchServices(query: string, list: Service[] = SERVICES): Service[] {
  const q = foldSearch(query);
  if (!q) return list;

  const scored: Array<{ s: Service; rank: number }> = [];
  for (const s of list) {
    const name = foldSearch(s.name);
    const what = foldSearch(s.what);
    const aka = (s.aka || []).map(foldSearch);

    let rank = -1;
    if (s.port === q) rank = 0;                                   // porta exata
    else if (name === q) rank = 1;                                // sigla exata
    else if (name.startsWith(q)) rank = 2;
    else if (aka.some((a) => a === q)) rank = 3;
    else if (s.port.startsWith(q)) rank = 4;
    else if (name.includes(q) || what.includes(q)) rank = 5;
    else if (aka.some((a) => a.includes(q))) rank = 6;

    if (rank >= 0) scored.push({ s, rank });
  }
  // Estável dentro do mesmo rank: a ordem do catálogo é curada (HTTPS antes de
  // HTTP, por exemplo), e reordenar por acaso desfaria isso.
  return scored
    .map((x, i) => ({ ...x, i }))
    .sort((a, b) => (a.rank - b.rank) || (a.i - b.i))
    .map((x) => x.s);
}

/** portLabel descreve uma porta usando o catálogo, quando ela é conhecida. */
export function portLabel(port: string, proto: string): string {
  const hit = SERVICES.find((s) => s.port === port && s.proto === proto);
  return hit ? `${hit.name} (${port}/${proto})` : `porta ${port}/${proto}`;
}
