// Os alvos de rede: o que o LinkGuard JÁ sabe, oferecido pronto no lugar de um
// campo de texto onde se digita CIDR.
//
// POR QUE ISTO EXISTE. Para bloquear o notebook de alguém, o admin precisava
// descobrir o IP por fora (na tela de Hosts, ou no roteador), copiar, voltar e
// digitar. O produto já conhece esse aparelho pelo nome — ele aparece na tela
// de Hosts, tem apelido e reserva de DHCP —, e mesmo assim pedia o endereço.
//
// Este módulo é só a TRADUÇÃO: recebe o que as telas de Hosts, DHCP e Links
// devolvem e produz uma lista única, agrupada, com o endereço que a regra vai
// usar de verdade. Nada de I/O aqui — quem busca é o componente, e é isso que
// deixa esta parte coberta por asserção.

export type TargetKind = 'host' | 'reserva' | 'rede' | 'wan' | 'manual';

export interface Target {
  /** Chave estável para o React e para comparar seleção. */
  id: string;
  kind: TargetKind;
  /** O que a pessoa lê: "notebook-maria". */
  label: string;
  /** A informação de apoio: o endereço, o MAC, a interface. */
  hint: string;
  /** O que vai para a regra — IP, CIDR, ou '' para "qualquer". */
  value: string;
  /** Só para hosts: se ele está na rede agora. */
  online?: boolean;
}

export interface HostLike {
  mac: string; ip: string; hostname: string; alias: string;
  blocked?: boolean; last_seen?: string;
}
export interface ReservationLike { mac: string; ip: string; hostname: string }
export interface LinkLike { id: string; name: string; interface: string; ip_address?: string }

/**
 * hostName escolhe como chamar um aparelho.
 *
 * A ordem é apelido → hostname → MAC, e ela é a diferença entre uma lista que
 * ajuda e uma lista de endereços MAC. O apelido vem primeiro porque foi o
 * ADMIN quem o escreveu, justamente para reconhecer o aparelho; o hostname é o
 * que o aparelho diz de si (às vezes "android-9f2c", que não ajuda ninguém); o
 * MAC é o último recurso, e ainda assim melhor do que uma linha em branco.
 */
export function hostName(h: HostLike): string {
  return (h.alias || '').trim() || (h.hostname || '').trim() || h.mac;
}

/** onlineRecently: visto nos últimos 10 minutos conta como "na rede agora". */
export function onlineRecently(lastSeen: string | undefined, agora: number): boolean {
  if (!lastSeen) return false;
  const t = Date.parse(lastSeen);
  if (Number.isNaN(t)) return false;
  return agora - t < 10 * 60 * 1000;
}

/**
 * buildTargets monta a lista oferecida no seletor.
 *
 * Regras de conteúdo, todas com motivo:
 *
 *  - host SEM IP fica de fora: uma regra precisa de endereço, e oferecer um
 *    item que não dá para usar é pior do que não oferecer;
 *  - reserva cujo IP já aparece como host é FUNDIDA no host, não repetida — a
 *    mesma máquina em duas linhas faria o admin achar que são dois aparelhos;
 *  - a LAN inteira entra como rede, porque "bloquear tudo menos X" é um caso
 *    comum e ninguém deveria digitar o CIDR de cabeça;
 *  - os links WAN entram porque "saindo pela Fibra" é como o admin pensa, e
 *    ele não deveria precisar lembrar que a Fibra é a wlp0s20f3.
 */
export function buildTargets(
  hosts: HostLike[],
  reservas: ReservationLike[],
  links: LinkLike[],
  lanCidr: string,
  agora: number,
): Target[] {
  const out: Target[] = [];
  const ipsDeHosts = new Set<string>();

  for (const h of hosts || []) {
    const ip = (h.ip || '').trim();
    if (!ip) continue;
    ipsDeHosts.add(ip);
    out.push({
      id: `host:${h.mac || ip}`,
      kind: 'host',
      label: hostName(h),
      hint: ip,
      value: ip,
      online: onlineRecently(h.last_seen, agora),
    });
  }

  for (const r of reservas || []) {
    const ip = (r.ip || '').trim();
    if (!ip || ipsDeHosts.has(ip)) continue;
    out.push({
      id: `reserva:${r.mac || ip}`,
      kind: 'reserva',
      label: (r.hostname || '').trim() || r.mac,
      hint: `${ip} · reserva fixa`,
      value: ip,
    });
  }

  if ((lanCidr || '').trim()) {
    out.push({
      id: 'rede:lan',
      kind: 'rede',
      label: 'A LAN inteira',
      hint: lanCidr.trim(),
      value: lanCidr.trim(),
    });
  }

  for (const l of links || []) {
    if (!(l.interface || '').trim()) continue;
    out.push({
      id: `wan:${l.id}`,
      kind: 'wan',
      label: l.name || l.interface,
      hint: `link WAN · ${l.interface}`,
      // O valor é a INTERFACE, e não um IP: é assim que a regra fala de "por
      // onde o tráfego entra ou sai". Quem consome sabe distinguir pelo kind.
      value: l.interface,
    });
  }

  return out;
}

/** Rótulo do grupo na lista, na ordem em que os grupos aparecem. */
export const KIND_LABEL: Record<TargetKind, string> = {
  host: 'Aparelhos na rede',
  reserva: 'Reservas de DHCP',
  rede: 'Redes',
  wan: 'Links WAN',
  manual: 'Endereço digitado',
};

export const KIND_ORDER: TargetKind[] = ['host', 'reserva', 'rede', 'wan', 'manual'];

/**
 * searchTargets filtra pela busca, casando por nome E por endereço.
 *
 * Os dois importam: quem lembra do nome digita "maria", quem está olhando um
 * log digita "192.168.3.47". Aparelho ONLINE vem antes do offline dentro do
 * mesmo grupo — na hora de bloquear alguém, é quase sempre alguém que está na
 * rede agora.
 */
export function searchTargets(query: string, alvos: Target[]): Target[] {
  const q = (query || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim();

  const fold = (s: string) =>
    (s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');

  const filtrados = q
    ? alvos.filter((t) => fold(t.label).includes(q) || fold(t.hint).includes(q) || fold(t.value).includes(q))
    : alvos.slice();

  return filtrados.sort((a, b) => {
    const ka = KIND_ORDER.indexOf(a.kind);
    const kb = KIND_ORDER.indexOf(b.kind);
    if (ka !== kb) return ka - kb;
    if (a.kind === 'host' && a.online !== b.online) return a.online ? -1 : 1;
    return 0;
  });
}

/** describeTarget: como a regra pronta se refere a este alvo, em português. */
export function describeTarget(t: Target | null, vazio = 'qualquer origem'): string {
  if (!t || !t.value) return vazio;
  if (t.kind === 'wan') return `pelo link ${t.label}`;
  if (t.kind === 'rede') return `${t.label} (${t.value})`;
  if (t.kind === 'manual') return t.value;
  return `${t.label} (${t.value})`;
}
