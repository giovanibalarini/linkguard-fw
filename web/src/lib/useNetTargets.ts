/**
 * Busca, uma vez, o que o LinkGuard já sabe da rede e devolve pronto para o
 * seletor de alvos.
 *
 * Fica separado do componente porque a tradução (quem é host, quem é reserva,
 * o que fundir) mora em lib/netTargets, que é código puro e coberto por
 * asserção. Aqui só entra o I/O.
 *
 * As três chamadas são toleradas individualmente: um firewall onde o DHCP não
 * está configurado não tem reservas, e isso não pode deixar a lista de
 * APARELHOS sem aparecer. Falhar tudo junto degrada o seletor para "digite o
 * endereço", que é o comportamento de antes — nunca uma tela quebrada.
 */

import { useEffect, useState } from 'react';
import client from '../api/client';
import { buildTargets, type Target, type HostLike, type ReservationLike, type LinkLike } from './netTargets';

interface DhcpResp {
  config?: { subnet_cidr?: string };
  reservations?: ReservationLike[];
}

export function useNetTargets(): { targets: Target[]; carregando: boolean } {
  const [targets, setTargets] = useState<Target[]>([]);
  const [carregando, setCarregando] = useState(true);

  useEffect(() => {
    let vivo = true;
    (async () => {
      const pega = async <T,>(url: string, extrai: (d: unknown) => T[]): Promise<T[]> => {
        try {
          const r = await client.get(url);
          return extrai(r.data) || [];
        } catch {
          return [];
        }
      };

      // Uma chamada só para DHCP: GET /api/dhcp já devolve as reservas E a
      // configuração com o CIDR da LAN. Duas chamadas seriam duas chances de
      // falhar pela metade e mostrar reservas sem a rede, ou o contrário.
      const [hosts, dhcp, links] = await Promise.all([
        pega<HostLike>('/api/hosts', (d) => (Array.isArray(d) ? d : (d as { hosts?: HostLike[] })?.hosts ?? [])),
        pega<DhcpResp>('/api/dhcp', (d) => (d ? [d as DhcpResp] : [])),
        pega<LinkLike>('/api/links', (d) => (Array.isArray(d) ? d : [])),
      ]);

      if (!vivo) return;
      const reservas = dhcp[0]?.reservations ?? [];
      const lan = (dhcp[0]?.config?.subnet_cidr || '').trim();
      setTargets(buildTargets(hosts, reservas, links, lan, Date.now()));
      setCarregando(false);
    })();
    return () => { vivo = false; };
  }, []);

  return { targets, carregando };
}
