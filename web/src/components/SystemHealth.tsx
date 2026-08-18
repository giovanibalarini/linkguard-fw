import { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';
import client from '../api/client';
import Panel from './ui/Panel';
import { useI18n } from '../i18n';
import type { HealthItem, UpdatesReport } from '../types';

// Friendly labels for known service unit names.
const LABEL_KEY: Record<string, string> = {
  'nftables': 'mon.health.label.nftables',
  'kea-dhcp4-server': 'mon.health.label.dhcp',
  'unbound': 'mon.health.label.dns',
  'ntp-sync': 'mon.health.label.ntpSync',
  'smart-health': 'mon.health.label.smart',
  'boot-time': 'mon.health.label.bootTime',
  'journal-integrity': 'mon.health.label.journalIntegrity',
  'firewall-nat': 'mon.health.label.firewallNat',
  'firewall-boot-persist': 'mon.health.label.firewallBootPersist',
  'wan-interface': 'mon.health.label.wanInterface',
  'dns-resolver': 'mon.health.label.dnsResolver',
  'system-updates': 'mon.health.label.systemUpdates',
};

// O que fazer quando o vigia está fora do ar — só para os itens em que a saída
// NÃO é óbvia a partir do nome. Aparece apenas com `up: false`, de modo que o
// cartão saudável continua do tamanho de sempre.
//
// "Regras no próximo boot" é o caso que motivou isto. A validação em VM de
// 2026-08-13 (cenário 5) mediu que a primeira coisa que o operador tentaria —
// aplicar outra regra — NÃO apaga o item: a unidade tem ProtectSystem=strict
// com ReadWritePaths=-/etc/nftables.conf, e um caminho que não existia no start
// do serviço não entra gravável no namespace, então o processo já rodando
// continua sem conseguir escrever por mais mutações que venham. Sem esta linha o
// operador tenta a mutação, vê que nada muda e conclui que o produto está
// quebrado — às 3 da manhã, numa máquina que ele só alcança por SSH.
const FIX_HINT_KEY: Record<string, string> = {
  'firewall-boot-persist': 'mon.health.hint.firewallBootPersist',
};

export default function SystemHealth() {
  const { t } = useI18n();
  const [items, setItems] = useState<HealthItem[]>([]);
  const [updates, setUpdates] = useState<UpdatesReport | null>(null);
  const [showUpdates, setShowUpdates] = useState(false);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try { const { data } = await client.get<HealthItem[]>('/api/monitoring/health'); if (alive) setItems(data ?? []); }
      catch { /* best-effort */ }
      try { const { data } = await client.get<UpdatesReport>('/api/system/updates'); if (alive) setUpdates(data); }
      catch { /* best-effort, igual ao health */ }
    };
    load();
    const t = setInterval(load, 15000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  // Vira widget do painel (spec §5): o cartão preenche a célula que o operador
  // lhe deu, e o excedente rola dentro dele em vez de esticar a grade.
  //
  // Sem vigia nenhum, o widget diz isso — e não some. Sumir deixaria um buraco
  // no painel, e o operador não teria como saber se o widget está quebrado ou
  // se não há o que vigiar.
  if (items.length === 0) {
    return (
      <Panel title={t('mon.health.title')} className="h-full overflow-y-auto">
        <p className="py-2 text-sm text-gray-500">{t('mon.health.empty')}</p>
      </Panel>
    );
  }
  return (
    <Panel title={t('mon.health.title')} className="h-full overflow-y-auto">
      {/* auto-fill, e não `sm:`/`lg:`: dentro de um widget quem manda é a largura
          do CARTÃO, não a da janela. Com os breakpoints do Tailwind (que olham a
          janela) um widget de 4 colunas numa tela larga tentava caber 4 vigias
          lado a lado e todos os rótulos viravam "Sinc...", "Inte...", "Tem...". */}
      <div className="grid gap-2 [grid-template-columns:repeat(auto-fill,minmax(8.5rem,1fr))]">
        {items.map((it) => {
          const hintKey = it.up ? undefined : FIX_HINT_KEY[it.name];
          const hint = hintKey ? t(hintKey) : undefined;
          const labelKey = LABEL_KEY[it.name];
          const label = labelKey ? t(labelKey) : it.name;
          return (
          <div key={`${it.kind}:${it.name}`}
            className={`rounded-lg border p-3 ${it.up ? 'border-green-500/20 bg-green-500/5' : 'border-red-500/30 bg-red-500/10'}`}>
            <div className="flex items-center gap-2">
              {it.up ? <ShieldCheck className="w-4 h-4 text-green-400 shrink-0" /> : <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />}
              <div className="min-w-0">
                {/* O `truncate` corta o rótulo dentro de um cartão estreito, e
                    "Regras no ..." em vermelho não diz ao operador o que está
                    fora do ar. O title devolve o nome inteiro no hover — vale
                    para todos os vigias, não só o novo ("Sincroniza...",
                    "Temperatu...", "Atualizaçõ..." já sofriam do mesmo). */}
                <div className="text-white text-sm truncate" title={label}>{label}</div>
                <div className={`text-xs ${it.up ? 'text-green-400' : 'text-red-400'}`}>{it.up ? t('mon.health.up') : t('mon.health.down')}</div>
              </div>
            </div>
            {/* Visível, não só no `title`: em tela de toque não há hover, e esta
                é a única instrução que tira a máquina do estado. Só existe com o
                item vermelho, então o cartão saudável não muda de tamanho. */}
            {hint && (
              <p className="mt-2 text-[11px] leading-snug text-red-300/90 break-words">{hint}</p>
            )}
          </div>
          );
        })}
      </div>
      {updates && updates.total > 0 && (
        <div className="mt-3 pt-3 border-t border-gray-800/50">
          <button onClick={() => setShowUpdates(!showUpdates)} className="text-sm text-gray-400 hover:text-white">
            {t('mon.health.updates.pending', { n: updates.total })}
            {updates.security > 0 && <span className="text-amber-400">{t('mon.health.updates.security', { n: updates.security })}</span>}
            <span className="text-gray-600"> {showUpdates ? '▲' : '▼'}</span>
          </button>
          {showUpdates && (
            <div className="mt-2 space-y-1">
              {updates.packages.map((p) => (
                <div key={p.name} className="flex items-center justify-between text-xs">
                  <span className={p.security ? 'text-amber-400' : 'text-gray-400'}>{p.name}</span>
                  <span className="text-gray-600 font-mono">{p.current_version || '—'} → {p.new_version}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
