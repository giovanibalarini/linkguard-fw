import { Sparkles } from 'lucide-react';
import { CHANGELOG, type ChangeType } from '../data/changelog';

const TYPE_META: Record<ChangeType, { label: string; cls: string }> = {
  feat: { label: 'Novo', cls: 'bg-green-500/10 text-green-400 border border-green-500/20' },
  fix: { label: 'Correção', cls: 'bg-blue-500/10 text-blue-400 border border-blue-500/20' },
  security: { label: 'Segurança', cls: 'bg-amber-500/10 text-amber-300 border border-amber-500/20' },
};

function fmtDate(iso: string): string {
  // Render as DD/MM/YYYY without pulling a date library; iso is 'YYYY-MM-DD'.
  const [y, m, d] = iso.split('-');
  if (!y || !m || !d) return iso;
  return `${d}/${m}/${y}`;
}

export default function Changelog() {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <Sparkles className="w-5 h-5 text-blue-400" />
        <div>
          <h1 className="text-xl font-bold text-white">Novidades</h1>
          <p className="text-gray-500 text-sm">O que mudou em cada versão do LinkGuard.</p>
        </div>
      </div>

      <div className="space-y-4">
        {CHANGELOG.map((entry) => (
          <div key={entry.version} className="card">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 mb-3">
              <span className="text-white font-semibold">v{entry.version}</span>
              {entry.title && <span className="text-gray-300 text-sm">{entry.title}</span>}
              <span className="text-gray-600 text-xs ml-auto">{fmtDate(entry.date)}</span>
            </div>
            <ul className="space-y-2">
              {entry.changes.map((c, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm">
                  <span className={`shrink-0 mt-0.5 px-1.5 py-0.5 rounded text-[11px] font-medium ${TYPE_META[c.type].cls}`}>
                    {TYPE_META[c.type].label}
                  </span>
                  <span className="text-gray-300">{c.text}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
