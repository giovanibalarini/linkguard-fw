import { useState, useRef, useEffect } from 'react';
import { HelpCircle } from 'lucide-react';

/**
 * HelpTip is the in-context teaching primitive: a small "?" that opens a plain
 * language explanation of a concept. Used across the app so beginners can learn
 * what each thing (WAN, NAT, DHCP, DNS, failover, ...) means without leaving the
 * screen, while advanced users simply ignore it.
 */
export default function HelpTip({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, [open]);

  return (
    <span ref={ref} className="relative inline-flex align-middle">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="text-gray-500 hover:text-blue-400 transition-colors"
        aria-label={`Ajuda: ${title}`}
        title="O que é isso?"
      >
        <HelpCircle className="w-4 h-4" />
      </button>
      {open && (
        <div className="absolute left-0 top-6 z-50 w-72 rounded-lg border border-gray-700 bg-gray-900 p-3 shadow-2xl text-left">
          <p className="text-white text-sm font-semibold mb-1">{title}</p>
          <div className="text-gray-400 text-xs leading-relaxed">{children}</div>
        </div>
      )}
    </span>
  );
}
