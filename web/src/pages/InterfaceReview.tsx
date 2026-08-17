import { useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, AlertTriangle } from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import Tag from '../components/ui/Tag';
import type { IfaceEdit, PreviewResult, PendingChange } from '../types';

interface LocationState {
  edit: IfaceEdit;
  preview: PreviewResult;
}

export default function InterfaceReview() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState | undefined;
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState('');

  if (!state) {
    return (
      <div className="p-6">
        <p className="text-gray-500 text-sm">
          Nada para revisar. <button onClick={() => navigate(`/interfaces/${name}/edit`)} className="text-blue-400 underline">Volte pro formulário</button>.
        </p>
      </div>
    );
  }

  const { edit, preview } = state;

  const handleApply = async () => {
    setApplying(true);
    setError('');
    try {
      const { data } = await client.post<PendingChange>('/api/interfaces/apply', edit);
      navigate('/interfaces', { state: { justApplied: data } });
    } catch (e) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg || 'Falha ao aplicar.');
    } finally {
      setApplying(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <button onClick={() => navigate(`/interfaces/${name}/edit`)} className="flex items-center gap-2 text-gray-400 hover:text-white text-sm">
        <ArrowLeft className="w-4 h-4" /> Voltar pro formulário
      </button>

      <div>
        <h1 className="text-xl font-bold text-white">Revisar mudanças — {name}</h1>
        <p className="text-gray-500 text-sm mt-0.5">Confira o que vai ser escrito antes de aplicar.</p>
      </div>

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{error}</div>}

      {preview.warnings.map((w, i) => (
        <div key={i} className="flex items-start gap-3 px-4 py-3 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-300 text-sm">
          <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
          <span>{w}</span>
        </div>
      ))}

      {preview.files.map((f) => (
        <Panel key={f.path} title={f.path}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            <div>
              <div className="text-gray-500 mb-1 uppercase tracking-wide">Antes</div>
              <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 whitespace-pre-wrap text-gray-400 min-h-[4rem]">
                {f.old_content || '(arquivo não existe ainda)'}
              </pre>
            </div>
            <div>
              <div className="text-gray-500 mb-1 uppercase tracking-wide">Depois</div>
              <pre className="bg-gray-950 border border-emerald-800/50 rounded-lg p-3 whitespace-pre-wrap text-emerald-300 min-h-[4rem]">
                {f.new_content}
              </pre>
            </div>
          </div>
        </Panel>
      ))}

      <div className="flex items-center gap-3">
        <button onClick={handleApply} disabled={applying} className="btn-primary">
          {applying ? 'Aplicando...' : 'Aplicar'}
        </button>
        <Tag variant="warn">Vai pedir confirmação em até 90s ou reverte sozinho</Tag>
      </div>
    </div>
  );
}
