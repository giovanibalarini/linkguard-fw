import { useEffect, useState } from 'react';
import { Sparkles, Check, X } from 'lucide-react';
import client from '../api/client';
import Panel from './ui/Panel';
import { useI18n } from '../i18n';
import type { AIStatus, AIConfig } from '../types';

const MODELS = [
  { id: 'claude-opus-4-8', label: 'Claude Opus 4.8', descKey: 'cfg.ai.model.opus.desc' },
  { id: 'claude-sonnet-5', label: 'Claude Sonnet 5', descKey: 'cfg.ai.model.sonnet.desc' },
  { id: 'claude-haiku-4-5', label: 'Claude Haiku 4.5', descKey: 'cfg.ai.model.haiku.desc' },
];

const CONSENT_FIELDS: { key: string; labelKey: string }[] = [
  { key: 'hostname', labelKey: 'cfg.ai.consent.hostname' },
  { key: 'mac', labelKey: 'cfg.ai.consent.mac' },
  { key: 'dns_queries', labelKey: 'cfg.ai.consent.dns' },
];

// digest_hour não tem controle na UI ainda (sem seletor de horário do resumo
// diário) e AIStatus não o expõe, então é enviado fixo com o mesmo valor do
// default do backend (internal/ai/config.go: DigestHour: 6). Nada além deste
// formulário grava ai_config hoje, então isso não sobrescreve um valor
// divergente na prática — mas se um horário customizável for adicionado no
// futuro (backend ou outra tela), este "Salvar configurações" voltaria a
// resetá-lo para 6 silenciosamente. Ver task-6-report.md.
const DEFAULT_DIGEST_HOUR = 6;

export default function AISettings() {
  const { t } = useI18n();
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [token, setToken] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<'ok' | 'fail' | null>(null);
  const [budget, setBudget] = useState(5);
  const [model, setModel] = useState('claude-opus-4-8');
  const [effort, setEffort] = useState('high');
  const [enabled, setEnabled] = useState(false);
  // AIStatus não inclui telemetry_consent (o backend não o devolve em
  // GET /api/ai/status — só em PUT /api/ai/config), então este estado não
  // pode ser recarregado do servidor. Após salvar e recarregar a página, as
  // caixas de consentimento aparecem desmarcadas mesmo que o consentimento
  // esteja de fato persistido no backend. Ver task-6-report.md.
  const [consent, setConsent] = useState<Record<string, boolean>>({});

  const load = async () => {
    const res = await client.get<AIStatus>('/api/ai/status');
    setStatus(res.data);
    setBudget(res.data.monthly_budget_usd);
    setModel(res.data.model);
    setEffort(res.data.effort);
    setEnabled(res.data.enabled);
  };

  useEffect(() => { load(); }, []);

  const saveToken = async () => {
    if (!token.trim()) return;
    setSaving(true);
    try {
      await client.put('/api/ai/token', { token });
      setToken('');
      await load();
    } finally {
      setSaving(false);
    }
  };

  const removeToken = async () => {
    setSaving(true);
    try {
      await client.delete('/api/ai/token');
      await load();
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      await client.post('/api/ai/token/test');
      setTestResult('ok');
    } catch {
      setTestResult('fail');
    } finally {
      setTesting(false);
    }
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      const body: AIConfig = {
        enabled, model, effort, monthly_budget_usd: budget,
        telemetry_consent: consent, digest_hour: DEFAULT_DIGEST_HOUR,
      };
      await client.put('/api/ai/config', body);
      await load();
    } finally {
      setSaving(false);
    }
  };

  return (
    <Panel title={<span className="flex items-center gap-2"><Sparkles className="w-4 h-4 text-purple-400" /><span className="text-white font-semibold">{t('cfg.ai.title')}</span></span>}>
      <div className="space-y-4">
      <p className="text-gray-500 text-sm">
        {t('cfg.ai.intro')}
      </p>

      {!status?.configured ? (
        <div className="flex gap-2">
          <input
            type="password"
            placeholder="sk-ant-..."
            value={token}
            onChange={e => setToken(e.target.value)}
            className="input flex-1"
          />
          <button onClick={saveToken} disabled={saving} className="btn-primary">{t('cfg.ai.saveToken')}</button>
        </div>
      ) : (
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-300">{t('cfg.ai.tokenConfigured')} <span className="font-mono">{status.hint}</span></span>
          <div className="flex gap-2">
            <button onClick={testConnection} disabled={testing} className="btn-secondary">
              {testing ? t('cfg.ai.testing') : t('cfg.ai.testConnection')}
            </button>
            <button onClick={removeToken} disabled={saving} className="btn-secondary text-red-400">{t('cfg.ai.removeToken')}</button>
          </div>
        </div>
      )}

      {testResult === 'ok' && (
        <p className="text-emerald-400 text-xs flex items-center gap-1"><Check className="w-3 h-3" /> {t('cfg.ai.testOk')}</p>
      )}
      {testResult === 'fail' && (
        <p className="text-red-400 text-xs flex items-center gap-1"><X className="w-3 h-3" /> {t('cfg.ai.testFail')}</p>
      )}

      {status?.configured && (
        <>
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
            {t('cfg.ai.autoAnalysis')}
          </label>

          <div>
            <p className="text-gray-500 text-xs mb-2">{t('cfg.ai.model')}</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {MODELS.map(m => (
                <button
                  key={m.id}
                  onClick={() => setModel(m.id)}
                  className={`p-2 rounded border text-left text-xs ${model === m.id ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700'}`}
                >
                  <p className="text-white font-medium">{m.label}</p>
                  <p className="text-gray-500">{t(m.descKey)}</p>
                </button>
              ))}
            </div>
          </div>

          <div>
            <p className="text-gray-500 text-xs mb-1">{t('cfg.ai.budget')}</p>
            <input
              type="number" min={1} step={0.5}
              value={budget}
              onChange={e => setBudget(parseFloat(e.target.value))}
              className="input w-32"
            />
            <p className="text-gray-600 text-xs mt-1">
              {t('cfg.ai.spent', {
                spent: status?.spent_this_month_usd.toFixed(2) ?? '0.00',
                budget: status?.monthly_budget_usd.toFixed(2) ?? budget.toFixed(2),
              })}
            </p>
          </div>

          <div>
            <p className="text-gray-500 text-xs mb-2">{t('cfg.ai.consent')}</p>
            <div className="space-y-1">
              {CONSENT_FIELDS.map(f => (
                <label key={f.key} className="flex items-center gap-2 text-sm text-gray-300">
                  <input
                    type="checkbox"
                    checked={consent[f.key] ?? false}
                    onChange={e => setConsent(c => ({ ...c, [f.key]: e.target.checked }))}
                  />
                  {t(f.labelKey)}
                </label>
              ))}
            </div>
          </div>

          <button onClick={saveConfig} disabled={saving} className="btn-primary">{t('cfg.ai.saveConfig')}</button>
        </>
      )}
      </div>
    </Panel>
  );
}
