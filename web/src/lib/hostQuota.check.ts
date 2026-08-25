import assert from 'node:assert';
import { readFileSync } from 'node:fs';

let n = 0;
const check = (c: unknown, m: string) => { assert.ok(c, m); n++; };

const ler = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');
const cota = ler('../components/HostQuota.tsx');
const notificacoes = ler('../components/NotificationSettings.tsx');
const servicos = ler('../i18n/strings/servicos.yaml');
const configuracoes = ler('../i18n/strings/configuracoes.yaml');

// ─────────────────────────────────────────────────────────────────────────────
// A TELA DA COTA NÃO PODE PROMETER O QUE O PRODUTO NÃO FAZ (issue #126).
//
// Três frases são obrigatórias, e cada uma existe porque a ausência dela já
// produziu, ou produziria, uma leitura errada da tela:
//
//   1. "medido pelo firewall, só IPv4"  — o número subconta em silêncio;
//   2. "avisa, não corta nem limita"    — a tela venderia um controle que a
//                                          feature deliberadamente não tem;
//   3. onde o aviso PÁRA                — o alerta que nomeia um aparelho só
//                                          sai da caixa com escolha explícita,
//                                          e o admin que declara 80% precisa
//                                          saber disso antes de contar com um
//                                          aviso no telefone.
// ─────────────────────────────────────────────────────────────────────────────

{
  check(cota.includes('svc.hosts.quota.helpMeasuredTerm'), 'a tela precisa dizer que a medição é do firewall e só IPv4');
  check(cota.includes('svc.hosts.quota.warnNoEnforcement'), 'a tela precisa dizer que avisa e não corta');
  check(cota.includes('svc.hosts.quota.warnWhereItStops'), 'a tela precisa dizer onde o aviso pára');
  for (const chave of ['svc.hosts.quota.helpMeasuredTerm', 'svc.hosts.quota.warnNoEnforcement', 'svc.hosts.quota.warnWhereItStops']) {
    check(servicos.includes(chave + ':'), 'a chave ' + chave + ' existe no dicionário');
  }
}

// A ajuda tem de admitir também o que a conta SOBRA, e não só o que ela perde.
// A contabilidade casa iifname != WAN e oifname != WAN em regras separadas, de
// modo que um pacote roteado entre duas redes internas conta como upload da
// origem E download do destino. Uma restauração de backup para um NAS local
// estoura a cota de dois aparelhos sem tocar um byte da franquia da operadora.
{
  const ajuda = servicos.slice(servicos.indexOf('svc.hosts.quota.help2:'), servicos.indexOf('svc.hosts.quota.warnNoEnforcement:'));
  check(/rede interna|internal network/i.test(ajuda),
    'a ajuda precisa dizer que tráfego entre redes internas TAMBÉM entra na conta');
  check(/IPv6/.test(ajuda), 'a ajuda precisa continuar dizendo que IPv6 não entra');
}

// ─────────────────────────────────────────────────────────────────────────────
// O OPT-IN PRECISA TER CAMINHO (issues #117 e #126).
//
// notificar_aparelho nasceu no backend com padrão falso e sem controle nenhum
// na interface: nenhum arquivo de web/src o mencionava. Resultado literal — o
// alerta de cota nomeia o aparelho e é notificado em lugar nenhum, em qualquer
// instalação entregue. "Um recurso opt-in sem caminho para o opt-in é um
// recurso desligado com trabalho extra" já está escrito em scripts/
// vm-validate.sh, sobre a #118.
// ─────────────────────────────────────────────────────────────────────────────

{
  check(notificacoes.includes('notificar_aparelho'),
    'a tela de notificações precisa expor notificar_aparelho: sem ela o portão fica fechado para sempre');
  check(notificacoes.includes('cfg.notify.hostIdentity'), 'o controle precisa de rótulo traduzido');
  for (const chave of ['cfg.notify.hostIdentity', 'cfg.notify.hostIdentity.hint']) {
    check(configuracoes.includes(chave + ':'), 'a chave ' + chave + ' existe no dicionário');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// A TELA NÃO MANDA O CAMPO DO AVISO, E LÊ O QUE O BACKEND DEVOLVE.
//
// Antes, o PUT mandava enabled: true e a tela NUNCA lia r.enabled de volta. Um
// corpo sem o campo gravava false por zero-value e produzia uma cota desenhada,
// com barra que enche, que cruza 100% e não alerta nunca. Quem decide agora é o
// backend, a partir do limite.
// ─────────────────────────────────────────────────────────────────────────────

{
  const corpoDoPut = cota.slice(cota.indexOf('const save ='), cota.indexOf('const remove ='));
  check(!/\benabled\s*:/.test(corpoDoPut),
    'o PUT da cota não pode mandar um booleano de aviso que a tela nunca lê de volta');
}

// Barra verde e cota morta são visualmente idênticas sem isto: host_metadata
// guarda a linha para sempre, então present continua verdadeiro para o endereço
// que um celular rotacionou ontem.
{
  check(cota.includes('measured_at'), 'a tela precisa distinguir 0% consumido de nada medido neste ciclo');
  check(cota.includes('svc.hosts.quota.noMeasure'), 'o rótulo de sem medição precisa estar traduzido');
  check(cota.includes('svc.hosts.quota.periodChangeWarning'),
    'trocar período redefine o ciclo, e o admin precisa saber disso antes de salvar');
}

console.log(`hostQuota.check: ${n} asserções OK`);
