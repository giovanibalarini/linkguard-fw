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
    version: '1.0.80',
    date: '2026-07-29',
    title: 'Revisão de segurança completa',
    changes: [
      { type: 'security', text: 'Corrigida uma falha grave na VPN: um nome de dispositivo ou endereço malformado salvo antes desta correção podia levar à execução de comandos indevidos no servidor ao aplicar a configuração. Agora todo dado é validado antes de gerar o arquivo da VPN, mesmo o que já estava salvo.' },
      { type: 'security', text: 'Corrigida uma falha que permitia a um administrador com permissão só de "gerenciar usuários" se promover (ou promover outra conta) a um papel com mais poder do que deveria ter acesso — agora exige também a permissão de "gerenciar papéis".' },
      { type: 'security', text: 'Reforçada a validação de endereços e interfaces de rede em redirecionamento de porta, no assistente de 2 internets e nas regras avançadas de firewall — bloqueando valores malformados antes que cheguem aos comandos do sistema.' },
      { type: 'security', text: 'O login agora obriga o uso de uma chave interna forte (mínimo de 32 caracteres) — o serviço recusa iniciar com uma chave fraca em vez de rodar de forma insegura.' },
      { type: 'security', text: 'Trocar a senha agora invalida imediatamente qualquer sessão antiga daquela conta (inclusive de quem já tinha um acesso salvo antes da troca).' },
      { type: 'security', text: 'Mensagens de erro internas do servidor pararam de vazar detalhe técnico (caminhos de arquivo, erros de banco) para quem está usando o painel — o log continua completo, só o que aparece na tela ficou mais genérico.' },
      { type: 'security', text: 'O backup agora usa uma proteção de senha ainda mais forte (mesmo se alguém tentasse "adivinhar" a senha testando muitas combinações, ficou bem mais caro). Backups antigos continuam podendo ser restaurados normalmente.' },
      { type: 'security', text: 'Restaurar um backup com a senha errada repetidas vezes agora bloqueia novas tentativas por alguns minutos, e o tamanho do arquivo enviado tem um limite real.' },
      { type: 'security', text: 'Todas as chamadas ao painel agora têm um limite de tamanho de corpo, e listagens (como o histórico de eventos) têm um teto máximo de itens por página — evita que um pedido malformado sobrecarregue o servidor.' },
      { type: 'security', text: 'O login ficou mais resistente a tentativas de descobrir nomes de usuário válidos por tempo de resposta, e agora toda tentativa de login (certa, errada ou bloqueada) fica registrada no log de auditoria.' },
      { type: 'fix', text: 'O campo de URL do WhatsApp (que não deveria ser editável) foi removido das configurações — evita configuração incorreta que impedia o envio de alertas.' },
    ],
  },
  {
    version: '1.0.79',
    date: '2026-07-29',
    title: 'Backup cifrado e envio automático por e-mail',
    changes: [
      { type: 'security', text: 'O arquivo de backup (baixado ou enviado por e-mail) agora é sempre cifrado com uma senha que você define em Configurações → Backup — antes ele saía em texto puro, expondo a topologia da rede e o inventário de aparelhos se vazasse.' },
      { type: 'feat', text: 'Backup automático agendado (diário, semanal ou mensal), enviado cifrado por e-mail usando o mesmo e-mail já configurado em Notificações. Desligado por padrão.' },
      { type: 'feat', text: 'Botão "Enviar por e-mail agora" para disparar um backup avulso a qualquer momento, sem esperar o agendamento.' },
      { type: 'feat', text: 'A tela mostra o resultado do último envio automático (sucesso ou falha) e avisa em Alertas se o envio parar de funcionar.' },
    ],
  },
  {
    version: '1.0.78',
    date: '2026-07-29',
    title: 'Reskin de Administração e Configurações',
    changes: [
      { type: 'feat', text: 'Telas de Administração (usuários e papéis) e Configurações (todas as seções, incluindo notificações, 2FA, HTTPS, backup, atualizações e assistente de IA) ganharam o visual novo do painel — sem mudar nada de como funcionam.' },
    ],
  },
  {
    version: '1.0.77',
    date: '2026-07-29',
    title: 'Reskin de Hosts, Alertas, Monitoramento e Logs',
    changes: [
      { type: 'feat', text: 'Telas de Hosts, Monitoramento e Logs ganharam o visual novo do painel — sem mudar nada de como funcionam.' },
    ],
  },
  {
    version: '1.0.76',
    date: '2026-07-28',
    title: 'Reskin de Firewall e VPN',
    changes: [
      { type: 'feat', text: 'Telas de Firewall (regras, direcionamento por WAN, bloqueios, encaminhamento de portas) e VPN ganharam o visual novo do painel — sem mudar nada de como funcionam.' },
    ],
  },
  {
    version: '1.0.75',
    date: '2026-07-28',
    title: 'Reskin de DHCP e DNS',
    changes: [
      { type: 'feat', text: 'Telas de DHCP e DNS ganharam o visual novo do painel — sem mudar nada de como funcionam.' },
    ],
  },
  {
    version: '1.0.74',
    date: '2026-07-28',
    title: 'Versão certa em Configurações → Sobre',
    changes: [
      { type: 'fix', text: 'A tela Configurações → Sobre sempre mostrou "1.0.0" como versão instalada, não importa a versão real rodando. Agora mostra a versão de verdade.' },
    ],
  },
  {
    version: '1.0.73',
    date: '2026-07-28',
    title: 'Apply de DHCP voltava a falhar sempre',
    changes: [
      { type: 'fix', text: 'Clicar em "Aplicar agora" na tela de DHCP sempre dava erro. A causa era uma restrição de segurança do serviço de DHCP que impedia ele de ler o arquivo de verificação — corrigido.' },
    ],
  },
  {
    version: '1.0.72',
    date: '2026-07-28',
    title: 'Reskin da tela Links WAN',
    changes: [
      { type: 'feat', text: 'Tela de Links WAN (lista de links, diálogos de criar/editar/excluir, assistente de 2 internets, balanceamento e teste de estresse) ganhou o visual novo do painel — sem mudar nada de como ela funciona.' },
    ],
  },
  {
    version: '1.0.71',
    date: '2026-07-28',
    title: 'Formulário de interface preenche o gateway certo',
    changes: [
      { type: 'fix', text: 'Ao editar uma interface física que nunca tinha sido configurada pelo painel, o campo de gateway aparecia em branco mesmo já existindo um configurado. Agora vem preenchido.' },
    ],
  },
  {
    version: '1.0.70',
    date: '2026-07-28',
    title: 'Formulário de interface preenche o IP certo',
    changes: [
      { type: 'fix', text: 'Mesma correção do gateway, mas para o campo de endereço IP (CIDR) — agora mostra o IP real da interface em vez de ficar em branco.' },
    ],
  },
  {
    version: '1.0.69',
    date: '2026-07-28',
    title: 'IP visível na árvore de Interfaces',
    changes: [
      { type: 'fix', text: 'A aba "Visão geral" de Interfaces (a árvore de WAN/LAN/portas) não mostrava o endereço IP de cada interface — só a aba "Interfaces" mostrava. Agora aparece nas duas.' },
    ],
  },
  {
    version: '1.0.68',
    date: '2026-07-28',
    title: 'Editar interface física direto pelo painel',
    changes: [
      { type: 'feat', text: 'Agora dá para editar o endereçamento de uma interface física (DHCP, IP fixo ou nenhum, com gateway) direto pela tela de Interfaces — clique em "editar". Uma tela de revisão mostra exatamente o que vai mudar antes de aplicar.' },
      { type: 'feat', text: 'Depois de aplicar, um aviso de segurança dá 90 segundos para você confirmar a mudança — se não confirmar (ou algo der errado), volta sozinho para como estava antes.' },
    ],
  },
  {
    version: '1.0.67',
    date: '2026-07-28',
    title: 'Visual novo do painel + árvore de topologia em Interfaces',
    changes: [
      { type: 'feat', text: 'Painel principal (Dashboard) ganhou um visual novo, mais limpo e direto.' },
      { type: 'feat', text: 'Interfaces virou uma árvore de topologia: mostra de relance quais portas são WAN, quais são LAN e o que está ligado em cada uma.' },
      { type: 'feat', text: 'Botão para piscar o LED de uma porta física — útil para achar o cabo certo no rack.' },
    ],
  },
  {
    version: '1.0.66',
    date: '2026-07-24',
    title: 'Interfaces em resumo colapsado',
    changes: [
      { type: 'feat', text: 'Gráficos de tráfego por interface viraram cards pequenos por padrão, que expandem ao clicar — a tela deixou de rolar demais quando havia muitas interfaces.' },
    ],
  },
  {
    version: '1.0.65',
    date: '2026-07-24',
    title: 'Correção no histórico de 30 minutos e 12 horas',
    changes: [
      { type: 'fix', text: 'As visões de 30 minutos e 12 horas em Interfaces apareciam vazias logo depois de abrir a página. Agora usam o histórico já salvo, não um buffer que reiniciava a cada carregamento.' },
    ],
  },
  {
    version: '1.0.64',
    date: '2026-07-24',
    title: 'Zoom nos gráficos de histórico',
    changes: [
      { type: 'feat', text: 'Dá para arrastar e dar zoom nos gráficos de tráfego e latência, com detalhe de média e faixa mínima/máxima do período selecionado.' },
    ],
  },
  {
    version: '1.0.63',
    date: '2026-07-24',
    title: 'Correção de migração de banco de dados',
    changes: [
      { type: 'fix', text: 'Ajuste interno para evitar que servidores com muito histórico acumulado travassem na inicialização após uma atualização.' },
    ],
  },
  {
    version: '1.0.62',
    date: '2026-07-24',
    title: 'Base para histórico de longo prazo + assistente de IA opcional',
    changes: [
      { type: 'feat', text: 'Nova base de armazenamento para métricas de longo prazo, mais rápida e econômica.' },
      { type: 'feat', text: 'Cofre de segredos interno, para guardar chaves de API com segurança.' },
      { type: 'feat', text: 'Assistente de IA opcional (você usa sua própria chave de API — nada é enviado sem você configurar).' },
    ],
  },
  {
    version: '1.0.61',
    date: '2026-07-12',
    title: 'DHCP/DNS aplicam sozinhos + atualização pela tela volta a funcionar',
    changes: [
      { type: 'feat', text: 'Ao salvar uma reserva ou config de DHCP/DNS, agora aplica automaticamente — sem precisar clicar em "Aplicar". A recarga é suave (sem reiniciar o serviço, sem piscar). O botão vira "Aplicar agora" para forçar na hora.' },
      { type: 'fix', text: 'A verificação de atualização pela tela dava erro 404. Agora dá para informar um token de acesso do GitHub (em Configurações → Atualizações) e atualizar pelo painel novamente.' },
    ],
  },
  {
    version: '1.0.59',
    date: '2026-07-07',
    title: 'Reação mais rápida a link ruim (balanceamento)',
    changes: [
      { type: 'fix', text: 'A vigilância das internets ficou mais rápida e precisa: testa a cada 10 segundos com várias medições, pegando oscilações curtas (ping alto por poucos segundos) que antes passavam batido.' },
      { type: 'feat', text: 'Novo: quando um link fica ruim (ping alto/oscilando) por alguns segundos seguidos, o LinkGuard pode migrar na hora as conexões ativas dele para uma internet saudável — ideal para chamadas de vídeo que estavam travando. Ative em Rotas → Balanceamento (vem desligado por padrão).' },
    ],
  },
  {
    version: '1.0.58',
    date: '2026-07-03',
    title: 'Alertas mais silenciosos',
    changes: [
      { type: 'fix', text: 'CPU, memória e disco agora avisam uma vez ao passar do limite (e quando normaliza), em vez de repetir a cada minuto — sem encher o WhatsApp.' },
    ],
  },
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
