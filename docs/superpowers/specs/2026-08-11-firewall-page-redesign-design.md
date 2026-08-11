# Tela de Firewall: ver o firewall inteiro e editar como appliance

## 1. Motivação

Depois de ligar a proteção de NTP pelo painel (v1.0.96), o operador foi ver a
regra na tela de Firewall e não a encontrou: *"parece na parte de firewall,
mas está péssimo de analisar. Precisei ir nas rules pra ver a regra aplicada.
Preciso que melhore essa interface e que eu consiga alterar na mão as coisas
de forma fácil iguais as appliances de firewall."*

Diagnóstico: a aba "Regras personalizadas" mostra **apenas a chain
`user_rules`** — regras que o admin cria. Tudo que o LinkGuard aplica sozinho
(NAT, proteção de NTP, bloqueios, marcação de host por WAN) vive em outras
chains e só aparece no despejo bruto de `nft list ruleset`. O operador não
tem, em lugar nenhum, a visão do que o firewall realmente faz.

Achado colateral, exposto pela mesma reclamação: as chains `forward` e
`mark_hosts` estavam com **todas as regras duplicadas** (contadores distintos
provaram serem regras reais, não artefato de exibição). Resíduo do incidente
de 2026-08-10 (arquivo carregado duas vezes), tornado permanente porque o
`Persist` gravava o estado vivo. Limpo à mão em produção; a §6 trata de
impedir a reincidência.

## 2. Princípio: mostrar tudo, mentir sobre nada

Decisão do operador entre as alternativas apresentadas: **mostrar o firewall
inteiro, identificando o que é gerenciado**, em vez de permitir editar tudo.

A razão é a regra de entrega do projeto (`FEATURES.md`): regras derivadas de
um controle de nível mais alto (o botão de NTP, os bloqueios, o NAT) são
**reconciliadas no boot e a cada mudança**. Oferecer edição manual delas seria
prometer algo que o próximo boot desfaz — exatamente a confiança falsa que a
plataforma existe para eliminar.

Portanto cada regra exibida carrega uma de duas naturezas:

- **Gerenciada pelo LinkGuard** — mostrada com origem explícita e um atalho
  para o controle que a gera ("esta regra vem de *NTP* → abrir"). Não
  editável ali.
- **Sua** (chain `user_rules`) — editável, reordenável, desativável.

## 3. Visão unificada (a mudança principal)

Uma lista única, em **ordem de avaliação real** — que é a ordem em que o
kernel decide —, agrupada por etapa do caminho do pacote, com linguagem de
gente ao lado da sintaxe nft:

| Etapa | Chain | O que faz |
|---|---|---|
| Entrada (tráfego para o próprio firewall) | `input` | proteção de serviços locais (ex.: NTP) |
| Marcação | `mark_hosts` | direciona host para uma WAN específica |
| Encaminhamento (tráfego atravessando) | `forward` → `user_rules` | suas regras, depois os bloqueios |
| NAT de saída | `postrouting` | mascaramento para as WANs |
| Redirecionamento de porta | `prerouting_dnat` | port forwards |

Cada linha mostra: ação (com cor), descrição em português, a expressão nft
original (recolhida por padrão, expansível), e os **contadores**.

### 3.1 Contadores
O nftables já conta pacotes e bytes por regra — hoje simplesmente não é
exibido. A tela mostra ambos, com um seletor de unidade:

- **bytes** (KB/MB/GB) e **bits** (Kb/Mb/Gb) — pedido explícito do operador,
  porque quem administra rede raciocina em Mbps enquanto armazenamento é
  medido em bytes. A conversão é ×8, e o rótulo tem que deixar claro qual
  está em uso (confundir os dois é erro clássico de diagnóstico).
- Regra sem contador aparece como "—", nunca como zero: não medido e medido
  zero são estados diferentes (regra do "nada de dado falso").

**Consequência para as regras existentes:** as regras de `user_rules` criadas
hoje não têm `counter`. Passam a ser criadas com ele; as antigas continuam
sem, mostrando "—" até serem recriadas. Documentar isso na tela em vez de
fingir.

## 4. Editar como appliance (chain `user_rules`)

As quatro capacidades pedidas:

1. **Contadores por regra** — §3.1.
2. **Reordenar arrastando** — a ordem decide o resultado no firewall; hoje só
   há botões de subir/descer, lentos com muitas regras.
3. **Ativar/desativar sem apagar** — testar desligando uma regra e religar
   depois, sem perder a configuração. Padrão em pfSense/OPNsense.
4. **Editor de texto do ruleset, com validação** — §5.

### 4.1 Consequência arquitetural de "desativar sem apagar"

O nftables **não tem** conceito de regra desativada. Hoje as regras do
usuário existem só dentro do nft, identificadas por *handle* — que muda a
cada recriação.

Para suportar desativar (e para tornar a ordem e a identidade estáveis), as
regras do usuário passam a viver **no banco**, e o nft passa a ser o
resultado renderizado delas — o mesmo modelo de reconciliação já usado para
NAT, NTP e resolv.conf. Ganhos além do pedido:

- identidade estável (não depende de handle volátil);
- ordem explícita, não implícita na posição do nft;
- campo de **descrição** por regra ("por que essa regra existe"), que é o que
  falta quando se lê um firewall meses depois;
- a chain `user_rules` passa a ser reconciliável — imune à classe de
  duplicação da §1.

Migração: na primeira execução, as regras hoje existentes no nft são
importadas para o banco (mesma abordagem do importador da Fase 1 de
interfaces), preservando ordem. Nada é perdido, e o operador não precisa
recriar nada.

## 5. Editor de texto do ruleset

Uma aba de especialista, com o ruleset em texto:

- **Valida antes de aplicar** (`nft -c -f`), mostrando o erro do próprio nft
  quando falha — nada é aplicado se não validar.
- **Snapshot automático antes de aplicar**, reaproveitando o mecanismo de
  backup/rollback que já existe na tela.
- **Aviso honesto e visível**: as chains gerenciadas são reconciliadas no
  boot e a cada mudança de configuração — edições manuais nelas serão
  desfeitas. O editor serve para o que o LinkGuard ainda não modela, não para
  brigar com a reconciliação.

## 6. Impedir a reincidência da duplicação

As chains estruturais (`forward`, `mark_hosts`) hoje só são criadas no
bootstrap e nunca reconciliadas — foi o que permitiu a duplicação virar
permanente. Passam a ser reconciliadas no boot como as demais: flush do
próprio chain e reescrita a partir da definição canônica.

Cuidado: a definição canônica precisa incluir `counter` em cada regra (o
ruleset de produção, criado à mão em jun/2026, tem contadores que o bootstrap
atual não emite — reconciliar sem eles apagaria justamente a informação que a
§3.1 passa a exibir).

## 7. Entrega em fases

| Fase | Entrega | Por quê nesta ordem |
|---|---|---|
| **A** | Visão unificada + contadores (bytes/bits) + marcação de gerenciado + reconciliação das chains estruturais (§6) | Resolve a dor principal ("não consigo analisar") sem mudar o modelo de dados; risco baixo |
| **B** | Regras do usuário no banco: desativar, reordenar arrastando, descrição, migração | Mudança de modelo; merece entrega e validação próprias |
| **C** | Editor de texto com validação e snapshot | Escape hatch de especialista; independente das anteriores |

## 8. Fora de escopo

- Endurecer a política de input (fechar SSH/painel/Samba nas WANs) —
  continua sendo projeto próprio, com inventário de portas e janela.
- Regras IPv6 (a modelagem atual é IPv4).
- Aliases/grupos de host reutilizáveis em regras (estilo pfSense) — evolução
  natural depois da Fase B, não antes.
