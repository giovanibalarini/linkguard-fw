# Grupos de regras: organizar o firewall como appliance

## 1. Motivação

Depois de subir a Fase B, o operador olhou a aba "Regras" e foi direto ao
ponto: *"no LinkGuard se trabalha muito com chains, que são uma espécie de
grupos de regras. Acho que podemos trabalhar desta forma abstraindo para o
usuário final que são chains. A aba 'regras' é exatamente isto mas com esse
nome fica horrível e a forma como lá se organiza também acho muito feio."*

O diagnóstico procede em três frentes:

- **Lista chapada.** Três regras ocupam a tela inteira, cada uma num cartão
  com sete controles espalhados. Não há agrupamento nenhum: tudo vive numa
  única chain `user_rules`.
- **A aba mistura assuntos.** "Regras personalizadas", "Direcionamento por
  WAN", "Destinos bloqueados" e "Hosts bloqueados" empilhados no mesmo
  lugar, sendo conceitos distintos.
- **Não dá para agrupar nem desligar em bloco.** Testar desligando um
  conjunto de regras exige desligar uma a uma.

Isto já estava no `FEATURES.md` (Fase 1) e nunca saiu do papel: *"grupos de
regras via chains nativas — ativar/desativar um grupo inteiro removendo ou
inserindo o jump, sem mexer regra a regra"*.

Esta entrega **substitui** a Fase C originalmente planejada (editor de texto
do ruleset), decisão explícita do operador: grupos servem no dia a dia e
alcançam muito mais gente; o editor cru só serve a quem já sabe sintaxe nft
e passa a ser menos necessário quando o que ele resolveria ganha tela
própria. O editor fica anotado para depois, e herda o mecanismo de
confirmação da §5.

## 2. O que é um grupo

| Campo | O quê |
|---|---|
| **nome** | livre, exibido ("Wi-Fi visitantes") |
| **quando** | condição de entrada — origem, destino, interface (opcional) |
| **onde** | `atravessando` (padrão) ou `destinado ao firewall` |
| **regras** | lista ordenada, mesmo modelo de campos já existente |
| **e o que sobrar?** | `continuar` (padrão) · `permitir` · `bloquear` |
| **ligado** | tira ou põe o `jump`, sem perder as regras |
| **ordem** | posição entre os demais grupos |

Não há nada escondido atrás deste modelo: cada campo tem efeito direto e
observável no ruleset.

### 2.1 Mapeamento para nftables

Cada grupo é uma chain regular. A condição de entrada é a linha do `jump`:

```
chain forward {
    ...bloqueios...
    ip saddr 192.168.50.0/24 counter jump grp_a3f21c08
    ip saddr 192.168.3.10    counter jump grp_5b0e9d14
}

chain grp_a3f21c08 {              # Wi-Fi visitantes
    tcp dport 443 counter accept
    udp dport 53 counter accept
    counter drop                  # "e o que sobrar? bloquear"
}
```

- **Condição não casou** → o `jump` não é tomado, o grupo inteiro é pulado.
  É isto que faz a tela virar índice em vez de parede de regras.
- **Casou e uma regra decidiu** → acabou.
- **Casou e nada decidiu** → o "e o que sobrar?" do grupo:
  `continuar` não emite linha final (o `jump` retorna naturalmente);
  `permitir` emite `counter accept`; `bloquear` emite `counter drop`.

**Nome da chain vem do id do grupo, nunca do nome digitado** (`grp_` + 8 hex
do id). Nome não é identidade: renomear quebraria a chain, e um nome com
caractere especial viraria injeção no comando `nft`. É a mesma disciplina
que a v1.0.80 já aplicou nos outros geradores.

## 3. Ordem de avaliação (a mudança de comportamento)

Hoje as regras do usuário são avaliadas **antes** das listas de bloqueio.
Consequência que existe desde sempre e que ninguém percebeu: uma regra de
"Permitir" passa por cima de "Destinos bloqueados" e "Hosts bloqueados" — o
bloqueio administrativo perde para uma regra criada meses antes.

**Isto inverte.** As listas de bloqueio passam a ser avaliadas antes dos
grupos:

```
pacote atravessando o firewall
  │
  ├─ mark_hosts                    qual WAN este host usa
  │
  ├─ hosts bloqueados      → descarta      ⟵ agora primeiro,
  ├─ destinos bloqueados   → descarta         e sempre vencem
  │
  ├─ seus grupos, na sua ordem
  │    ├─ condição não casou        → pula o grupo inteiro
  │    ├─ casou e uma regra decidiu → acabou
  │    └─ casou e nada decidiu      → "e o que sobrar?"
  │
  └─ postrouting                   mascara pela WAN
```

Razão: "bloquear host em 1 clique" é uma ação administrativa. Se ela não
vence, ela mente — e o projeto existe para eliminar exatamente esse tipo de
confiança falsa.

**É mudança de comportamento em máquina em produção**, então:

- A tela de grupos exibe, de forma fixa e visível, que hosts e destinos
  bloqueados são avaliados antes e sempre vencem.
- O `README.md` e as notas da versão registram a inversão.
- Um alerta informativo é criado uma única vez na migração, dizendo que a
  ordem mudou e o que isso significa.

## 4. Alcance: atravessando e destinado ao firewall

Hoje as regras do usuário só valem para tráfego **atravessando** o firewall
(chain `forward`). Não há como escrever "visitante não fala com o próprio
firewall" — SSH, painel 9997, DNS, Samba.

Um grupo passa a escolher onde age:

- **atravessando** (padrão) — `jump` a partir da chain `forward`.
- **destinado ao firewall** — `jump` a partir da chain `input`, criada na
  v1.0.96 para a proteção de NTP.

A chain `input` **continua com `policy accept`**, sempre. Esta é a decisão
de segurança inegociável herdada da spec de NTP (2026-08-11, §2): política
restritiva trancaria o operador para fora no instante em que fosse aplicada.
Bloqueio se faz por regra explícita dentro do grupo, nunca por política.

Grupos de input são renderizados **depois** das regras de proteção de NTP,
que continuam sendo geradas pelo controle de NTP.

## 5. Confirmar-ou-reverte

Um grupo que age no próprio firewall pode trancar o operador para fora —
SSH, painel, Samba — de uma máquina remota, sem acesso físico. `nft -c`
prova que o ruleset compila; não prova que ainda dá para entrar.

Por isso, **toda mudança que envolve um grupo de escopo "destinado ao
firewall"** (criar, editar, ligar, desligar, reordenar, apagar) passa por
confirmação:

1. A mudança é aplicada de verdade.
2. Uma janela de **90 segundos** é aberta.
3. O painel mostra contagem regressiva e dois botões: *Confirmar, está tudo
   certo* e *Reverter agora*.
4. Sem confirmação até o fim da janela, o LinkGuard **reverte sozinho** ao
   estado anterior dos grupos e registra alerta.

Mudança que envolve apenas grupos "atravessando" **não** passa por
confirmação: tráfego em trânsito não pode cortar o acesso do operador à
própria máquina, e exigir confirmação ali seria só atrito.

### 5.1 O pendente mora no banco, não na memória

O estado pendente — snapshot do estado anterior dos grupos, instante de
expiração, quem aplicou — é gravado **no banco**, não apenas num timer em
memória.

Sem isso, um reboot dentro da janela deixaria valendo para sempre uma regra
não confirmada que pode ter trancado o operador — e aí não há volta remota.
Com isso, no boot o LinkGuard encontra a mudança não confirmada e **reverte**,
registrando alerta com o que reverteu e por quê. Decisão explícita do
operador, ciente de que isso pode custar refazer uma alteração legítima após
um reboot planejado.

O timer em memória continua existindo para o caso comum (processo vivo); a
verificação no boot é a rede embaixo dele.

### 5.2 Reverter é escopado

Reverter restaura o estado anterior **dos grupos** no banco e reconcilia as
chains próprias. Não é `flush ruleset` nem restauração de snapshot inteiro —
continua valendo a regra do projeto de nunca dar flush no que não é nosso.

### 5.3 A edição fica travada enquanto a janela corre

Nenhuma alteração em grupos ou regras é aceita enquanto há confirmação
pendente: a API recusa e o painel desabilita os controles, exibindo a faixa
com o relógio.

Sem isso, "reverter ao estado anterior" vira uma coisa ambígua — o estado
anterior a qual das mudanças? — e o operador pode empilhar uma segunda
alteração arriscada sobre uma que ainda não se provou boa. Travar mantém o
alvo da reversão sendo exatamente um.

O relógio exibe **"reverte em"**, não "expira em": diz ao operador o que vai
acontecer com a máquina dele, não que um prazo terminou.

## 6. Migração

Na primeira execução, as regras hoje existentes em `user_rules` viram um
grupo chamado **"Minhas regras"**: sem condição de entrada, escopo
`atravessando`, "e o que sobrar? continuar", em primeira posição. Ordem
preservada. O comportamento resultante é idêntico ao de hoje — o operador
renomeia e divide depois, com calma.

Mecânica, reaproveitando o que a Fase B endureceu e que já rodou em
produção:

- Tudo numa transação: o grupo, as regras e a trava de migração entram
  juntos ou não entram.
- Regra que o modelo não consegue representar entra **desativada**, com o
  texto original preservado na descrição — nada é perdido.
- Depois da migração bem-sucedida, a chain `user_rules` é removida do
  ruleset. Ordem obrigatória: reconstruir a chain `forward` sem o `jump`
  para ela **antes** de removê-la, porque nft recusa apagar chain ainda
  referenciada.

A inversão de ordem da §3 vale a partir da migração.

## 7. Interface

A aba "Regras" vira **"Grupos de regras"**. As três seções que hoje moram
junto — Direcionamento por WAN, Destinos bloqueados, Hosts bloqueados — saem
para uma aba própria, **"Bloqueios e direcionamento"**, dentro do Firewall.
Ficam perto porque agora são avaliadas antes dos grupos, e entender a ordem
exige ver as duas coisas no mesmo lugar.

### 7.1 Índice e detalhe, não acordeão

O desenho foi decidido comparando três tratamentos no companion visual. O
escolhido é **índice à esquerda, detalhe à direita** — nada expande nem
colapsa, o operador seleciona um grupo e lê. A tela nunca muda de altura sob
o cursor, que era a origem do "confuso" na primeira proposta.

```
┌──────────────────┬─────────────────────────────────────────────────────┐
│ 5 GRUPOS  [Novo] │  Wi-Fi visitantes      [Desligar] [Editar] [Remover]│
├──────────────────┤                                                     │
│ ⠿1 ● Wi-Fi visi… │  QUANDO origem 192.168.50.0/24 · ONDE atravessando  │
│      2 regras ·  │                        entraram 1.247 pct · 4.1 MB  │
│      4.1 MB      │                                                     │
│ ⠿2 ● Servidores  │   #  AÇÃO      QUANDO A REGRA CASA  DESCR.  PCT  TRÁFEGO│
│      1 regra ·   │   1  Permitir  tcp dport 443        naveg.  1.219  4.1 MB│
│      84.5 MB     │   2  Permitir  udp dport 53         DNS        84  12.0 KB│
│ ⠿3 ● Visitantes  │  ┌ e o que sobrar? BLOQUEAR ──────────── 12 ·  980 B ┐│
│      fora do  ⚠  │                                                     │
│      firewall    │  [+ Nova regra neste grupo]                         │
│ ⠿4 ● Minhas reg… │                                                     │
│ ⠿5 ○ Testes      │                                                     │
└──────────────────┴─────────────────────────────────────────────────────┘
```

**Índice (esquerda).** Ordem, estado (ponto verde/cinza), nome e um resumo de
uma linha — `2 regras · 4.1 MB` — que permite comparar grupos sem abrir
nenhum. O ⠿ de arrastar só aparece no hover, para a lista ficar limpa em
repouso. Grupo de escopo "destinado ao firewall" leva ⚠ discreto, avisando
antes do clique que alterá-lo pedirá confirmação.

**Detalhe (direita).** Nome, ações do grupo no topo, e a condição de entrada
numa faixa própria — com o contador do `jump`, isto é, quanto tráfego de
fato entrou no grupo.

### 7.2 As regras são uma tabela de colunas alinhadas

Esta é a correção do diagnóstico errado da primeira proposta: o problema não
era quantidade de informação, era **falta de coluna**. Selo, condição,
contadores e ícones soltos numa linha flex alinhavam diferente em cada grupo,
e o olho tinha que varrer. Appliance profissional é mais denso que aquilo e
mais legível, porque o olho desce a coluna.

Colunas: `#`, ação, **quando a regra casa**, descrição, pacotes, tráfego.

A coluna "quando a regra casa" mostra **sintaxe nft crua** (`tcp dport 443`,
`ip saddr 10.0.0.5`), não português. Decisão do operador: o que se lê na tela
é literalmente o que se acha no `nft list`, sem uma camada de tradução onde
caberia a tela dizer uma coisa e o firewall fazer outra.

### 7.2.1 Nome de ação não se traduz

Pela mesma razão, os **nomes clássicos de ação de firewall ficam em inglês**,
sempre, em qualquer tela: `accept`, `drop`, `reject`, `dnat`, `snat`,
`masquerade`, `jump`, `mark`. Nunca "Permitir", "Bloquear", "Rejeitar".

São o vocabulário do ofício, não jargão de implementação: quem administra
rede lê `drop` no painel e encontra `drop` no `nft list ruleset`, sem um
segundo dicionário que só existe aqui dentro. Traduzir criaria exatamente a
camada de interpretação que a §7.2 acabou de eliminar da coluna ao lado.

Onde a pessoa está **escolhendo** em vez de lendo — o formulário de criar
regra —, o keyword vem acompanhado de uma explicação curta em português
("descarta em silêncio", "recusa e avisa a origem"). O keyword é a
identidade; a frase é o significado. As descrições em prosa do resto da tela
continuam em português: elas explicam o que a regra faz, não nomeiam a ação.

Aplicado retroativamente às telas que já existiam (v1.0.98).

### 7.3 Demais regras da tela

- **Contadores** por regra, em bytes ou bits, no mesmo seletor que a Visão
  geral já tem. O contador do grupo é o da própria linha de `jump` — não a
  soma das regras: soma contaria a mais o que casou duas condições e a menos
  o que entrou e não casou com nada. Sem contador exibe "—", nunca zero.
- **Arrastar** no índice reordena grupos; arrastar na tabela reordena regras.
- O selo **"Configurada, não aplicada"** da Fase B passa a valer também no
  nível do grupo.
- Durante uma confirmação pendente (§5.3), a faixa com o relógio ocupa o topo
  e os controles ficam desabilitados.
- Tudo gated por `firewall.write`, como o resto da tela.

## 8. Segurança e honestidade

Herda integralmente o que a Fase B endureceu, sem exceção:

- **Validação com a ferramenta real antes de qualquer escrita no banco**: o
  conjunto inteiro renderizado passa por `nft -c -f`. Se não valida, nada é
  gravado e o erro do próprio nft é exibido.
- **Condição de entrada validada com o mesmo rigor dos campos de regra** —
  IPv4/CIDR por `net.ParseCIDR`, interface por `reIface`. Ela entra no
  comando do `nft`.
- **Falha por regra é contida**: uma regra que o nft recusa não trunca o
  grupo; as demais permanecem e o apply reporta não-ok.
- **Reconciliação no boot** a partir do banco, com flush apenas dos chains
  próprios — nunca da tabela nem do ruleset.
- **`apply_status` honesto**: regra ou grupo pulado produz estado não-ok e
  faixa visível, nunca um "ok" sintético.

## 9. Entrega em fases

| Fase | Entrega | Por quê nesta ordem |
|---|---|---|
| **C1** | Grupos para tráfego atravessando: condição, "e o que sobrar", ligar/desligar, ordem, migração, inversão da §3, reforma da tela e aba nova de bloqueios | Resolve a reclamação inteira e **não tem risco de lockout** — nada aqui alcança o acesso do operador à máquina |
| **C2** | Escopo "destinado ao firewall" + confirmar-ou-reverte (§5), incluindo a verificação no boot | A parte com risco, entregue junto com a rede de proteção que a torna aceitável |

Cada fase é utilizável sozinha e respeita a regra de entrega: funciona de
verdade, é gerenciável pelo painel e é verificável ali.

## 10. Testes

- **Modelo**: condição vira a linha de `jump` correta; condição vazia gera
  `jump` sem condição; "e o que sobrar" gera `accept`/`drop`/nada; grupo
  desligado não emite `jump` mas mantém a chain; nome da chain deriva do id
  e nunca do nome digitado.
- **Ordem**: bloqueios antes dos grupos; grupos na ordem configurada; regras
  na ordem configurada dentro do grupo.
- **Validação**: condição com IPv6, CIDR inválido ou interface inválida é
  recusada antes de qualquer escrita no banco (teste assertando zero linhas
  gravadas).
- **Migração**: transação única; ordem preservada; regra não representável
  entra desativada com texto original; `user_rules` só é removida depois de
  a `forward` deixar de referenciá-la; idempotente entre execuções.
- **Reconciliação**: flush apenas dos chains próprios (mesmo teste de
  segurança do masquerade); idempotente entre execuções sucessivas; no-op em
  dry-run.
- **Confirmar-ou-reverte (C2)**: com janela pendente, toda mutação de grupo
  ou regra é recusada pela API (§5.3); expira e reverte; confirmação dentro da
  janela mantém; pendente sobrevive a restart do processo e é revertido no
  boot; mudança só de grupo "atravessando" não abre janela.
- **VM com navegador**: criar dois grupos com condições diferentes e provar
  no `nft` real que a ordem e os `jump` saíram certos; desligar um grupo e
  provar que o `jump` sumiu e as regras continuam; arrastar e conferir a
  nova ordem no `nft`; na C2, aplicar um grupo de input e deixar a janela
  expirar, provando a reversão.

## 11. Fora de escopo (explicitamente)

- **Editor de texto do ruleset** — adiado, herda o mecanismo da §5.
- **Objetos/aliases nomeados** (dar nome a uma rede ou a um conjunto de
  portas e reusar). É a lacuna mais sentida frente a pfSense e FortiGate, e
  a candidata natural à próxima entrega — mas é projeto próprio, com tela e
  modelo de dados próprios.
- **Múltiplas portas numa regra** (`80,443` em vez de uma regra por porta).
  O modelo atual aceita uma porta ou um intervalo; grupos não mudam isso.
  Pequeno e muito usado — bom candidato a andar junto com aliases, que
  também trata "dar nome a um conjunto".
- **Log por regra** e **regra com horário** — ambos comuns em appliance,
  ambos projetos próprios.
- **Regras IPv6** — a modelagem atual é IPv4.
- **Endurecer a política da chain input** — continua fora, pelas razões da
  §4.
