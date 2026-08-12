# Bloqueios viram grupos, e o direcionamento por WAN ganha casa própria

## 1. Motivação

A Fase C1 entregou grupos de regras e, junto, uma aba nova chamada
"Bloqueios e direcionamento", que recebeu três seções que antes estavam
empilhadas na aba de regras. Vendo funcionando, o operador foi direto ao
ponto:

> *"Quero mover o que tem, se entender que cabe, a parte de bloqueios e
> direcionamento para essa parte de grupo. Tem coisa ali que enxergo nesse
> contexto de grupos."*

Ele está certo em dois dos três casos, e a diferença importa.

**Hosts bloqueados** e **Destinos bloqueados** já *são* grupos: uma coleção
de endereços mais uma ação (`drop`), avaliada numa posição específica do
caminho do pacote. É a mesma forma de um grupo de regras. Estão em outra aba
só porque nasceram antes do conceito existir.

**Direcionamento por WAN** é outra coisa: ele não decide se o pacote passa,
decide por qual porta ele sai. Acontece numa chain diferente (`mark_hosts`,
hook prerouting, mangle), num estágio anterior. Misturá-lo na mesma lista
diria ao operador que ele é avaliado junto com os outros, o que é falso.

Mas — e aqui a proposta inicial desta spec estava errada — isso **não** é
motivo para tirá-lo do Firewall. Correção do operador:

> *"Direcionamento por WAN, entendo que por baixo dos panos isso é regra de
> firewall. Logo vejo que o contexto deveria ficar em firewall, por mais que
> tenha um comportamento exclusivo e propósito."*

Procede. É uma regra de nftables como qualquer outra, aparece na Visão geral
junto com o resto porque é ali que o pacote passa por ela, e mandar o admin
editá-la na tela de Hosts o faria sair do firewall para mexer numa regra de
firewall. Comportamento exclusivo justifica **aba própria e explicação
própria**, não mudança de endereço.

## 2. Bloqueios viram grupos de verdade

### 2.1 O que muda, e o que não muda

**Não muda a mecânica.** Hosts e destinos bloqueados continuam sendo
**named sets** do nftables (`@blocked_hosts`, `@blocklist`). É decisão
registrada no `FEATURES.md` (F1) e é melhor do que chain de regras para este
caso: adicionar ou remover um host é atômico e instantâneo, sem recarregar
nada. Reimplementá-los como lista de regras seria regressão.

**Muda a apresentação e a ordem.** Eles passam a ser linhas na tabela
`firewall_groups`, com um tipo próprio, o que lhes dá `position` de graça —
e é a posição que permite ao operador reordená-los junto com os grupos dele,
na mesma lista.

| | Grupo do admin | Grupo do sistema |
|---|---|---|
| nome | livre | fixo ("Hosts bloqueados") |
| condição de entrada | livre | não tem |
| "e o que sobrar" | livre | não tem |
| conteúdo | regras em `firewall_rules` | membros do named set |
| apagar | pode | **não** |
| renomear | pode | não |
| reordenar | pode | **pode** |
| ligar/desligar | pode | pode |

### 2.2 Ordem: o padrão é seguro, a exceção é deliberada

Decisão do operador: os grupos do sistema são **reordenáveis**, inclusive
para depois dos grupos dele.

Isto convive com a inversão de ordem que a Fase C1 entregou (spec de
2026-08-11, §3), e não a desfaz:

- **O padrão continua sendo bloqueios primeiro.** A migração os cria nas
  posições 0 e 1, que é exatamente o comportamento que já está em produção.
- **O que a Fase C1 eliminou foi a surpresa**, não a possibilidade. O
  problema era um "accept" antigo anular um bloqueio novo *sem ninguém
  perceber*, porque a ordem era invisível. Agora ela está na tela, numerada,
  e mover um bloqueio para baixo é um arrasto visível e reversível.
- Se o operador colocar um bloqueio depois de um grupo dele, a tela diz o
  que isso significa, na própria linha: *"regras acima deste bloqueio podem
  liberar tráfego que ele descartaria"*.

O padrão codifica a resposta segura; a exceção exige um ato explícito.

### 2.3 Renderização da chain forward

Hoje `forwardChainRules` emite, nesta ordem fixa: os quatro `drop` dos sets,
depois um `jump` por grupo ativado. Passa a percorrer **uma única lista
ordenada** e, para cada item, emitir conforme o tipo:

```
para cada item em ordem de posição, se ligado:
    grupo do admin        -> <condição> counter jump grp_<hex>
    hosts bloqueados      -> ip saddr @blocked_hosts counter drop
                             ip daddr @blocked_hosts counter drop
    destinos bloqueados   -> ip daddr @blocklist      counter drop
                             ip saddr @blocklist      counter drop
```

Um grupo do sistema **desligado** não emite suas linhas — mesma semântica de
desligar um grupo do admin, e o set continua guardado com seus membros.

Isto elimina o caso especial: a chain `forward` passa a ser função de uma
lista só, o que também torna a ordem exibida na tela verificável contra o
`nft list` linha a linha.

### 2.4 Migração

Na primeira execução com este código, criar os dois grupos do sistema nas
posições 0 e 1, e deslocar os grupos existentes do admin para depois. Mesma
disciplina da migração anterior: transação única, trava de "já rodou" (não
"a tabela está vazia"), e idempotente.

Os sets já existem no ruleset e no banco — a migração cria apenas as linhas
de grupo que os representam. Nenhum membro é tocado.

## 3. Direcionamento por WAN: aba própria

A aba "Bloqueios e direcionamento" se dissolve. Os bloqueios vão para a
lista de grupos (§2); o direcionamento ganha a aba **"Direcionamento por
WAN"**, dentro do Firewall.

A aba explica o que ele é, já que é o único controle do firewall que não
filtra:

> Estes hosts saem pela WAN2; os demais pela WAN1. Isto não bloqueia nem
> libera nada — só escolhe por qual link o tráfego sai. Acontece antes de
> qualquer regra de grupo, na etapa de marcação.

A tela de Hosts continua podendo levar até aqui (o inventário é onde se
reconhece a máquina pelo nome e MAC), mas a edição mora no Firewall.

Abas resultantes: **Visão geral · Grupos de regras · Direcionamento por WAN
· Encaminhamento · Ruleset · Snapshots**.

## 4. Interface

A lista de grupos passa a mostrar os cinco tipos de item na ordem real:

```
┌──────────────────┬──────────────────────────────────────────────────┐
│ 4 GRUPOS  [Novo] │  Hosts bloqueados                    do sistema  │
├──────────────────┤                                                  │
│ ⠿1 ● Hosts       │  Qualquer tráfego de ou para estes hosts é       │
│      bloqueados  │  descartado. Não tem condição nem regras: a      │
│      1 host      │  lista de membros é o próprio conteúdo.          │
│ ⠿2 ● Destinos    │                                                  │
│      bloqueados  │   192.168.3.112                       [remover]  │
│      2 faixas    │                                                  │
│ ⠿3 ● Wi-Fi visi… │   [+ bloquear host]                              │
│ ⠿4 ● Servidores  │                                                  │
└──────────────────┴──────────────────────────────────────────────────┘
```

- Grupo do sistema leva marca visível de que é do sistema, e não oferece
  apagar nem renomear. Oferece arrastar e ligar/desligar.
- O contador vem das próprias regras de set no `nft`, como hoje.
- Membro sem contador exibe `—`, nunca zero (regra do projeto).
- Quando um grupo do sistema estiver posicionado **depois** de algum grupo
  do admin, a linha dele exibe o aviso da §2.2.
- Some a faixa "Hosts e destinos bloqueados são avaliados antes destes
  grupos e sempre vencem": ela deixa de ser verdade universal, e a ordem
  agora está visível na própria lista.

## 5. Testes

- **Renderização**: a chain `forward` sai na ordem exata da lista, com
  grupo do sistema emitindo suas duas linhas de set e grupo do admin
  emitindo o `jump`; item desligado não emite nada; bloqueio movido para
  depois de um grupo do admin aparece depois no `nft`.
- **Migração**: cria os dois grupos do sistema nas posições 0 e 1,
  preservando os grupos do admin depois; transacional; idempotente; não
  ressuscita grupo do sistema que o admin tenha desligado.
- **Proteções**: apagar grupo do sistema é recusado; renomear é recusado;
  reordenar e ligar/desligar são aceitos.
- **VM, contra nft real**: mover um bloqueio para o fim e conferir no
  `nft list chain` que as linhas de set foram para o fim; desligar um
  bloqueio e conferir que as linhas somem e o set permanece com os membros.

## 6. Fora de escopo

- Mudar a mecânica dos sets (continuam named sets).
- Escopo "destinado ao firewall" e confirmar-ou-reverte — continuam sendo a
  Fase C2.
- Grupos do sistema para outros controles gerenciados (NAT, proteção de
  NTP, port forward): eles vivem em chains com hooks próprios, não na
  `forward`, e não entram nesta lista.
