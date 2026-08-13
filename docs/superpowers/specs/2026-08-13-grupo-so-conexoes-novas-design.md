# Grupo que vale só para conexões novas

## 1. De onde isto veio

Da pergunta do operador sobre o `ct state established` na chain `input`, depois
da entrega da Fase C2. A investigação mostrou três coisas:

1. O LinkGuard não emite `ct state` em **nenhuma** regra que gera
   (`internal/nftables/reconcile.go`). Conntrack só é lido para contabilidade
   por host e para a expulsão de fluxos de link degradado.
2. Pôr `ct state established accept` no topo da `input` seria um erro: ele faz o
   teste de 90 segundos da janela de confirmação **mentir**. O operador testa com
   a sessão que sobreviveu, vê tudo funcionando, confirma — e descobre o bloqueio
   na próxima reconexão, sem rede nenhuma embaixo.
3. Combinar `established accept` com expulsão ativa de conntrack devolveria quase
   exatamente o comportamento de hoje, a um custo alto: o tradutor de campos de
   regra para seletores do `conntrack -D` não consegue expressar `iifname`, então
   ele erraria para mais (matando fluxos que ninguém pediu) ou para menos
   (deixando passar o que a regra bloqueia).

O que falta de verdade não é um padrão global. É o operador **poder escolher**,
e a tela dizer qual escolha está valendo.

## 2. O que se ganha

Hoje, bloquear é sempre imediato e total: a regra derruba na hora os fluxos que
casam com ela. É o certo como padrão — é inequívoco, e é o que faz a janela de
confirmação funcionar como teste de acesso.

Mas metade dos casos reais quer a outra coisa: *"não quero que este host abra
conexão nova comigo, mas não vou derrubar a transferência que ele já está
fazendo"*. Hoje isso não existe, e o operador só tem a marreta.

## 3. A escolha, e onde ela mora

**Por grupo, não por regra.** É como o operador pensa ("este grupo de bloqueios
vale para conexões novas"), e por regra multiplicaria a superfície sem pedido —
um campo a mais em cada linha, na tela e na API, para um caso que ninguém trouxe.

O grupo ganha um campo com dois valores:

- **"toda conexão"** (padrão, e o que toda linha existente já significa)
- **"só conexões novas"**

## 4. Como isso vira nftables

O `ct state new` vai na **linha de `jump`**, não dentro da chain do grupo:

```
ip saddr 192.168.50.0/24 ct state new counter jump grp_a1b2c3
```

A semântica fica exata e legível: *este grupo só decide sobre conexões novas;
o que já está estabelecido passa por ele sem ser avaliado*.

A alternativa — pôr uma linha de `established accept` dentro da chain do grupo —
foi descartada: `accept` numa chain saltada é terminal, então ela não devolveria
o fluxo para as chains seguintes, e um grupo mudaria o destino do tráfego que
diz não avaliar.

**Vale para os dois escopos.** Um grupo `forward` tem o mesmo caso de uso
(cortar conexões novas de um host sem matar o download em curso) e o mesmo
tradutor. Grupos do **sistema** (`blocked_hosts`, `blocklist`) ficam de fora:
são lista fechada, renderizados por um mapa próprio, e bloqueio de host é
justamente onde se quer a marreta.

## 5. A honestidade que isto obriga na janela de confirmação

Este é o ponto que decide se a feature pode existir.

Um grupo de escopo **input** com "só conexões novas" que bloqueie o painel **não
derruba a sessão do operador**. Ele vai testar, ver tudo funcionando, e confirmar
um bloqueio que só vai morder amanhã.

Então: quando a janela de 90 segundos for aberta por um grupo com "só conexões
novas", a faixa **tem** que dizer isso, com essas palavras:

> Este grupo vale só para conexões novas. **A sua sessão atual não é afetada** —
> abra uma conexão nova (outro terminal SSH, uma aba anônima) para testar de
> verdade antes de confirmar.

Sem esse aviso a rede de proteção vira teatro, e é melhor não ter a feature.
Ver as ressalvas operacionais já registradas da Fase C2.

## 6. Persistência e compatibilidade

Coluna nova em `firewall_groups`, `TEXT NOT NULL DEFAULT ''`, migração
transacional no molde de `migrateAddFirewallGroupScope`. Vazio conta como "toda
conexão" — que é o que toda linha criada antes desta mudança significa, e o que
o firewall vivo já faz.

Na API o campo é opcional; ausente significa **manter o gravado**, como já é com
`scope` — protege cliente antigo de rebaixar em silêncio uma escolha que o
operador fez.

## 7. Tela

- No modal do grupo, a escolha entre "toda conexão" e "só conexões novas", com
  uma linha explicando a diferença em termos do que acontece com o que já está
  de pé.
- Na lista e no detalhe, o grupo com "só conexões novas" carrega a marca — sem
  ela, dois grupos idênticos na tela se comportam de formas diferentes, que é
  exatamente o tipo de coisa que faz o operador desconfiar do software.
- A pré-visualização da regra mostra `ct state new` em `font-mono`, junto do
  resto da linha: a tela não esconde o que vai para o firewall.
- Nome de ação do nftables (`accept`, `drop`, `reject`, `jump`) e `ct state new`
  nunca se traduzem.

## 8. Testes

- **Renderização**: grupo com "só conexões novas" emite `ct state new` na linha
  de jump, na posição certa (depois da condição de entrada, antes do `counter`);
  grupo com "toda conexão" emite a linha de hoje, **byte a byte igual** — nenhuma
  máquina existente pode ver o firewall mudar por causa desta entrega.
- **Fixture da saída real do `nft`**, não da saída do próprio gerador — foi assim
  que um bug crítico passou por cinco testes verdes neste projeto.
- **Pré-voo**: `nft -c -f` aceita a linha nova, verificado contra o `nft` de
  verdade (o binário está em `/usr/sbin/nft`; use `unshare -rn` para não tocar no
  ruleset da máquina), com controle negativo.
- **Grupo do sistema** não aceita o campo, nem pela API.
- **Migração** numa cópia do banco de produção: todo grupo existente fica em
  "toda conexão".
- **Janela**: abrir janela por um grupo com "só conexões novas" traz o aviso da
  §5; por um grupo comum, não traz.
- **Na VM, com tráfego de verdade**: uma transferência em curso sobrevive à
  aplicação do grupo, e uma conexão nova é recusada. Isto não se prova com
  executor falso — é a afirmação central da feature.

## 9. Fora de escopo

- `ct state established accept` global na `input` (§1, item 2).
- Expulsão ativa de conntrack por regra de firewall (§1, item 3).
- Escolha por regra em vez de por grupo (§3).
- `ct state invalid drop`: é outra decisão, com outro raciocínio, e entra sozinha
  se entrar.
- `ct state related accept` no topo da `input`: é correção de armadilha de PMTUD,
  já em andamento à parte — não depende desta feature nem a bloqueia.
