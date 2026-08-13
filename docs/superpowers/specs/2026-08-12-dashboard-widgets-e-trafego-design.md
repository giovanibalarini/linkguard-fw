# Painel com widgets, e a tela de tráfego que o dado merece

## 1. Motivação

Dois pedidos do operador, que se resolvem juntos porque compartilham o mesmo
gráfico e a mesma fonte de dados:

> *"Pensa em elaborar uma página web no dash com tráfego em tempo real do link
> das interfaces. É bonito de ver."*

> *"Queria remodelar a tela de dashboard. Queria poder escolher quais widgets
> adicionar e que me interessam."*

O segundo tem uma razão concreta e visível: o painel de hoje dedica os
primeiros **60% da tela** a "Primeiros passos" (parado em 5 de 6 há meses,
por causa do usuário padrão) e a "O que você quer fazer?". A informação
operacional — saúde do sistema, WANs, alertas — só começa abaixo da dobra. A
máquina roda há meses; a tela ainda trata quem a usa como quem acabou de
instalar.

## 2. A descoberta que muda o trabalho: o dado já existe, e é bom

Medido na máquina de produção antes de desenhar qualquer coisa:

- `internal/tsdb.TrafficSampler` amostra **a cada 1 segundo**, por interface,
  a partir de `/proc/net/dev`.
- As séries `if.rx_bps` e `if.tx_bps` são gravadas em **quatro resoluções**:
  1s, 60s, 900s e 3600s, com poda automática.
- Há dado real e farto: a `enp3s0` registrou picos de **84 Mbps**; 719 pontos
  em 12 h, 2767 em 30 dias, 1317 em um ano.
- O endpoint `GET /api/system/traffic-history?iface=&range=` já devolve
  `timestamp`, `rx_bps` e `tx_bps` por ponto.

**Portanto esta entrega não constrói coleta.** Ela constrói a visualização
que o dado já existente merece. O risco cai muito e o resultado visível sobe.

> Registro honesto: a primeira leitura desta investigação concluiu que o
> histórico não existia — erro de parâmetro (`iface`, não `interface`) e
> depois de campo (`rx_bps`, não `rx`). Só não virou um falso achado grave
> porque foi conferido no banco antes de ser reportado.

## 3. A tela de tráfego

Um gráfico grande, não uma sparkline. Decisões, todas verificadas no mockup
com os dados reais da máquina:

**Espelhado.** Descendo para cima, subindo para baixo, no mesmo eixo. Num
firewall com duas WANs, assimetria é o que se procura, e assim ela salta.

**O ponto guarda o pico, não a média.** Ao reduzir centenas de pontos para
caber na tela, cada um carrega o **máximo** do intervalo. Média esconde
rajada, e rajada é o que derruba link.

**Escala linear por padrão, log a um clique.** Isto saiu de um problema real
que o mockup expôs: um único pico de 10,2 Mb/s domina a escala e achata os
99% do tráfego que vivem entre 100 e 600 kb/s numa linha reta — que é
exatamente o defeito da tela atual. Em log, a forma real aparece sem o pico
deixar de estar marcado. Linear continua sendo o padrão porque é ela que diz
a verdade sobre magnitude.

**Sem dado, sem linha.** Intervalo sem amostra fica em branco, nunca em zero.
`—` significa não medido; zero significa medido e deu zero.

**Uma faixa com as interfaces**, cada uma com taxa atual, minigráfico, pico e
total acumulado. Clicar troca o gráfico grande.

## 4. O painel com widgets

### 4.1 Cada admin monta o seu

Decisão do operador. O produto é multi-admin com RBAC: quem cuida de rede
quer WAN e tráfego; quem cuida de suporte quer hosts e DHCP. O layout é
preferência pessoal e é gravado por usuário.

**O catálogo respeita permissão.** Cada widget declara o que exige
(`hosts.read`, `dhcp.read`, `monitoring.read`). Widget que o usuário não pode
ver não aparece na lista — nem para adicionar. Um layout salvo que referencie
um widget cuja permissão foi revogada simplesmente não renderiza aquele
widget, sem erro e sem buraco.

### 4.2 Grade livre, com arrastar e redimensionar

Decisão do operador entre três alternativas, ciente de que era a mais cara.

Grade de **12 colunas**, altura de linha fixa, widgets com posição e tamanho
próprios. Modo de edição explícito: fora dele a tela é só leitura, sem alças
nem risco de mover algo sem querer.

### 4.3 Sem biblioteca de grade — e o que isso custa

Não se acrescenta dependência para isto. Num appliance de segurança, uma
biblioteca de layout é superfície de cadeia de suprimentos por conveniência,
e o projeto já tem postura documentada sobre isso.

**Mas a parte difícil é real, e o mockup a encontrou.** A primeira versão da
grade não tinha resolução de colisão: arrastar um widget por cima de outro
empilhava os dois no mesmo lugar. É exatamente o que a biblioteca resolveria.
O algoritmo necessário é o mesmo que elas usam no núcleo, e é obrigatório:

1. **Empurrar em cascata** — quem foi invadido desce para logo abaixo de quem
   invadiu, repetidamente, até ninguém mais colidir (com guarda contra laço
   infinito).
2. **Compactar para cima** — cada item sobe enquanto não encostar em ninguém.
   Sem isso, remover um widget deixa um buraco permanente no meio do painel.

As duas passadas rodam ao soltar o arrasto, ao redimensionar, ao adicionar e
ao remover. São ~40 linhas somadas às ~200 da grade.

### 4.4 No celular vira uma coluna

A posição salva vale no desktop. Em tela estreita os widgets empilham na
ordem que o admin definiu (por `y`, depois `x`). Não há um segundo layout
para manter — o projeto já pagou pela responsividade e não vai pagar de novo.

### 4.5 O onboarding some sozinho

"Primeiros passos" sai do painel quando os 6 passos terminam. Numa instalação
nova ele aparece, como hoje. "O que você quer fazer?" vira widget como os
outros, disponível no catálogo e desligável.

## 5. Catálogo de widgets

Todo widget precisa de fonte de dado real. A regra do projeto é explícita:
widget sem dado real é omitido, nunca preenchido com estimativa.

| Widget | Fonte | Permissão |
|---|---|---|
| Saúde do sistema | vigias já existentes | `monitoring.read` |
| Links WAN | `GET /api/links` | `links.read` |
| Tráfego das interfaces | `traffic-history` + `/api/system/status` | `monitoring.read` |
| Quem está consumindo | `GET /api/hosts/traffic` | `hosts.read` |
| Alertas abertos | `GET /api/alerts?unresolved=true` | `alerts.read` |
| CPU, memória, disco | `/api/system/status` + `metric_samples` | `monitoring.read` |
| Hosts na rede | `GET /api/hosts` | `hosts.read` |
| Primeiros passos | estado de onboarding | — |
| O que você quer fazer | estático | — |

Layout inicial, para quem já passou do onboarding: saúde, WANs e alertas na
primeira dobra; tráfego, consumo e recursos abaixo.

## 6. Persistência

O layout é uma lista de `{widget, x, y, largura, altura}` por usuário. Duas
regras que evitam o modo de falha óbvio:

- **Layout inválido nunca trava a tela.** Item que referencia widget
  inexistente (versão anterior, widget removido do produto) é descartado na
  leitura, e o resto renderiza.
- **"Restaurar padrão"** sempre disponível, para quem se perdeu arrastando.

## 7. Testes

- **Colisão e compactação** (o núcleo): arrastar sobre outro empurra em
  cascata; remover no meio faz os de baixo subirem; redimensionar para maior
  empurra; nenhuma configuração produz dois widgets ocupando a mesma célula.
  Provar por propriedade, não só por caso: para um conjunto de operações
  aleatórias, nunca existem dois itens sobrepostos.
- **Permissão**: widget fora da permissão não aparece no catálogo, e um
  layout salvo que o contenha não o renderiza nem quebra a página.
- **Gráfico**: ponto reduzido guarda o máximo, não a média; sem amostra não
  desenha linha; alternar linear/log muda a projeção e o rótulo do eixo.
- **Persistência**: layout com widget desconhecido é descartado item a item;
  "restaurar padrão" volta ao layout de fábrica.
- **VM com navegador (Firefox)**: arrastar, redimensionar, adicionar, remover
  e recarregar a página mantendo o layout; e a 390px tudo vira uma coluna na
  ordem certa.

## 8. Entrega em fases

| Fase | Entrega | Por quê nesta ordem |
|---|---|---|
| **A** | Tela de tráfego (gráfico grande, espelhado, linear/log, faixa de interfaces) | Nenhuma dependência do painel; é o componente que o widget vai reusar |
| **B** | Painel com widgets: grade, colisão, catálogo, persistência por usuário | Usa o gráfico da Fase A como um dos widgets |

## 9. Fora de escopo

- Coleta nova de métrica — não é necessária (§2).
- Layout separado por tamanho de tela (§4.4).
- Widget configurável por dentro (escolher qual interface, qual janela): o
  widget nasce com um padrão sensato; parametrizar é evolução natural depois.
- Compartilhar layout entre admins ou definir um padrão da máquina — o
  operador escolheu explicitamente "cada um monta o seu".
