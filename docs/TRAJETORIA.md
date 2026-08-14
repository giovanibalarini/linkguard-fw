# Trajetória do LinkGuard FW

Dois meses, de 17 de junho a 13 de agosto de 2026. 561 commits. Uma máquina de
produção que nunca ficou fora do ar por causa de um deploy.

Este documento não é um changelog — o `git log` já faz isso. Ele existe para
explicar **por que** o produto tem a forma que tem. Quase toda decisão de
desenho aqui é cicatriz de alguma coisa que deu errado, e quem for mexer no
código merece saber de qual.

---

## O ponto de partida

Uma empresa pequena com duas conexões de internet e um Debian fazendo de
firewall. A operação era manual: regras de `iptables` empilhadas num
`rc.local`, um `/etc/network/interfaces` que ninguém ousava tocar, uma
configuração de DHCP que uma pessoa só entendia. Funcionava — do jeito que
essas coisas funcionam, até o dia em que alguém precisa mexer e não sabe o que
vai quebrar.

O objetivo nunca foi "uma interface para o iptables". Foi tirar a rede da
cabeça de uma pessoa e colocá-la num lugar onde ela pudesse ser vista,
alterada e **verificada** por quem chegasse depois.

Disso saiu a regra que governa o projeto inteiro e que está no README como
inegociável:

> Nada aqui é maquete. Tudo que for implementado tem que funcionar de verdade
> no sistema e ser gerenciável pelo painel — ligar, desligar, editar e
> conferir — sem SSH.

E o corolário, que é o que dá trabalho: **configurado não é o mesmo que
funcionando**. Um vigia que só lê um arquivo de configuração não prova nada.
Se o painel não consegue mostrar que a coisa está valendo no kernel, a
funcionalidade não está pronta.

---

## Junho — o MVP, e a primeira virada

O começo foi o previsível: listar regras de `iptables`, mostrar links WAN,
gráficos de tráfego. Uma semana depois veio a primeira decisão que mudou o
projeto: **abandonar o `iptables` e passar a gerenciar `nftables` nativo**.

O motivo não foi modernidade. Foi que o `iptables` não tem como um programa
ser dono de um pedaço do firewall. Você acrescenta regras numa chain global e
torce para ninguém mais mexer. Com `nftables` dá para ter uma tabela própria
— `table inet linkguard` — e daí sai o modelo que sustenta tudo:

> **O banco é a verdade. O nftables é o resultado renderizado, reconstruído a
> cada boot. O LinkGuard nunca dá flush no ruleset inteiro nem toca na tabela
> de outro programa.**

Ainda em junho entraram RBAC multi-admin, o inventário de hosts da LAN, e a
gestão de DHCP (Kea) e DNS recursivo (unbound). Foi aí que o produto deixou de
ser um painel e virou um **appliance**: ele passou a instalar e configurar
serviços do sistema, e a impor a própria configuração a cada boot. O README
tem uma seção inteira avisando disso, porque é o tipo de coisa que precisa
estar escrita antes de alguém instalar numa máquina que faz outra coisa.

## Julho — profundidade, e as primeiras cicatrizes

Julho foi o mês de tornar o appliance confiável em vez de apenas completo.

**Balanceamento e failover multi-WAN**, com um detalhe que só aparece na
prática: quando um link degrada e você tira o tráfego dele, as conexões já
estabelecidas **não migram** — o conntrack as mantém presas ao NAT antigo. Uma
chamada de vídeo continua morrendo num link ruim mesmo depois de o
balanceamento já ter mudado. Daí nasceu a expulsão ativa de fluxos, com
debounce e período de carência, porque expulsar cedo demais é pior que não
expulsar.

**Observabilidade própria**: um banco de série temporal embutido, amostrando
`/proc/net/dev` a cada segundo, com agregações em 60s, 900s e 3600s e poda
automática. Sem Prometheus obrigatório, sem dependência externa para o produto
funcionar sozinho.

**Cofre de segredos**, **backup agendado criptografado**, e uma camada de IA
opcional no modelo BYOK — o operador traz a própria chave, e ela só aconselha;
nunca decide sobre firewall ou roteamento. Essa fronteira está escrita na
spec: o determinismo do balanceamento não é negociável.

**A reforma de interface** (v1.0.72 a v1.0.78) e a responsividade mobile
(v1.0.81). Aqui vale o registro de método: a reforma foi feita tela a tela,
com verificação visual em navegador de verdade a cada passo. Duas vezes o
resultado só ficou bom porque a captura de tela mostrou algo que nenhum teste
mostraria.

E **uma revisão de segurança** no fim do mês, que achou e corrigiu execução
remota de código na integração com WireGuard e uma escalação de privilégio no
RBAC (v1.0.80).

### O incidente que mudou como se faz migração

**24 de julho.** Um deploy com uma migração de schema **sem transação**. A
migração travou no meio, e o serviço não subiu — por mais de 50 minutos, sem
nenhum monitor de failover rodando, numa máquina que é o firewall da empresa.
Rollback, correção e redeploy no mesmo dia.

A regra que saiu daí é absoluta e está em todo plano desde então: **toda
migração de schema em transação**. Não é boa prática; é a coisa que impediu o
repeteco.

### O bug que nenhum teste unitário pegaria

O apply de DHCP **sempre falhava**. Os testes passavam, a lógica estava certa,
o arquivo gerado estava correto. O perfil AppArmor do `kea-dhcp4` só lê de
`/etc/kea/` — e o código escrevia num arquivo temporário em `/tmp` antes de
mover. Corrigido na v1.0.73.

Esse foi o primeiro de vários. A lição virou prática: **teste verde não é
prova; saída de comando numa máquina de verdade é.** Todo release passa por
uma VM descartável, instalada do zero, antes de tocar a produção.

---

## Agosto — o firewall levado a sério

### A troca de disco

**10 de agosto.** Migração de disco na máquina de produção, ao vivo. E a
descoberta de que **nomes de interface física não são estáveis**: depois do
boot, a WAN1 mudou de `enp4s0` para `enp5s0`. Isso quebrou três coisas em
cascata — o `/etc/network/interfaces`, o registro do link no banco, e a regra
de masquerade do nftables. O NAT simplesmente não subiu.

Duas coisas saíram disso: **nomeação de interface fixada por MAC address**
(`.link` files no systemd-networkd), e a percepção de que o LinkGuard precisava
**reconciliar o firewall a partir do estado atual da máquina no boot**, em vez
de confiar num arquivo gravado. O que existia era estático; virou reconciliação.

### A reforma da tela de firewall

A tela de regras era uma lista plana. O operador disse, com todas as letras:

> "No LinkGuard se trabalha muito com chains, que são uma espécie de grupos de
> regras. Na aba 'regras' é exatamente isto, mas com esse nome fica horrível e
> a forma como se organiza lá também acho muito feio."

Daí saíram os **grupos de regras**: chains apresentadas como grupos ordenados,
com condição de entrada ("só o tráfego vindo desta rede chega nestas regras"),
arrastar para reordenar, e ligar/desligar sem apagar. A abstração escondeu a
palavra "chain" sem esconder o que ela faz — a pré-visualização continua
mostrando a linha `nft` que vai para o kernel.

Uma restrição do operador que virou regra do projeto: **nomes clássicos de
ação não se traduzem.** `accept`, `drop`, `reject`, `jump` aparecem em inglês e
em fonte monoespaçada, porque é isso que a pessoa vai procurar na
documentação do nftables. A prosa ao redor é em português.

### A rede de proteção contra lockout

Até agosto, todo o produto mexia em tráfego **atravessando** o firewall. Um
erro ali derruba a rede da empresa — grave, mas o operador ainda tem SSH e
painel para consertar.

A fase seguinte alcançava o tráfego **destinado ao próprio firewall**: SSH, o
painel, DNS, Samba. Um erro aí tranca o operador para fora de uma máquina
remota, possivelmente de madrugada e sem acesso físico.

Essa capacidade só é aceitável com uma rede embaixo, e ela foi construída
antes da capacidade: **confirmar-ou-reverter**. O operador aplica, tem 90
segundos para testar que ainda tem acesso, e confirma. Se não confirmar —
porque acabou de cortar o próprio SSH — o LinkGuard reverte sozinho. O estado
pendente mora no banco, então um reboot ou uma queda de energia dentro da
janela também revertem, em vez de tornar permanente um bloqueio que ninguém
confirmou.

Três revisões independentes barraram o deploy dessa entrega. O que elas
acharam, cada uma provada com sonda executada e não com leitura:

- a reversão apagava a própria rede de proteção **antes** de saber se tinha
  conseguido reverter — se a reconciliação falhasse, a regra perigosa ficava
  viva, o watchdog desarmado, e nada tentava de novo;
- um reconcile parcialmente falho deixava a regra de input viva no kernel e no
  banco, **sem janela**, e o operador lia "erro interno do servidor";
- duas mutações simultâneas: as duas valendo, só uma com rede embaixo;
- um beco sem saída em que o painel virava somente-leitura sem confirmar, sem
  reverter e sem conseguir consertar — a saída era `sqlite3` na máquina;
- e a suíte de testes escrevia no `/etc/nftables.conf` **real**: rodar
  `go test` como root na própria appliance apagaria o firewall de boot.

Na VM, 15 cenários — incluindo corte de energia com `kill -9` dentro da janela
e o LinkGuard mascarado para não subir. Em todos, o acesso voltou sozinho.

### A pergunta do `ct state established`

Depois da entrega, o operador perguntou: não faz sentido ter
`ct state established accept` na chain de input?

É a pergunta certa, e a resposta acabou sendo não — pelo motivo menos óbvio.
Com `established accept`, a sessão SSH do operador **sobrevive ao próprio
bloqueio**. Ele testa nos 90 segundos, vê tudo funcionando, confirma, e
descobre o problema na próxima reconexão, quando já não há rede de proteção
nenhuma. O `established` faz o teste da janela **mentir**.

O que faltava de verdade era outra coisa: `ct state related`, que fecha uma
armadilha de Path MTU Discovery — um grupo que bloqueia ICMP faz o SSH
conectar e travar no primeiro pacote grande, sem nada na tela explicando. E,
como capacidade nova, a escolha **por grupo** de valer só para conexões novas
(`ct state new`), com um aviso obrigatório na janela de confirmação dizendo,
com todas as letras, que a sessão atual não é afetada e que é preciso abrir uma
conexão nova para testar de verdade.

Medido na VM: a transferência em curso sobrevive 42 segundos ao bloqueio "só
novas", e morre em menos de 11 segundos no modo "toda conexão".

### O painel que a máquina merecia

O painel dedicava os primeiros 60% da tela a "Primeiros passos" — parado em 5
de 6 há meses, por causa do usuário padrão — e a "O que você quer fazer?". A
informação operacional só começava abaixo da dobra. A máquina rodava há meses;
a tela ainda tratava quem a usava como quem tinha acabado de instalar.

Virou uma grade de 12 colunas com widgets que cada admin escolhe, layout
gravado por usuário, catálogo filtrado por permissão de RBAC. A parte difícil
não foi a tela: foi a **resolução de colisão** — empurrar em cascata e
compactar para cima — escrita à mão, porque acrescentar uma biblioteca de
layout num appliance de segurança é comprar superfície de cadeia de
suprimentos por conveniência. A prova é por propriedade: para 500 operações
pseudoaleatórias, nunca existem dois widgets na mesma célula.

E a tela de tráfego, que o operador pediu assim: *"pensa em elaborar uma
página web no dash com tráfego em tempo real do link das interfaces. É bonito
de ver."* Gráfico espelhado, e cada coluna guardando o **pico** do intervalo em
vez da média — porque média esconde rajada, e rajada é o que derruba link.

---

## O método

Vale registrar, porque explica o número de bugs achados antes da produção.

**Especificação antes de plano, plano antes de código.** Toda entrega começa
por um documento em `docs/superpowers/specs/` que registra as decisões **e as
alternativas descartadas, com o motivo**. Meses depois, a pergunta que aparece
não é "o que faz isso?", é "por que não fizeram do jeito óbvio?".

**Implementador e revisor são independentes.** Quem escreve não revisa. O
revisor recebe o diff, as restrições do projeto, e a instrução de verificar
qualquer achado crítico **de fato** — por mutação, por sonda executada — antes
de reportar, porque achado crítico falso custa tanto quanto bug perdido.

**Prova por mutação.** Um teste só conta depois de alguém quebrar a
implementação de propósito e ver o teste ficar vermelho. Nesta base isso já
pegou vários testes que passavam com a funcionalidade inteira arrancada — e,
mais de uma vez, foi o próprio autor da mutação que percebeu que ela tinha
passado verde sem exercitar nada, e refez.

**Fixture de teste que envolve saída de ferramenta tem que ser a saída real da
ferramenta.** O `nft` aspeia nomes de interface e canonicaliza máscaras. Um
bug crítico já passou por cinco testes verdes porque as fixtures tinham sido
escritas à mão, no formato que o gerador produzia e não no que o kernel
devolvia.

**Validação numa VM que nasce pelada.** Sem `nftables`, sem Kea, sem unbound,
sem chrony. O LinkGuard tem que ser o primeiro e instalar o resto — porque
pré-instalar as dependências mascararia exatamente o que precisa ser provado.
Foi assim que se descobriu que a instalação travava num prompt de conffile do
dpkg, que nenhum teste unitário jamais mostraria.

**A produção só recebe o que a VM aprovou.** E quando algo muda depois da
validação, revalida. Nas palavras do operador:

> "É melhor esperar 1 dia corrigindo problema e testando do que instalar algo
> que não funciona e vai precisar voltar pra prancheta pra corrigir."

---

## Onde está hoje

Uma máquina de produção com duas WANs, rodando desde julho. Firewall nftables
com grupos de regras e rede de proteção contra lockout, DHCP, DNS recursivo,
NTP servindo a LAN, inventário de hosts, tráfego em tempo real e painel
montável por admin.

**O que ainda incomoda**, e está registrado no código:

- O painel marca um grupo como "aplicada" pela **presença** do jump, não pela
  forma dele. Apertar esse critério traz de volta um falso "configurada, não
  aplicada" que já custou uma correção — então a dívida está documentada com
  o que foi medido, em vez de consertada às pressas.
- `/etc/network/interfaces` ainda é gerido à mão nas instalações atuais; a
  migração para systemd-networkd está desenhada mas não concluída.
- O produto roda **uma** máquina. Tudo aqui é honesto sobre uma amostra de um.

---

*Se você chegou até aqui avaliando se deve usar isto: leia a seção "LinkGuard
takes over the machine" do README antes de qualquer coisa. Ele é um appliance,
e a premissa é que instalar o LinkGuard é entregar a máquina a ele.*
