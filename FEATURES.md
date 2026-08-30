# LinkGuard FW — Roadmap de Funcionalidades

## Visão

Transformar a operação manual de firewall/roteamento (hoje feita à mão em
`/etc/network/firewall.sh`) numa **plataforma gerenciada, multi-administrador e
host-cêntrica** para pequenas e médias empresas com múltiplos links WAN.

O norte é: **tudo que hoje é uma linha de bash frágil deve virar uma ação
declarativa, auditável e reversível no painel.**

### Quem usa
PMEs com múltiplos administradores. Cada admin precisa de credencial própria e
permissão por funcionalidade (RBAC), com registro de "quem fez o quê".

---

## Princípio central

> Quase toda funcionalidade nova depende de **UMA fundação**:
> **inventário de hosts da LAN + contabilização de tráfego por host.**

Resolvido isso, caem de graça: identificar hosts, medir consumo, bloquear,
agrupar e direcionar por WAN. DHCP/DNS **não** são pré-requisito para isso —
o firewall já vê todo o tráfego forwarded. Eles entram depois, como
enriquecimento (nome legível, MAC, reserva estática).

---

## Premissa de instalação: o LinkGuard toma conta da máquina

> **Instalar o LinkGuard é entregar a ele a máquina.** Ele não é um utilitário
> que convive com configuração manual — é um appliance. Tudo que ele
> gerencia e que estiver disponível na máquina, ele assume: rede, firewall,
> roteamento, DHCP, DNS, NTP, nomeação de interface.

Isso começa na própria instalação: **não se instala as dependências e depois
o LinkGuard — instala-se o LinkGuard, e ele traz o que precisa.** Numa máquina
pelada ele é o primeiro a entrar e é ele quem coordena as instalações. Na
prática:

- a base sem a qual o produto não faz nada (`nftables`, `iproute2`,
  `iptables`, `iputils-ping`) o próprio serviço garante no primeiro boot
  (`internal/bootstrapdeps`);
- por isso essa base está em `Recommends:` e não em `Depends:` no pacote:
  com `Depends:`, um `dpkg -i` numa máquina pelada para no meio (`iU`,
  "dependency problems prevent configuration"), o serviço nunca sobe e não
  sobra painel nenhum para explicar o que houve. Um pacote também não
  consegue chamar o apt dos próprios scripts — o dpkg segura o lock durante
  toda a execução —, mas um serviço em execução consegue;
- o que é opcional é instalado **sob demanda**, e não no boot — instalar no
  boot seria assumir serviços que ninguém pediu. Quem faz isso hoje, e
  exatamente quando:
  - `kea-dhcp4-server`, `unbound` e `dns-root-data`: ao salvar (ou aplicar) a
    configuração de DHCP/DNS. O apply instala e configura na mesma ação, sem
    reiniciar o serviço;
  - `chrony`: por um botão explícito na tela de NTP ("instalar chrony"). Não
    entra sozinho ao mexer na configuração de horário;
  - `smartmontools`: **não** é instalado pelo LinkGuard. Ele está em
    `Recommends:` do pacote, então quem instala com `apt install
    ./linkguard-fw_*.deb` (o caminho normal) já o recebe; num box onde ele
    falte, a checagem de saúde de disco do Vigia simplesmente reporta que não
    há dado, sem inventar nada;
- **se não conseguir instalar** (sem rede, espelho fora do ar, repositório
  quebrado), ele tenta de novo uma vez depois de atualizar o índice do apt e,
  se ainda assim falhar, **não cala**: alerta crítico no painel dizendo quais
  pacotes faltam, o que deixa de funcionar por causa de cada um e o comando
  para instalar à mão, mais o mesmo no log. O serviço continua de pé
  justamente para que exista painel onde ler isso. É a regra do "não finge"
  abaixo aplicada ao próprio ato de instalar.

A outra consequência prática, que precisa estar clara para quem instala: ele
**reaplica a própria configuração em todo boot**. Edição feita à mão nos
arquivos que ele gerencia é sobrescrita — de propósito. É isso que torna o
painel a fonte de verdade em vez de um amontoado de arquivos editados na
unha (ver "Visão").

Regras de convivência que o projeto segue para que isso não vire hostilidade:

- **Drop-in em vez de sequestro**: onde o pacote tem config própria
  (`chrony.conf`, `unbound.conf`), o LinkGuard escreve um arquivo separado ao
  lado, para que atualização de pacote nunca brigue com ele. A exceção é o
  `/etc/nftables.conf`, que ele possui — e desde a v1.0.94 grava ali **só a
  própria tabela**, depois de um incidente em que capturou uma regra alheia e
  a ressuscitou em todo boot.
- **Só o que é dele**: nunca dá flush no ruleset inteiro nem em tabela de
  terceiros; limpa apenas os próprios chains.
- **Não finge**: se o pré-requisito não existe (pacote ausente, serviço
  parado), ele registra e não age — em vez de aplicar meia configuração. Ex.:
  não assume o `resolv.conf` se o unbound não estiver instalado, porque isso
  deixaria a máquina sem resolução alguma.
- **Fora de escopo é fora de escopo**: hoje não mexe em
  `/etc/network/interfaces` (ifupdown segue manual) nem em nada não
  relacionado a rede.

A lista completa e atual do que ele assume está no `README.md`, na seção de
aviso de instalação — mantê-la honesta é parte do contrato com quem instala.

---

## Regra de entrega (inegociável)

> **Nada é só interface visual. Tudo que é implementado tem que funcionar de
> verdade e tem que estar no painel, para o admin habilitar, desabilitar e
> gerenciar por inteiro — sem SSH.**

Uma funcionalidade só está pronta quando as três coisas são verdade ao mesmo
tempo:

1. **Funciona de fato no sistema** — aplica o estado real (arquivo de config,
   regra de nftables, serviço recarregado), não só grava no banco. Se depende
   de um pré-requisito ausente (pacote não instalado, serviço parado), diz
   isso claramente em vez de fingir sucesso.
2. **É gerenciável pelo painel** — ligar, desligar, editar e ver o estado
   atual, com a permissão RBAC correspondente. Um recurso que só existe por
   arquivo de configuração ou linha de comando não conta como entregue.
3. **É verificável pelo painel** — o admin consegue ver se está de fato
   valendo. Config aplicada ≠ funcionando: checar o arquivo não substitui
   provar o comportamento (ex.: o vigia de DNS faz uma consulta real, não só
   lê o `resolv.conf`).

Corolário prático: **backend sem tela não é entrega**, e **tela sem efeito
real é pior que não ter** — cria confiança falsa, que é exatamente o que
esta plataforma existe para eliminar.

---

## Decisões transversais (fundação)

### F1 — nftables nativo, declarativo e idempotente
O backend do kernel já é nftables (Debian 13). A mudança é trocar o frontend
imperativo (`iptables -A ...` append-only) por **geração de ruleset `nft`
declarativo**, aplicado de forma atômica (flush+load). Benefícios diretos:
- acaba a duplicação de regras ao reaplicar (problema real hoje);
- `map` saddr→mark resolve "grupo de host → WAN" em uma regra;
- `set` nomeado resolve "bloquear/desbloquear host" sem recarregar nada.

### F2 — RBAC multi-admin
Hoje a auth é single-user (`admin/admin` + JWT). Evoluir para:
- usuários, papéis e permissão por funcionalidade (ex.: quem pode mexer em
  WAN/rotas vs. quem só vê relatórios);
- todo comando de escrita checa permissão e grava **quem** no audit log;
- avaliar integração com AD/Samba (o servidor já roda `winbind`) como opção
  futura de autenticação.

### F3 — Identidade + contabilização de host
- **Identidade**: `ip neigh` (IP↔MAC) + leases DHCP (hostname) + conntrack.
- **Contabilização**: contadores nft por host (`update @acct_up { ip saddr }`
  em base chain própria, depois da filtragem), agregados com *rollup* temporal.
  O caminho por `net.netfilter.nf_conntrack_acct=1` foi tentado primeiro e
  **não serve**: conexão fechada some do conntrack e leva os bytes junto.

### F4 — Armazenamento
- **Manter SQLite** para config/estado (links, regras, grupos, hosts, usuários,
  alertas). Trocar por Postgres mataria a vantagem de "binário único, drop-in".
- O dado que escala é **série temporal por host**. Resolver com *downsampling*
  estilo RRD (1s→1min→1h→1dia), estendendo o `internal/tsdb` (antigo
  `trafficrrd`) para a dimensão por host — feito na #113, com a série `host.*`
  amostrada a cada 10s e teto de 50 rótulos por amostra, o excedente somado em
  "outros". **Não** jogar série temporal crua no banco.

---

## Fases

### Fase 0 — Saneamento do que já existe
> **Atualizado (14/08).** O caminho real não foi "importar e corrigir" o
> `firewall.sh` — foi substituí-lo por um modelo nativo em nftables
> (`table inet linkguard`), reconciliado do zero a cada boot. Os problemas
> que esta fase queria resolver estão resolvidos por essa via; nenhum deles
> sobrevive porque o script antigo não roda mais.
- [x] Importar `firewall.sh` para o modelo declarativo do LinkGuard — via
      reescrita completa, não importação do script.
- [x] Eliminar regras/`ip rule` duplicadas (causadas pelo append-only) — o
      modelo novo reconstrói cada chain do zero a cada reconciliação, nunca
      acrescenta.
- [x] Unificar persistência (hoje há `netfilter-persistent` **e** `rc.local` —
      escolher uma fonte de verdade: o LinkGuard) — `netfilter-persistent` e
      `rc.local` não são mais usados; o banco é a única fonte de verdade.
- [x] Escopar o `MASQUERADE` por interface WAN (hoje é global, sem `-o`) —
      `oifname { "wan1", "wan2" } masquerade`, nunca global.
- [x] Remover linha morta `ip rule add 192.168.18.1 from sumicity` — o script
      que a continha não existe mais.

### Fase 1 — Firewall básico em 1 clique
Para máquinas que querem virar firewall "do zero".
- [x] Habilitar `ip_forward` + NAT (MASQUERADE) escopado por WAN.
- [x] Política FORWARD sã por padrão — decisão diferente da esperada
      originalmente: a política é sempre `accept` (nunca restritiva), e o
      bloqueio é só por regra explícita. É deliberado — numa máquina só
      acessível remotamente, uma política restritiva tranca o operador para
      fora no instante em que é aplicada. Ver `docs/TRAJETORIA.md`.
- [x] **Grupos de regras via chains nativas** (nft chains) — ativar/desativar um
      grupo inteiro removendo/inserindo o jump, sem mexer regra a regra. Tela
      própria ("Grupos de regras"), com Direcionamento por WAN / Destinos
      bloqueados / Hosts bloqueados numa aba separada ("Bloqueios e
      direcionamento").

> **Mudança de comportamento (Fase C1):** hosts e destinos bloqueados agora
> são avaliados **antes** das regras do admin e sempre vencem — antes era o
> contrário, e um `accept` de grupo conseguia anular um bloqueio. Quem
> atualizar uma instalação em produção precisa revisar bloqueios e grupos:
> algo que hoje passa por causa de uma regra de grupo pode passar a ser
> bloqueado depois da atualização.

### Fase 2 — Host-cêntrico (a fundação que destrava o resto)
- [x] Inventário de hosts da LAN trafegando dados (ip neigh + conntrack).
- [x] Consumo de rede por host — **entregue de verdade só nas issues #112 e
      #113**, e esta linha esteve errada até 2026-08-20. O que existia era
      leitura instantânea de `/proc/net/nf_conntrack`, que só contém conexão
      viva: o host que baixou 5 GB há dez minutos aparecia com zero, e não
      havia rollup nenhum — a série `host.*` não existia no tsdb. Hoje a
      contagem vem de sets com `counter` no nftables (#112) e o rollup
      temporal existe, amostrado a cada 10s e rotulado por MAC (#113).
- [x] **Bloquear host em 1 clique** (named set nft; add/remove atômico).

### Fase 3 — Grupos de host → WAN
Produtiza as linhas `mangle MARK` que hoje são editadas na mão.
- [x] Criar grupos de host e atribuir a uma WAN (fwmark → tabela de rota).
- [x] Implementar como `map` nft saddr→mark (uma regra, N hosts) —
      `meta mark set ip saddr map @host_wan`, exatamente uma regra.
- [x] **Barrar e direcionar por domínio** (#123) — o alvo da regra deixa de ser
      só endereço. Direcionar entra no mesmo mapa `host_wan` ("estes serviços
      saem pela WAN2"); barrar entra na chain de destinos bloqueados que já
      existia. Todo alvo nasce em **ensaio** — aprende os endereços e conta a
      rotatividade sem escrever uma linha no kernel — e só escreve quando
      promovido. Leia junto a armadilha do DNS em "Não-faça": isto é bom para
      direcionar e fraco contra quem quer escapar.
- [ ] **Identificar por MAC/reserva**, não por IP solto (ver Fase 5) — hoje o
      pin por IP dentro do range DHCP dinâmico é frágil. **Ainda não feito**:
      o mapa de direcionamento (`host_wan`) é indexado por IP puro; o vínculo
      com a reserva DHCP por MAC não existe. Verificado em 14/08, é o maior
      item real ainda em aberto deste documento.

### Fase 4 — Rebalanceamento agendado (requisito do cliente)
Mover hosts pesados para o link de maior capacidade — **sem** automação em
tempo real (que quebraria conexões ativas).
- [x] Política configurável pelo admin (agendamentos por dia/horário, com o
      peso de cada link) — mais simples do que "limiares + qual WAN é a
      maior": o admin define o peso de cada agendamento diretamente, sem
      heurística automática de capacidade.
- [x] Execução **agendada** (ex.: madrugada ou 2x/dia), janela de poucas conexões.
- [ ] **Preview / dry-run** antes de aplicar; aplicar = repinagem determinística.
      **Não feito**: o agendamento aplica direto, sem etapa de préviamento.
- [ ] Modo "sugerir e aprovar com 1 clique" como alternativa ao automático.
      **Não feito.**

### Fase 5 — Absorver DHCP e DNS (serviços que já são operados na mão)
O servidor já roda `isc-dhcp-server` + `bind9`. Trazer pro painel.
- [x] **DHCP**: migrar `isc-dhcp` (EOL) → **Kea**, com reservas estáticas por
      MAC.
- [x] **DNS**: log de queries por host (visibilidade) + filtro opcional por
      blocklist (via `local-zone` do unbound). **DNS não é enforcement** — o
      bloqueio real continua no firewall. Desde a #123 essa frase deixou de ser
      só uma ressalva e virou o desenho: o resolver vê a **resposta** (#116) e
      alimenta um `set` com timeout, a regra casa no set, e quem descarta o
      pacote continua sendo o firewall. O DNS aponta o alvo; não o defende.

---

## Não-faça / armadilhas

- **Não** auto-balancear hosts em tempo real → quebra conexões (NAT preso ao IP
  da WAN). Só agendado ou só para fluxos novos.
- **Não** trocar SQLite por Postgres → mata o "binário único". Escala de métrica
  se resolve com rollup, não com outro banco.
- **Não** tratar DNS como controle de acesso → burlável com DoH/DNS fixo. O
  alvo por domínio (#123) **não revoga isto**. Errar o direcionamento manda
  tráfego pelo link errado, e paciência; o mesmo mecanismo como bloqueio não
  segura quem fixa IP no cliente, usa DoH ou VPN, e CDN grande ainda resolve
  para dezenas de endereços rotativos e compartilhados. A tela tem de dizer
  essa diferença, senão vende como controle o que é preferência de rota.
- **Não** fixar host em WAN por IP dentro de range DHCP dinâmico → use MAC/reserva.
- **Não** entregar backend sem o controle correspondente no painel → o admin
  fica dependente de SSH, que é justamente o que a plataforma existe para
  eliminar (ver "Regra de entrega").
- **Não** dar como saudável o que só foi *configurado* → verificar o arquivo
  não prova que o serviço responde. Em 2026-08-10 o painel ficou verde com o
  DNS do próprio firewall quebrado porque o vigia só lia o `resolv.conf`.

---

## Decisões pendentes (precisam de definição)

1. **DHCP**: Kea (API-first, recomendado) vs. dnsmasq (DHCP+DNS num daemon só)?
2. **Autenticação de admin**: local (no SQLite) apenas, ou também via AD/winbind?
3. **Escopo do nftables**: migrar tudo de uma vez ou conviver com as regras
   legadas durante a transição?
