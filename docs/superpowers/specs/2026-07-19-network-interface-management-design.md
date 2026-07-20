# Gerenciamento de interfaces de rede

**Data:** 2026-07-19
**Status:** desenho aprovado, pronto para plano de implementação

---

## 1. Problema

Hoje o LinkGuard não configura interface nenhuma. A página `web/src/pages/Interfaces.tsx`
é exclusivamente monitoramento de tráfego (lê `/api/system/status`, que por sua vez lê
`/proc/net/dev`), e `internal/links/service.go` assume que a interface WAN **já existe e já
está endereçada** — o endereçamento real é feito na mão, em `/etc/network/interfaces` e
`firewall.sh`, direto no servidor.

Isso impede o produto de ser um appliance: para colocar uma caixa em produção ainda é
preciso SSH e edição manual de arquivo. É a lacuna que separa o LinkGuard de um pfSense.

Este documento desenha a camada que faltava: **modelar, aplicar, diagnosticar e reverter a
configuração de interfaces de rede pelo painel.**

## 2. Princípio norteador

A tela **não é um CRUD de interfaces**. Configurar interface é atividade de dia zero — depois
que a caixa sobe, ninguém mexe nisso por meses. O que o administrador faz toda semana é
*entender* a rede física e, ocasionalmente, *mexer nela sem medo*.

Portanto a tela responde, nesta ordem de importância:

1. **"O que está acontecendo?"** — cabo caiu, porta negociando velocidade errada, erro acumulando.
2. **"Qual porta é essa?"** — identificação física quando o admin está na frente do rack.
3. **"O que mudou, e como eu volto?"** — histórico e restauração.
4. **"Como eu monto isso?"** — criação guiada que não deixa montar errado.

A configuração declarativa é o meio. O diagnóstico é o uso diário.

## 3. Escopo

### Dentro do v1

- Tipos: interface **física**, **VLAN 802.1Q** e **bridge**
- Endereçamento IPv4: **estático**, **DHCP** e **nenhum** (membro de bridge / L2 puro)
- Aplicador **systemd-networkd**
- **Commit/confirm** com rollback automático
- **Importador** do estado real da máquina + adoção gradual + detecção de deriva
- **Diagnóstico físico**: carrier, velocidade/duplex negociados, contadores de erro
- **Identificação física**: piscar LED da porta (`ethtool -p`) e MAC visível
- **Descrição livre** por interface
- **Histórico de versões** da config de rede, com restauração
- **Fluxos guiados** por tarefa, com modo avançado (formulário cru)

### Fora do v1, explicitamente

| Item | Por quê |
|---|---|
| **PPPoE** | Exige `pppd` como segundo aplicador inteiro (peers, chap-secrets, supervisão de discagem). Nenhuma WAN de produção usa. O modelo já reserva `Kind = "pppoe"`. |
| **Bonding / LAG** | Raro em PME e exige switch compatível. Modelo reserva `Kind = "bond"`. |
| **Configuração de IPv6** | v1 **exibe** IPv6 mas não configura (ver §9.1). |
| **Migração do servidor de produção** | Spec separado — ver §14. |
| **Criação em lote de VLANs** | YAGNI para o porte de rede alvo. |

## 4. Decisões e suas razões

| Decisão | Razão |
|---|---|
| LinkGuard é **fonte da verdade** da config de rede | É o que transforma o produto em appliance. Sem isso o admin continua precisando de SSH. |
| Adoção **gradual** via flag `Managed` | O destino é posse total, mas o caminho é interface por interface, não um salto. Reduz o risco no servidor que já está em produção. |
| Aplicador **systemd-networkd** | Declarativo e idempotente (mesma filosofia do nftables em `FEATURES.md` F1); VLAN e bridge são nativos; reload gracioso. Já vem com o systemd no Debian 13. |
| **Commit/confirm** com rollback automático | O servidor é acessado remotamente. Sem isso, uma config errada custa uma visita presencial. |
| Sem indireção de nomes (`WAN`/`OPT1`) | O pfSense mantém dois nomes para a mesma coisa e o `OPT1` não descreve nada. Aqui a interface se chama pelo nome real, com apelido livre por cima. |
| VLAN aparece na lista **sem passo de atribuição** | Elimina a pegadinha mais comum do pfSense ("criei a VLAN e ela não aparece"). |

## 5. Arquitetura

```
internal/netif/            modelo, validação, grafo de dependência, interface Provider
internal/netif/networkd/   provider systemd-networkd (render + apply + state)
internal/netif/importer/   lê o estado real da máquina → modelo
internal/netif/history/    versões da config, diff e restauração
```

O padrão espelha `internal/netsvc` (modelo agnóstico + `Provider`, com o backend concreto
em `internal/keaunbound`), que já está validado no produto.

### 5.1 Modelo

```go
type Kind string // "physical" | "vlan" | "bridge"   (reservados: "pppoe", "bond")

type Iface struct {
    Name        string   // nome no SO — eth0, vlan100, br10. Chave de ligação.
    Kind        Kind
    Alias       string   // nome curto (reusa /api/system/interface-aliases)
    Description string   // documentação livre: "patch painel P12, sala dos servidores"
    Parent      string   // vlan: NIC pai
    VLANID      int      // vlan: 1–4094
    Members     []string // bridge: interfaces membro
    AddrMode    string   // "static" | "dhcp" | "none"
    CIDR        string   // static: 192.168.3.3/24
    Gateway     string
    MTU         int
    Role        string   // "wan" | "lan" | "unassigned" — rótulo, não comportamento
    Managed     bool     // false = existe na máquina, LinkGuard não mexe
    Enabled     bool
}
```

Três pontos que sustentam o resto:

**`Name` é a chave de ligação, e é imutável.** `netsvc.Config.Interface` e
`storage.Link.Interface` já são a string do nome (`"br10"`). Interfaces viram entidades de
primeira classe sem quebrar nada do que já existe.

Como consequência, **renomear não é uma operação no v1**: o nome é a chave primária no banco e
na API (`/api/interfaces/{name}`), e mudá-lo quebraria silenciosamente as referências em
`Link` e na config de DHCP. Trocar o nome de uma interface virtual significa excluir e recriar,
o que força o admin a enxergar as referências que serão afetadas. Para nome amigável existe o
`Alias`.

**`Managed` habilita a adoção gradual.** O importador cadastra tudo com `Managed=false`; o
LinkGuard só renderiza config de quem foi adotado explicitamente.

**`Role` é rótulo, não comportamento.** Quem define que uma interface é WAN de verdade
continua sendo o `Link` que aponta para ela. Não criar um segundo lugar que decide isso.

**`Alias` reusa o que já existe.** `GET/PUT /api/system/interface-aliases` já está implementado
e devolve um mapa nome→apelido. Não criar mecanismo paralelo.

### 5.2 Regras de integridade

Vivem em `internal/netif` como funções puras — são a maior fonte de bug neste tipo de feature:

- VLAN exige `Parent` existente e `VLANID` entre 1 e 4094
- não pode haver duas VLANs com o mesmo `(Parent, VLANID)`
- membro de bridge não pode ter endereço próprio (`AddrMode` deve ser `"none"`)
- uma interface não pode ser membro de duas bridges
- uma bridge não pode ser membro de si mesma, direta ou indiretamente (sem ciclos)
- não se pode excluir interface referenciada por um `Link` ou pela config de DHCP
- `AddrMode="static"` exige `CIDR` válido; `Gateway`, se presente, deve estar dentro da rede

### 5.3 Provider

```go
type Provider interface {
    Render(ifaces []Iface) []ConfigFile               // puro — alimenta o preview do diff
    Apply(ctx context.Context, ifaces []Iface) (string, error)
    State(ctx context.Context) ([]LiveIface, error)   // estado real, via networkctl -j
}
```

O `Render` produz arquivos com prefixo numérico para garantir ordem de resolução — físicas
em `10-`, VLANs em `20-`, bridges em `30-` — e **cada arquivo carrega um cabeçalho
`# managed by linkguard`**.

Esse cabeçalho define o que o LinkGuard pode apagar. Arquivo sem ele nunca é tocado, mesmo
no modo de posse total. É a diferença entre "eu gerencio a rede" e "eu apago config que não
é minha".

O `Apply` escreve em staging, faz swap atômico sobre `/etc/systemd/network/` removendo
apenas arquivos marcados que sumiram do modelo, e então chama `networkctl reload`.

**Ressalva conhecida:** `reload` sozinho não cobre tudo. Remover um `.netdev` ou trocar o
tipo de uma interface exige `networkctl reconfigure` na interface afetada. O aplicador
precisa derivar essa lista a partir do diff entre o estado anterior e o novo. É a parte mais
delicada da implementação.

## 6. Commit/confirm

Envolve o `Apply` por fora:

1. Antes de aplicar: snapshot dos arquivos atuais + do estado do banco, gravado como
   `pending_change` com um **deadline** (padrão 90s, ajustável).
2. Aplica.
3. A UI mostra um banner com contagem regressiva e o botão **"Confirmar — está tudo funcionando"**.
4. Silêncio até o deadline → restaura o snapshot, `networkctl reload`, e abre um alerta via
   `internal/alerts` descrevendo o que foi revertido.

**O clique de confirmar é a própria prova de conectividade** — é uma requisição autenticada
que só chega se a rede continuar funcionando. Não é preciso inventar health check.

Dois requisitos não óbvios:

- O deadline vai **persistido no SQLite**, não apenas numa goroutine. Um restart do LinkGuard
  no meio da janela não pode fazer uma mudança não confirmada virar permanente por acidente.
- Se o rollback disparar, a mudança que falhou fica **salva como rascunho**. O admin volta,
  encontra o que tentou fazer, e corrige — em vez de digitar tudo de novo.

## 7. Importador, adoção e deriva

O importador lê o estado real com `ip -j link`, `ip -j addr` e `networkctl -j`, e deriva o
modelo: identifica bridge e seus membros (`linkinfo.info_kind`, `master`), VLAN e sua tag
(`linkinfo.info_data.id`), endereçamento estático versus DHCP.

**`/api/system/status` não serve para isso** — ele devolve nome e endereços, mas não o tipo
nem o pai, então não há como saber que `br10` é bridge nem quem são seus membros.

Tudo entra com `Managed=false`, exibido como **"detectada — não gerenciada"** com um botão
*Adotar*. Adotar é a única ação que muda o mundo: marca `Managed=true` e a partir dali o
LinkGuard renderiza aquela interface.

O importador roda no boot e sob demanda, é **idempotente e não-destrutivo**: reimportar nunca
sobrescreve o que já foi adotado.

**Deriva.** Se o estado real divergir do modelo de uma interface gerenciada — alguém entrou
por SSH e mexeu na mão — a UI mostra como *deriva*, com diff lado a lado e a opção de
reaplicar ou reimportar. **Não corrigir automaticamente:** config de rede divergindo em
silêncio é como se perde a confiança na ferramenta.

### 7.1 Classificação de ruído (requisito, não polimento)

O QA nesta máquina mostrou **22 interfaces** em `/api/system/status`, a maioria bridges do
Docker (`br-0293233c552c`, `docker0`, …). Numa lista plana as duas interfaces que interessam
ficam perdidas no meio de dezoito irrelevantes. Num firewall real o ruído vem de WireGuard e
túneis, mas vem.

O importador classifica e agrupa como **interface de sistema** (oculta por padrão, com opção
de exibir): `lo`, `docker*`, `br-<hex>`, `veth*`, `tun*`, `tap*`, `wg*`.

## 8. Histórico e restauração

O commit/confirm protege contra o erro que derruba na hora. Não protege contra o erro que só
aparece três dias depois.

Cada aplicação bem-sucedida vira uma **versão**: autor, data, diff dos arquivos e o modelo
completo serializado. A UI lista as versões e permite restaurar qualquer uma — e a restauração
passa pelo mesmo commit/confirm, sem exceção.

Reusar a infraestrutura de `/api/backup`, que já existe, em vez de criar um segundo mecanismo.

## 9. Diagnóstico e identificação física

### 9.1 Estado físico

Dado **ao vivo**, não persistido no modelo. A lista exibe por interface:

- **carrier** — cabo conectado ou não
- **velocidade e duplex negociados** — via `ethtool`
- **contadores de erro e descarte** — `rx_errors`, `tx_errors`, `rx_dropped`, `tx_dropped`
  (já devolvidos por `/api/system/status`)
- **endereços IPv6**, em modo somente leitura

Com **destaque visual quando anormal**: porta gigabit negociando 100M, erro subindo, carrier
caído. O problema físico mais comum do mundo real não é config errada — é cabo ruim.

Sobre IPv6: o dado real desta máquina mostra nove endereços IPv6 numa única interface. O v1
não configura IPv6, mas **precisa exibi-lo** — caso contrário o painel mostra uma interface
sem endereço que claramente tem endereço, e o admin deixa de confiar na tela.

### 9.2 Identificar porta

Botão que executa `ethtool -p <iface> <segundos>` para piscar o LED da porta física, mais o
**MAC visível** na lista. Só se aplica a NIC física (o botão não aparece em VLAN nem bridge).

Requer permissão `interfaces.write` e entra no log de auditoria como qualquer outra ação.

## 10. Interface do usuário

`Interfaces.tsx` tem hoje 608 linhas e é só gráfico de tráfego. A parte de tráfego sai para
`components/InterfaceTraffic.tsx` e a página vira uma casca com abas. O monitoramento continua
idêntico para o usuário e o arquivo volta a ter um propósito só.

**Abas:** `Visão geral` · `Interfaces` · `VLANs` · `Bridges` · `Tráfego`

### 10.1 Visão geral (somente leitura)

Árvore da topologia montada, agrupada por papel, com as filhas aninhadas sob o pai:

```
WAN
  eth0 · WAN Vivo · 200.150.10.2/30      [Link 1]  1G full
  eth1 · WAN Sumicity · DHCP             [Link 2]  1G full
LAN
  br10 · 192.168.3.3/24                  [Deriva]
    └ eth2 · membro                                1G full
    └ eth3 · membro                                100M half  ⚠
    └ vlan100 · Voip · tag 100
NÃO ATRIBUÍDAS
  eth4                                   [Adotar]  sem carrier
SISTEMA (18 ocultas)                     [mostrar]
```

É onde bridge mal montada, deriva e porta negociando errado saltam aos olhos — exatamente o
que uma tabela plana esconde.

### 10.2 Abas de trabalho

Uma linha por interface, com nome real, apelido, descrição, endereço, estado administrativo
(*Gerenciada* / *Detectada* / *Deriva*) e estado físico. Editar abre **página inteira**, não
modal apertado.

### 10.3 Criação: guiada por padrão, avançada sob demanda

Fluxos por tarefa, onde o painel já conhece a ordem correta e não deixa montar inválido:

- **"Criar rede VLAN"** — escolhe a interface pai, a tag e a faixa de endereços
- **"Transformar portas que sobraram em switch"** — monta bridge, remove endereço dos membros
- **"Adicionar segunda WAN"** — configura a interface e já oferece criar o `Link` correspondente

Um link **"modo avançado"** abre o formulário cru para quem já sabe o que quer. Atende
iniciante e veterano sem irritar nenhum dos dois.

### 10.4 Aplicação

Toda mudança passa por duas telas:

1. **Formulário** (guiado ou avançado), com validação no servidor via `netif` — não apenas no front
2. **Revisão** — mostra o **diff dos arquivos que serão escritos**, vindo do `Render` puro

Se a mudança afetar a interface pela qual o admin está acessando o painel, a tela de revisão
avisa isso em destaque antes de aplicar.

Ao aplicar, banner fixo com contagem regressiva e o botão de confirmar (§6).

## 11. API

| Método | Rota | Permissão |
|---|---|---|
| `GET` | `/api/interfaces` | `interfaces.read` |
| `POST` | `/api/interfaces` | `interfaces.write` |
| `PUT` | `/api/interfaces/{name}` | `interfaces.write` |
| `DELETE` | `/api/interfaces/{name}` | `interfaces.write` |
| `POST` | `/api/interfaces/{name}/adopt` | `interfaces.write` |
| `POST` | `/api/interfaces/{name}/identify` | `interfaces.write` |
| `POST` | `/api/interfaces/preview` | `interfaces.read` |
| `POST` | `/api/interfaces/apply` | `interfaces.write` |
| `POST` | `/api/interfaces/confirm` | `interfaces.write` |
| `GET` | `/api/interfaces/pending` | `interfaces.read` |
| `GET` | `/api/interfaces/history` | `interfaces.read` |
| `POST` | `/api/interfaces/history/{id}/restore` | `interfaces.write` |
| `GET` | `/api/interfaces/drift` | `interfaces.read` |

Segue o padrão de `preview`/`apply` já usado em `/api/netsvc/*` e `/api/firewall/*`.

## 12. RBAC

Duas permissões novas em `internal/auth/permissions.go`, seguindo a convenção `<area>.<ação>`:

```go
PermInterfacesRead  Permission = "interfaces.read"
PermInterfacesWrite Permission = "interfaces.write"
```

Área `"Interfaces"` no `Catalog`. Separadas de `links.*` de propósito: mexer em interface é
mais perigoso que mexer em rota. Toda escrita grava autor no log de auditoria.

## 13. Testes e verificação

Quatro camadas, da mais barata à mais cara:

**Puro, sem sistema.** As regras de integridade (§5.2) são funções puras — teste tabelado, no
estilo já usado no repositório. O `Render` também é puro: comparação com arquivos golden de
`.netdev`/`.network`. Juntas cobrem a maior parte da lógica real.

**Importador com fixtures.** Saídas reais de `ip -j link` gravadas como JSON — incluindo uma
capturada de uma máquina com 22 interfaces e o zoo de bridges do Docker — viram entrada de
teste. Isso trava o requisito de classificação de §7.1: se o parser voltar a tratar
`br-0293233c552c` como interface gerenciável, o teste quebra.

**Aplicador em netns descartável.** O `Apply` real roda dentro de um network namespace criado
na hora, com veths falsos: cria bridge, cria VLAN, aplica, confere o resultado com `ip -j`. Se
der errado, morre o namespace e nada mais. Exige privilégio, então fica atrás de uma build tag
para não quebrar `make test` de quem não é root.

**Commit/confirm com provider falso.** Timer, rollback e persistência do deadline se testam
com um `Provider` de mentira que registra chamadas, sem tocar em rede. Inclui o caso crítico:
LinkGuard reinicia no meio da janela e a mudança não confirmada **não** vira permanente.

### 13.1 Roteiro de QA manual

Antes de considerar pronto, verificar em navegador real:

1. Adotar uma interface detectada e confirmar que ela passa a ser renderizada
2. Criar uma VLAN e vê-la aparecer sozinha na lista de Interfaces, **sem passo de atribuição**
3. Montar uma bridge com duas portas e conferir que os membros perderam o endereço próprio
4. Provocar deriva por fora (`ip addr add` na mão) e confirmar que a UI acusa
5. **Deixar a janela de confirmação expirar de propósito** e verificar que voltou ao estado
   anterior, com o rascunho preservado
6. Restaurar uma versão anterior do histórico
7. Desconectar um cabo e confirmar que carrier e velocidade refletem isso na Visão geral
8. Verificar que as interfaces de sistema (Docker, loopback) estão ocultas por padrão

## 14. Fases de entrega

O v1 é grande. As fases abaixo são entregáveis de forma independente — dá para parar em
qualquer uma sem ficar com coisa pela metade.

| Fase | Entrega | Por que é útil sozinha |
|---|---|---|
| **1** | Modelo + importador + classificação de ruído + Visão geral e listagem somente leitura, com estado físico e identificação de porta | Diagnóstico e documentação da rede já no painel. Zero risco: nada é escrito. |
| **2** | `Render` + `Apply` + commit/confirm + preview de diff + edição de interface física | Já permite gerenciar endereçamento com segurança. |
| **3** | VLAN e bridge + fluxos guiados | Fecha o escopo funcional prometido. |
| **4** | Histórico e restauração + detecção de deriva | Proteção contra o erro que aparece dias depois. |

**Depois, em spec separado:** migração do servidor de produção de `ifupdown` para
`systemd-networkd`, com unit de rollback no boot, ordem de restart de Kea e Unbound, e runbook.
O importador desta spec é o que gera a config equivalente ao que já roda hoje — o cutover vira
"mesma rede, outro dono", não "rede nova".

## 15. Riscos e armadilhas

- **Não** apagar arquivo em `/etc/systemd/network/` que não tenha o cabeçalho `# managed by linkguard`
- **Não** corrigir deriva automaticamente — mostrar e deixar o admin decidir
- **Não** confiar só em `networkctl reload`: mudança de tipo e remoção de `.netdev` exigem `reconfigure`
- **Não** deixar o deadline do commit/confirm apenas em memória
- **Não** exibir interface sem os endereços IPv6 que ela realmente tem
- **Não** criar um segundo mecanismo de apelido: `/api/system/interface-aliases` já existe
- **Não** tratar `Role` como comportamento — quem define WAN de verdade é o `Link`
