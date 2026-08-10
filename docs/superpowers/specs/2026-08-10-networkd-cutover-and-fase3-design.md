# Corte para systemd-networkd + Fase 3 (VLAN e bridge)

Spec separado anunciado em
[[2026-07-19-network-interface-management-design.md]] §14: *"Depois, em spec
separado: migração do servidor de produção de ifupdown para systemd-networkd
[...]. O importador desta spec é o que gera a config equivalente ao que já
roda hoje — o cutover vira 'mesma rede, outro dono', não 'rede nova'."*

Este documento fecha essa promessa e complementa com uma correção de causa raiz
descoberta ao vivo em 2026-08-10 (nomeação instável de interface física).

## 1. Motivação (o que aconteceu hoje)

Troca de disco do servidor de produção (`firewall-DG`), primeira instalação do
zero. Durante o processo:

- A placa de rede que ocupava o slot PCI `05:00.0` (WAN1 "Vivo", MAC
  `b8:ca:3a:fc:d6:03`) reapareceu como `enp4s0` em vez de `enp5s0` — porque a
  placa wifi que ocupava `04:00.0` foi fisicamente removida e reinserida
  durante o serviço, deslocando a numeração PCI dos slots seguintes.
- A porta que antes era WAN2 "sumicity" (`enp3s0`) passou a ser cabeada como
  LAN, e a porta que antes era LAN (`enp2s0`) passou a ser cabeada como WAN2 —
  decisão consciente do usuário pra essa instalação, não um erro.
- Toda a topologia (bridge LAN, duas WANs) teve que ser refeita **na mão**,
  editando `/etc/network/interfaces` via SSH — exatamente a "linha frágil de
  bash" que o projeto existe pra eliminar (ver `LinkGuard.md` §"O que é").

Duas causas raízes distintas, duas correções distintas:

1. **Nomeação de interface não é estável** — depende da posição física no
   barramento PCI, que muda com qualquer alteração de hardware. Nem migrar
   pra `networkd` sozinho resolve isso.
2. **Não existe aplicador real** pra bridge/WAN em produção hoje —
   `ifupdown` é editado à mão; a Fase 2 do `internal/netif` já sabe *gerar* a
   config certa, mas só tem efeito com `systemd-networkd` ativo, e produção
   nunca fez esse corte.

## 2. Decisão de escopo

Aprovado pelo usuário nesta sessão: fazer o corte para `systemd-networkd`
agora (não adiar de novo), incluindo a correção de nomeação estável, como
pré-requisito real da Fase 3. **Design e plano agora; execução em produção
numa janela própria**, não no mesmo dia de uma recuperação ao vivo.

## 3. Nomeação estável via arquivo `.link`

### Problema
Nomes `enpXsY` são derivados de `ID_PATH` (posição física/PCI), atribuído
pelo `systemd-udevd` via `net.naming-scheme`. Won't survive hardware change.

### Solução
LinkGuard passa a gerar um arquivo `.link` por NIC física conhecida, casando
por **endereço MAC** (`[Match] MACAddress=`), fixando um nome próprio via
`[Link] Name=`:

```ini
# /etc/systemd/network/10-linkguard-wan1.link
# managed by linkguard — corresponde ao Link "WAN VIVO" no banco
[Match]
MACAddress=b8:ca:3a:fc:d6:03

[Link]
Name=lg-wan1
```

- Nome próprio prefixado (`lg-`) pra nunca colidir com `enpXsY` nem com nomes
  que o kernel possa reciclar.
- Um `.link` por interface física **conhecida pelo LinkGuard** (toda que já
  tiver sido associada a um `Link` de WAN, ou marcada como membro de
  bridge/LAN pelo admin) — interfaces nunca vistas pelo painel não ganham
  `.link` (ficam com o nome padrão do kernel, sem gerência).
- Requer **reboot** para pegar — arquivo `.link` é lido no *coldplug* do
  udev, não é hot-apply como `.network`. Existe a alternativa de
  `udevadm trigger --settle` re-disparando o evento pra interface já
  existente, mas isso significa recriá-la (down/rename/up) numa interface de
  produção com tráfego passando — **decisão: sempre reboot**, nunca
  re-trigger ao vivo. É infraestrutura de baixo nível, não é uma mudança
  "Aplicar agora" como as outras — a UI deve deixar isso explícito (banner
  "requer reboot pra ter efeito", igual ao padrão de aviso já usado pra
  networkd inativo).
- Efeito prático: depois desse dia, trocar a placa de lugar no gabinete ou
  adicionar/remover outra placa **não muda mais o nome de nenhuma interface
  já conhecida** — só MAC importa.

### Onde entra no modelo existente
`internal/netif`'s `Interface.Name` continua sendo o nome *atual* do kernel
(pode ser `lg-wan1` depois do corte); o `.link` é gerado a partir do MAC já
registrado em `Interface`/`Link`, num novo arquivo
`internal/netif/networkd/link.go`, renderizado pelo mesmo `Render`/`Apply`
que já existe — mesmo commit/confirm, mesmo preview de diff.

## 4. Corte de ifupdown para networkd

**Princípio inegociável (confirmado pelo usuário): isto é uma troca de dono,
não uma coexistência.** Ao final do corte, `ifupdown`/`networking.service`
está **desativado**, `/etc/network/interfaces` reduzido a um stub
(`auto lo` / `iface lo inet loopback`, nada mais), e `systemd-networkd` é
dono de 100% do roteamento. Nunca os dois mecanismos ativos ao mesmo tempo
gerenciando a mesma interface.

### Sequência
1. **Importar o estado atual** pro modelo do `internal/netif` como o "dia 1"
   gerenciado — não parte de uma rede vazia. Fonte: `/etc/network/interfaces`
   vivo (bridge `br10`+membro `enp3s0`, WAN1 estático `enp4s0`, WAN2 DHCP
   `enp2s0`) + os `Link`s já no banco. Reaproveita o **importador da Fase 1**
   (§7 do spec original) — é exatamente o caso de uso que ele foi feito pra
   resolver.
2. Gerar os `.link` (seção 3) **e**, no mesmo passo, os `.network`/`.netdev`
   (Provider já existente) — mas os `.network` já devem referenciar o nome
   *novo* (`lg-wan1`, não `enp4s0`), mesmo gerados enquanto o kernel ainda
   chama a interface pelo nome antigo. `.link` só pega depois do reboot (ver
   seção 3), então os dois conjuntos de arquivo ficam escritos e inertes até
   o mesmo reboot os ativar juntos — nunca existe um estado intermediário em
   que o `.network` aponta pra um nome que o `.link` ainda não criou.
3. `systemctl disable --now networking` (ifupdown) e sobrescrever
   `/etc/network/interfaces` com o stub.
4. `systemctl enable --now systemd-networkd`.
5. Confirmar: `networkctl status`, `ip -br addr show`, ping nos dois
   gateways de WAN, DHCP/DNS respondendo na LAN.
6. **Ordem de restart pós-corte**: rede tem que estar de pé antes de
   `kea-dhcp4-server`/`unbound` subirem — usar dependência declarada do
   systemd (`After=systemd-networkd.service`,
   `BindsTo=`/`Requires=network-online.target` conforme o caso), não confiar
   em ordem manual.

### Rollback
- `/etc/network/interfaces.bak-pre-linkguard` (já existe, gerado
  automaticamente na preparação de hoje) é o fallback documentado.
- Runbook de reversão: `systemctl disable --now systemd-networkd` →
  restaurar o backup em `/etc/network/interfaces` →
  `systemctl enable --now networking`.
- Igual ao princípio da seção acima: reversão também é troca de dono
  completa, não mistura os dois.

### Riscos herdados do spec original (§15), ainda válidos
Não apagar `.network`/`.netdev` sem o cabeçalho `# managed by linkguard`;
não confiar só em `networkctl reload` (mudança de tipo/remoção de `.netdev`
exige `reconfigure`); checar arquivos órfãos deixados por testes da Fase 2
antes de ativar (ver memória `interfaces-fase2-networkd-migration-notes`).

## 5. Fase 3 — criar VLAN e bridge

Reaproveita quase integralmente o design já aprovado em
[[2026-07-19-network-interface-management-design.md]] §5.1–5.3: mesmo
modelo (`Kind`: physical/vlan/bridge, `Members []string`, `VLANID`), mesmas
regras de integridade (§5.2: VLAN exige pai existente e ID 1–4094 único por
pai; membro de bridge não pode ter endereço próprio; sem ciclos; interface
não pode ser membro de duas bridges).

**O que muda nesta fase:**
- `checkEditable` (`internal/netif/service.go`) para de rejeitar
  `KindVLAN`/`KindBridge` — passa a permitir **criar** essas duas (não só
  editar física, como hoje).
- Dois fluxos guiados já especificados em §10.3: **"Criar rede VLAN"**
  (escolhe interface pai + tag) e **"Transformar portas em switch"** (monta
  bridge, remove endereço dos membros).
- `internal/netif/networkd/networkd.go`: os prefixos `20-` (VLAN) e `30-`
  (bridge) já estão **reservados** no código (comentário existente) — Fase 3
  implementa o `Render` para esses dois `Kind`s, que hoje só existe pra
  `physical` (prefixo `10-`).

**Pré-condição dura: só tem efeito real depois do corte da seção 4.** Antes
disso, funciona exatamente como a Fase 2 funciona hoje — salva no painel,
preview mostra o diff, mas aviso claro pro admin de que não aplica nada até
`systemd-networkd` estar no comando.

## 6. Fases de entrega (desta spec)

| Fase | Entrega |
|---|---|
| **A** | `.link` por MAC (seção 3) — implementável e testável isoladamente, zero risco (não aplica sozinho, só gera arquivo) |
| **B** | Corte ifupdown→networkd em produção (seção 4) — a operação de risco real, janela própria |
| **C** | Criar VLAN/bridge (seção 5) — só depois de B estar validado e estável por alguns dias |

## 7. Testes e verificação

- **A**: unitário — dado um MAC conhecido, gera o `.link` esperado; nomes
  não colidem entre si; interface desconhecida não gera arquivo.
- **B**: ensaiado primeiro num ambiente descartável (mesmo padrão da VM
  `~/linkguard-testvm/` usada hoje: qemu com múltiplas NICs, simula o corte
  completo antes de tocar produção) — critério de sucesso: rede sobrevive a
  um reboot depois do corte, DHCP/DNS respondem, os dois WANs mantêm
  conectividade, rollback testado e funcional.
- **C**: reaproveita o roteiro de QA já escrito em §13.1 do spec original
  (criar VLAN, ver aparecer sem passo de atribuição; montar bridge com duas
  portas, confirmar que os membros perdem endereço próprio).

## 8. Fora de escopo (explicitamente)

- Qualquer coisa sobre a placa wifi em si (card reinserido, ainda não
  detectada pelo kernel — acompanhamento separado, físico, não é este spec).
- Restaurar o compartilhamento Samba/dados (`/data/*`) — trabalho paralelo,
  sem relação com rede.
- Bonding/LACP — fora do escopo do v1 original (§3), continua fora aqui.
