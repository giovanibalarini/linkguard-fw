# Servir NTP para a LAN (com proteção de firewall e anúncio via DHCP)

## 1. Motivação

O firewall já é o resolvedor DNS da rede e, desde a v1.0.95, sincroniza o
próprio relógio com fontes NTP boas. Pergunta do operador (2026-08-11):
*"Disponibilizamos as máquinas se sincronizarem na rede via o nosso NTP? O
DHCP entrega essa possibilidade?"*

Verificado ao vivo: **não**, nas duas pontas.
- `chrony` não tem nenhuma diretiva `allow` e não escuta na porta 123 — só
  age como cliente.
- O Kea entrega apenas `routers` e `domain-name-servers`; a opção 42
  (`ntp-servers`) não é gerada.

Isso foi decisão consciente na spec de 2026-08-10 (§12, "servir NTP para a
LAN" ficou explicitamente fora de escopo), mas a pergunta expõe uma
incoerência real: quem já é DNS da rede deveria ser também a fonte de
horário. Ganhos: relógio coerente entre todas as máquinas (log e
autenticação dependem disso), funciona mesmo com a internet fora, e menos
tráfego externo.

Pedido explícito adicional: a opção precisa estar **na interface web**, e ao
ser habilitada as **regras de firewall devem entrar automaticamente**
protegendo o serviço — não bastando o `allow` do chrony e o bind correto.

## 2. Descoberta que molda o design: não existe filtro de INPUT

Verificado ao vivo em produção: a tabela `inet linkguard` tem chains para
`prerouting` (mangle), `forward` e `postrouting` (nat) — **nenhuma com hook
`input`**. Confirmado que o ruleset inteiro não tem nenhum `hook input`.

Ou seja: hoje **nada filtra o tráfego destinado ao próprio firewall** (SSH,
painel 9997, DNS 53, Samba 445/139, DHCP 67). As WANs atuais estão atrás de
CPEs do provedor em faixas privadas, então não há exposição direta à
internet — mas a camada não existe.

Esta entrega cria a **primeira chain de input** do projeto. Decisão de
segurança inegociável:

> A chain nasce com **`policy accept`**, nunca `drop`.

Uma chain de input com política `drop` bloquearia SSH e o painel no instante
em que fosse aplicada, deixando o operador trancado para fora de um firewall
em produção — possivelmente de madrugada e sem acesso físico. A proteção
desta entrega é feita por **regras específicas de negação**, não por
política restritiva. Endurecer a política é um projeto próprio, com
inventário de portas, ordem de regras e janela de manutenção.

## 3. O que o toggle faz

Um único controle na tela de NTP — "Servir horário para a rede local" —
que, quando ligado, faz três coisas de forma coordenada:

1. **chrony passa a servir**: o drop-in gerado
   (`/etc/chrony/conf.d/linkguard.conf`) ganha uma linha `allow <cidr>` por
   rede autorizada (§3.1).
2. **firewall protege**: regras específicas na nova chain de input (§4).
3. **DHCP anuncia**: o Kea passa a entregar a opção 42 (`ntp-servers`)
   apontando para o IP do firewall na LAN.

Desligado, o comportamento volta exatamente ao de hoje: sem `allow`, sem
regra de firewall, sem opção no DHCP. Padrão de fábrica: **desligado**
(aditivo, não muda o comportamento de instalações existentes).

### 3.1 Quem pode acessar é escolha do admin (não do software)

O operador pode ter VLANs, uma rede Wi-Fi separada, uma rede de convidados —
e decidir quais delas podem usar o serviço de horário. Amarrar a liberação
na sub-rede única do DHCP seria o software decidindo por ele.

Portanto: `Config.AllowedNetworks []string` — uma lista de CIDRs, editável no
painel. Cada entrada vira uma linha `allow` no chrony e entra no conjunto
aceito pela regra de firewall.

- **Padrão inteligente, não imposição**: ao ligar o toggle pela primeira vez,
  a lista é pré-preenchida com a sub-rede da LAN (`netsvc.Config.SubnetCIDR`)
  — o caso comum funciona sem digitar nada, mas o campo continua editável.
- **CIDR cobre os casos citados**: VLAN e Wi-Fi com sub-rede própria entram
  como entradas adicionais; Wi-Fi em bridge na mesma LAN já está coberto pela
  entrada existente.
- **Validação**: cada entrada precisa ser um CIDR válido (`net.ParseCIDR`) —
  vai para um arquivo de config de daemon e para o `nft`.
- **Guarda-corpo**: `0.0.0.0/0` e `::/0` são **rejeitados** com erro claro.
  Servidor NTP aberto para a internet é vetor conhecido de ataque de
  amplificação, e isso quase certamente seria engano — não uma escolha
  informada. Qualquer outra faixa é aceita: o admin conhece a rede dele.
- Lista vazia com o toggle ligado = nada é liberado (nem chrony, nem
  firewall). Estado explícito, não um "libera tudo" implícito.

## 4. Regras de firewall

Nova chain `input` em `table inet linkguard`:

```
chain input {
    type filter hook input priority filter; policy accept;
    udp dport 123 ip saddr { <redes autorizadas> } accept
    udp dport 123 drop
}
```

- **Libera quem o admin escolheu, nega todo o resto.** Duas regras, nessa
  ordem: a primeira aceita NTP vindo das redes autorizadas (§3.1); a segunda
  descarta qualquer outro NTP destinado a esta máquina.
- Esse par é **mais preciso do que negar só as WANs**: cobre também uma VLAN
  ou rede de convidados que exista na máquina e que o admin *não* autorizou —
  caso que a regra por interface deixaria passar silenciosamente.
- O escopo é cirúrgico: as duas regras casam **apenas `udp dport 123`**.
  Nenhum outro tráfego destinado ao firewall é tocado, e a política da chain
  continua `accept` (§2).
- **Por que isso importa mesmo com o `allow` do chrony:** o `allow` é
  controle na aplicação; a regra de firewall é a segunda camada, que
  continua valendo se a config do chrony for sobrescrita por uma atualização
  de pacote. Defesa em profundidade foi exatamente o que o operador pediu.
- Com o toggle desligado (ou lista vazia), a chain fica vazia — sem a regra
  de accept e sem a de drop, voltando ao comportamento atual.

### Reconciliação
A chain é reconstruída (flush do chain + regra) no boot e a cada mudança
relevante, seguindo exatamente o padrão de `ReconcileMasquerade` (v1.0.92):
flush apenas do chain próprio, nunca da tabela nem do ruleset; nomes de
interface validados por `reIface` antes de entrarem no comando.

Quando o toggle está desligado, a chain fica vazia (flush sem regra) — e
**não** é removida, para que o estado seja sempre explícito e idempotente.

## 5. Anúncio via DHCP

`GenerateKeaConfig` passa a emitir, quando o toggle está ligado:

```json
{ "name": "ntp-servers", "data": "<ip-do-firewall-na-LAN>" }
```

O IP é o `netsvc.Config.Gateway` (o endereço do firewall na LAN, já usado
para anunciar o DNS) — mesma fonte de verdade, sem campo novo.

**Acoplamento entre módulos:** a config de NTP mora em `internal/timesync` e
a de DHCP em `internal/netsvc`. Para não fazer um módulo escrever a config do
outro, o handler de DHCP lê o estado do NTP e o repassa como parâmetro ao
gerador — o gerador continua sendo função pura de suas entradas.

Ligar/desligar o toggle dispara o reload gracioso do Kea (mesmo caminho
debounced já usado quando se edita DHCP), para que os clientes recebam a
opção na próxima renovação de lease.

## 6. Interface

Na página de NTP já existente, gated por `ntp.write` como o resto da tela:

- Um switch **"Servir horário para a rede local"**.
- Quando ligado, um campo editável **"Redes autorizadas"** (lista de CIDRs,
  separados por vírgula, no mesmo padrão do campo de servidores NTP e do de
  upstreams de DNS que já existem). Pré-preenchido com a sub-rede da LAN na
  primeira vez, e livremente editável — é aqui que o admin acrescenta VLAN,
  Wi-Fi ou rede de convidados.
- Erro de validação vindo da API (CIDR inválido, `0.0.0.0/0`) exibido no
  mesmo padrão de mensagem já usado na tela.

Quando ligado, mostrar de forma discreta o que passou a valer — servindo
para as redes listadas, anunciado via DHCP, NTP negado para o resto — para
que o operador veja as três consequências sem precisar do SSH.

Isso satisfaz a regra de entrega do projeto (`FEATURES.md`): o recurso é
ligável, desligável e ajustável inteiramente pelo painel, e o painel mostra
o efeito real — não é backend com tela decorativa.

## 7. Testes

- **chrony**: uma linha `allow` por rede autorizada quando ligado, nenhuma quando desligado ou com lista vazia;
  idempotente entre execuções; CIDR inválido e `0.0.0.0/0` rejeitados.
- **firewall**: NTP das redes autorizadas é aceito e de qualquer outra
  origem é negado; nenhuma regra casa porta diferente de 123/udp; flush
  apenas do chain próprio (nunca tabela/ruleset — mesmo teste de segurança
  do masquerade); chain vazia quando desligado; nomes de interface
  sanitizados; no-op em dry-run.
- **Kea**: opção `ntp-servers` presente com o IP correto quando ligado,
  ausente quando desligado; JSON continua válido.
- **VM**: com o toggle ligado, uma consulta NTP vinda de uma rede autorizada
  é respondida e uma vinda de fora da lista é bloqueada; o lease do DHCP
  entrega a opção 42. Acrescentar uma segunda rede pelo painel passa a
  liberá-la sem tocar em arquivo nenhum — é a prova de que a escolha é do
  admin. Com o toggle desligado, tudo volta ao estado anterior.

## 8. Fora de escopo (explicitamente)

- **Endurecer a política de input** (fechar SSH/painel/Samba nas WANs) —
  é o projeto natural seguinte e o achado da §2 o justifica, mas exige
  inventário de portas e janela própria; misturar com esta entrega arriscaria
  lockout.
- Autenticação NTP (NTS/chaves), NTP sobre IPv6 para a LAN, e servir NTP em
  VLANs que ainda não existem.
- Nomeação estável de interface (Fase A) e proxy tipo Squid — anotados como
  trabalhos próprios.
