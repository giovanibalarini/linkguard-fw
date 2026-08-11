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
   (`/etc/chrony/conf.d/linkguard.conf`) ganha `allow <cidr-da-LAN>`. A
   sub-rede vem da config de DHCP/DNS já existente (`netsvc.Config.SubnetCIDR`),
   fonte de verdade única — não um campo novo para o operador manter em dois
   lugares.
2. **firewall protege**: regras específicas na nova chain de input (§4).
3. **DHCP anuncia**: o Kea passa a entregar a opção 42 (`ntp-servers`)
   apontando para o IP do firewall na LAN.

Desligado, o comportamento volta exatamente ao de hoje: sem `allow`, sem
regra de firewall, sem opção no DHCP. Padrão de fábrica: **desligado**
(aditivo, não muda o comportamento de instalações existentes).

## 4. Regras de firewall

Nova chain `input` em `table inet linkguard`:

```
chain input {
    type filter hook input priority filter; policy accept;
    iifname { "<wan1>", "<wan2>" } udp dport 123 drop
}
```

- A negação é por **interface de entrada (WAN)**, não por endereço de
  origem — mais robusto contra spoofing e independente de qual IP a WAN
  tenha no momento (que, como esta sessão provou, muda).
- O tráfego da LAN é aceito pela política `accept`, sem regra explícita. Uma
  regra `accept` para a LAN seria redundante e daria falsa sensação de que a
  política é restritiva.
- **Por que isso importa mesmo com o `allow` do chrony:** um servidor NTP
  aberto para a internet é vetor clássico de ataque de amplificação. O
  `allow` do chrony é controle de aplicação; a regra de firewall é a
  segunda camada, que continua valendo se a config do chrony for
  sobrescrita por uma atualização de pacote. Defesa em profundidade foi
  exatamente o que o operador pediu.
- As interfaces WAN vêm dos `Link`s habilitados no banco — mesma fonte de
  verdade que a regra de masquerade, e reconciliada do mesmo jeito.

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

Na página de NTP já existente, um switch "Servir horário para a rede local",
com texto explicando o efeito em uma linha (as máquinas da LAN passam a
sincronizar com o firewall, e o DHCP passa a indicá-lo automaticamente).
Gated por `ntp.write`, como o resto da tela.

Quando ligado, mostrar de forma discreta o que foi aplicado — servindo para
`<cidr>`, anunciado via DHCP, bloqueado nas WANs — para que o operador veja
as três consequências sem precisar do SSH, coerente com o princípio desta
sessão.

## 7. Testes

- **chrony**: `allow` presente quando ligado e ausente quando desligado;
  idempotente entre execuções; a sub-rede vem da config de DHCP.
- **firewall**: a regra nega 123/udp nas WANs e não nega na LAN; flush
  apenas do chain próprio (nunca tabela/ruleset — mesmo teste de segurança
  do masquerade); chain vazia quando desligado; nomes de interface
  sanitizados; no-op em dry-run.
- **Kea**: opção `ntp-servers` presente com o IP correto quando ligado,
  ausente quando desligado; JSON continua válido.
- **VM**: com o toggle ligado, um cliente da LAN sincroniza de fato com o
  firewall (`chronyc sources` do lado do cliente, ou consulta NTP direta ao
  192.168.3.3), a consulta NTP vinda da WAN é bloqueada, e o lease do DHCP
  entrega a opção 42. Com o toggle desligado, os três voltam ao estado
  anterior.

## 8. Fora de escopo (explicitamente)

- **Endurecer a política de input** (fechar SSH/painel/Samba nas WANs) —
  é o projeto natural seguinte e o achado da §2 o justifica, mas exige
  inventário de portas e janela própria; misturar com esta entrega arriscaria
  lockout.
- Autenticação NTP (NTS/chaves), NTP sobre IPv6 para a LAN, e servir NTP em
  VLANs que ainda não existem.
- Nomeação estável de interface (Fase A) e proxy tipo Squid — anotados como
  trabalhos próprios.
