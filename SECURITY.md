# Política de segurança

O LinkGuard FW é um appliance de firewall. Ele roda **como root**, gerencia as
regras de `nftables` da máquina, o DHCP, o DNS recursivo e o NTP, e expõe um
painel web na LAN. Uma falha aqui não é um bug de aplicação — é acesso ao
roteador da rede de alguém.

Por isso este projeto trata relato de vulnerabilidade de forma diferente de
relato de defeito comum.

## Como relatar uma vulnerabilidade

**Não abra uma issue pública.** Uma issue é indexada por buscadores no momento
em que é criada, e descreve o caminho de exploração antes de existir correção
disponível — em instalações que estão rodando neste momento.

Use o canal privado do GitHub:

**[Security → Report a vulnerability](https://github.com/giovanibalarini/linkguard-fw/security/advisories/new)**

O relato fica visível apenas para os mantenedores. Se preferir, o mesmo caminho
está em `Security` → `Advisories` → `Report a vulnerability`, na barra do
repositório.

### O que ajuda no relato

Nem tudo é obrigatório — relate mesmo que falte alguma coisa. Mas o que mais
acelera a correção:

- **Onde**: arquivo e linha, ou o endpoint da API.
- **Quem consegue explorar**: o modelo de ameaça deste produto é *alguém com
  acesso ao painel* (possivelmente com permissão de RBAC limitada) ou *alguém
  na LAN*. Uma falha que exige shell root na máquina não é uma falha — quem
  tem root já venceu.
- **O que o atacante obtém**: escalação de privilégio, execução de comando,
  vazamento de credencial, contorno de autenticação.
- **Como reproduzir**: a requisição, o valor do campo, o comando.

### O que não é vulnerabilidade neste projeto

Para poupar seu tempo — estes casos são conhecidos e são decisão de desenho,
não descuido:

- `/metrics` e `/api/health` sem autenticação. São endpoints de leitura, com
  registry dedicado, no padrão do Prometheus.
- Negação de serviço, exaustão de recurso e ausência de limite de requisição.
- Ausência de uma medida de endurecimento genérica, sem um caminho de
  exploração concreto.
- Dependência desatualizada sem falha alcançável demonstrada. O `govulncheck`
  e o Dependabot já cobrem isso.

## Prazo de resposta

Este é um projeto mantido por uma pessoa, em produção numa máquina. Não há
SLA comercial, mas o compromisso é:

| Etapa | Prazo |
|---|---|
| Confirmação de recebimento | até 3 dias |
| Avaliação inicial e severidade | até 7 dias |
| Correção de falha alta ou crítica | até 30 dias |

## Divulgação

A correção é desenvolvida no fork privado que o próprio advisory cria, e vai
para produção antes de qualquer publicação. Depois disso o advisory é
publicado, com crédito a quem relatou — a menos que a pessoa prefira o
anonimato.

O projeto publica o advisório mesmo quando a falha foi encontrada
internamente. O histórico do que foi achado e corrigido é informação que quem
avalia instalar isto merece ter.

## Versões cobertas

Só a versão mais recente recebe correção de segurança. Não há linha de suporte
estendido — a atualização é automática pelo próprio painel (Sistema →
Atualizações), com verificação de SHA-256 do pacote antes da instalação.

## Antes de instalar

Duas coisas que não são vulnerabilidades, mas que quem instala precisa saber, e
que estão detalhadas no README:

1. **O LinkGuard assume a máquina.** Ele instala e configura serviços do
   sistema e impõe a própria configuração a cada boot. A premissa é que
   instalar o LinkGuard é entregar a máquina a ele.
2. **A instalação semeia um usuário administrador padrão.** Troque a senha
   antes de conectar a máquina a uma rede não confiável.
