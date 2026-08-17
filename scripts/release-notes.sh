#!/usr/bin/env bash
#
# release-notes.sh — o corpo da nota de release, a partir do histórico (issue #63).
#
# Por que isto existe: a nota de release responde UMA pergunta — o que mudou
# desta versão para a anterior. Ela respondia outra. Repetia o passo a passo de
# instalação, que já mora no README e não muda de release para release, e quem
# abria a página de uma versão nova via três blocos de `wget` e nenhuma linha
# sobre o que tinha sido corrigido. Num produto que se auto-atualiza num
# firewall em produção, é essa lista que decide "atualizo agora ou no sábado".
#
# Por que sai do git e não de um arquivo curado: arquivo curado atrasa.
# web/src/data/changelog.ts, que alimenta a tela "Novidades" do painel, parou na
# 1.0.82 enquanto o projeto chegava à 1.0.105 — 23 versões sem uma linha. O que
# sai daqui não é prosa para o usuário final; é a lista honesta do que entrou, e
# ela não tem como ficar para trás sozinha.
#
# Por que é um script e não um bloco `run:` do workflow: aqui ele PODE ser
# executado. Um heredoc de YAML só é exercitado quando uma release sai — o pior
# momento possível para descobrir que o `sed` estava errado.
#
# Uso:
#   scripts/release-notes.sh v1.0.106 giovanibalarini/linkguard-fw <sha>
#
# Saída: markdown no stdout.

set -euo pipefail

TAG="${1:?uso: $0 <tag> <owner/repo> <sha>}"
REPO="${2:?uso: $0 <tag> <owner/repo> <sha>}"
SHA="${3:?uso: $0 <tag> <owner/repo> <sha>}"

# A tag anterior é a maior que NÃO seja esta.
#
# O `grep -vx` não é zelo: o workflow chama isto depois de a tag já apontar para
# HEAD, então sem ele a própria TAG é a primeira da lista ordenada, o intervalo
# vira "TAG..HEAD" (vazio) e a nota sai sem uma linha — falhando em silêncio,
# exatamente no caso que importa.
PREV=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname \
       | grep -vx "${TAG}" | head -n1 || true)

if [[ -n "${PREV}" ]]; then
  RANGE="${PREV}..HEAD"
else
  RANGE="HEAD"
fi

# --no-merges: o assunto de um commit de merge é "Merge pull request #NN", que
# não diz o que mudou. O trabalho de verdade está nos commits que ele traz, e
# esses entram na lista por conta própria.
#
# E o grep depois dele NÃO é redundante. --no-merges filtra por NÚMERO DE PAIS, e
# nem todo commit com cara de merge tem dois: 183a4c3 ("Merge pull request #50")
# saiu com um pai só, porque um `git stash` no meio da resolução de conflito
# limpou o MERGE_HEAD. Para o git aquilo não é merge; para quem lê a nota, é
# ruído do mesmo jeito. Filtrar pelos dois critérios é o que faz a nota
# depender do que a linha DIZ, e não de como ela foi parar no histórico.
SUBJECTS=$(git log --no-merges --format='%s' "${RANGE}" \
           | grep -vE "^Merge (pull request|branch|remote-tracking) " || true)

if [[ -n "${SUBJECTS}" ]]; then
  TOTAL=$(wc -l <<<"${SUBJECTS}")
else
  TOTAL=0
fi

KNOWN='sec|security|fix|feat|perf|refactor|test|docs|chore|build|ci|deps'

# emit REGEX_DO_TIPO TITULO — uma seção por tipo de conventional commit.
emit() {
  local found
  found=$(grep -E "^($1)(\(.+\))?!?: " <<<"${SUBJECTS}" || true)
  [[ -z "${found}" ]] && return 0
  printf '### %s\n\n' "$2"
  # Tira o prefixo — quem lê a seção "Correções" não precisa de "fix:" no começo
  # de cada linha. O escopo vira rótulo em vez de sumir: "(firewall)" e "(web)"
  # são o que diz a quem a linha interessa. A ordem dos dois `s///` importa: o
  # padrão com escopo tem que ser tentado ANTES do sem escopo, senão o segundo
  # casa primeiro e come o "(...)" junto.
  sed -E "s/^($1)\((.+)\)!?: */- (\2) /; s/^($1)!?: */- /" <<<"${found}"
  printf '\n'
}

printf '## O que mudou em %s\n\n' "${TAG}"

if [[ -n "${PREV}" ]]; then
  printf 'Comparado com [`%s`](https://github.com/%s/compare/%s...%s) — %d commits.\n\n' \
    "${PREV}" "${REPO}" "${PREV}" "${TAG}" "${TOTAL}"
fi

# A ordem é a de quem vai atualizar um firewall em produção e precisa decidir
# com que urgência: segurança primeiro, manutenção por último.
emit 'sec|security'        'Segurança'
emit 'fix'                 'Correções'
emit 'feat'                'Novidades'
emit 'perf'                'Desempenho'
emit 'refactor'            'Reestruturação interna'
emit 'test'                'Testes'
emit 'docs'                'Documentação'
emit 'chore|build|ci|deps' 'Manutenção'

# Commit fora do padrão não pode sumir da nota: ele existiu e mudou o produto.
# Cai aqui em vez de ser descartado em silêncio — uma nota que omite o que não
# soube classificar é pior do que uma nota feia.
OTHERS=$(grep -vE "^(${KNOWN})(\(.+\))?!?: " <<<"${SUBJECTS}" || true)
if [[ -n "${OTHERS}" ]]; then
  printf '### Outros\n\n'
  sed -E 's/^/- /' <<<"${OTHERS}"
  printf '\n'
fi

if [[ "${TOTAL}" -eq 0 ]]; then
  printf '_Sem commits novos desde `%s`._\n\n' "${PREV}"
fi

printf -- '---\n\n'
printf 'Instalação e atualização: veja [Installation no README](https://github.com/%s/blob/main/README.md#installation).\n\n' "${REPO}"
# O checksum FICA. Ao contrário do passo a passo de instalação, ele é sobre os
# artefatos DESTA release e não teria onde morar no README.
printf 'Confira os artefatos antes de instalar:\n\n'
printf '```bash\n'
printf 'wget https://github.com/%s/releases/download/%s/sha256sums.txt\n' "${REPO}" "${TAG}"
printf 'sha256sum -c sha256sums.txt\n'
printf '```\n\n'
printf 'Build automático do commit %s.\n' "${SHA}"
