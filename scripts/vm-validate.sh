#!/usr/bin/env bash
#
# vm-validate.sh — valida um .deb do LinkGuard numa VM descartável, do zero.
#
# Por que isto existe: teste verde não é prova. Vários defeitos deste projeto
# passaram por suítes inteiras verdes e só apareceram numa máquina de verdade —
# o perfil AppArmor do kea que só lê /etc/kea, o prompt de conffile do dpkg numa
# máquina pelada, o ReadWritePaths que não remonta um caminho ausente no start.
# O que este script faz é exercitar a API por HTTP contra um sistema instalado,
# não chamar funções Go.
#
# Uso:
#   scripts/vm-validate.sh --deb dist/linkguard-fw_X_amd64.deb
#   scripts/vm-validate.sh --deb novo.deb --from-deb antigo.deb   # + upgrade
#
# --from-deb liga a bateria de upgrade: instala o pacote antigo primeiro, anota
# o estado, instala o novo por cima e confere o que a migração deveria ter feito
# (e o que ela NÃO deveria ter feito).
#
# Pré-requisitos: a VM de ~/linkguard-testvm (recreate.sh / destroy.sh / ssh.sh),
# python3 no host (gera o código TOTP), e o painel encaminhado em 127.0.0.1:9997.
#
# Saída: uma linha por verificação. Sai com 1 se qualquer uma falhar.

set -uo pipefail

VM_DIR="${VM_DIR:-$HOME/linkguard-testvm}"
API="${API:-http://127.0.0.1:9997}"
DEB=""
FROM_DEB=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deb)      DEB="$2"; shift 2 ;;
    --from-deb) FROM_DEB="$2"; shift 2 ;;
    *) echo "argumento desconhecido: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$DEB" ]] || { echo "uso: $0 --deb <pacote.deb> [--from-deb <anterior.deb>]" >&2; exit 2; }
[[ -f "$DEB" ]] || { echo "não achei o .deb: $DEB" >&2; exit 2; }
[[ -z "$FROM_DEB" || -f "$FROM_DEB" ]] || { echo "não achei o --from-deb: $FROM_DEB" >&2; exit 2; }

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mOK\033[0m   %s\n' "$1"; }
# PULADAS registra bateria que não rodou. Sem isto, "N verificações OK, 0
# falhas" descreve a cobertura que a rodada TEVE e não a que ela deveria ter, e
# as duas divergem em silêncio: a bateria de upgrade só roda com --from-deb, e
# sem ela o resumo dizia 207 OK / 0 falhas exatamente como se tivesse rodado
# tudo. Uma suíte que esconde o que não mediu é pior do que uma que falha.
PULADAS=()
pular() { PULADAS+=("$1 — $2"); printf '\n\033[1m%s\033[0m\n  \033[33mPULADA\033[0m %s\n' "$1" "$2"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFALHA\033[0m %s\n' "$1"; [[ -n "${2:-}" ]] && printf '        %s\n' "$2"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

vm()  { ssh -i "$VM_DIR/vm_key" -p 2222 -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            -o LogLevel=ERROR root@127.0.0.1 "$@"; }

# api METHOD PATH [TOKEN] [BODY] → imprime "HTTP_STATUS\nCORPO"
api() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-s -o /tmp/lgv_body -w '%{http_code}' -X "$method" "$API$path")
  [[ -n "$token" ]] && args+=(-H "Authorization: Bearer $token")
  [[ -n "$body"  ]] && args+=(-H 'Content-Type: application/json' -d "$body")
  # ZERA O CORPO ANTES DE CADA CHAMADA. Quando o curl não consegue conectar, o
  # `-o` não escreve o arquivo — e a asserção seguinte lia a RESPOSTA ANTERIOR
  # como se fosse a desta chamada. Foi assim que uma asserção sobre contenção
  # recebeu uma lista de links e falhou dizendo a coisa errada.
  : > /tmp/lgv_body
  local code; code=$(curl "${args[@]}")
  echo "$code"; cat /tmp/lgv_body 2>/dev/null; echo
}
status() { api "$@" | head -1; }
body()   { api "$@" | tail -n +2; }

jqf() { python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('$1',''))" 2>/dev/null; }

# role_perms TOKEN ROLE_ID → permissões do papel, uma por linha.
# Não existe GET /api/roles/{id}; a listagem é a fonte.
role_perms() {
  body GET /api/roles "$1" | python3 -c "
import json,sys
rid=sys.argv[1]
for r in json.load(sys.stdin):
    if r.get('id')==rid:
        for p in (r.get('permissions') or []): print(p)
" "$2" 2>/dev/null
}

# login USUARIO SENHA [CODIGO] → token, ou vazio
login() {
  local u="$1" p="$2" c="${3:-}"
  body POST /api/auth/login "" "{\"username\":\"$u\",\"password\":\"$p\",\"code\":\"$c\"}" | jqf token
}

totp() { # totp SEGREDO_BASE32
  python3 - "$1" <<'PY'
import base64, hmac, hashlib, struct, sys, time
secret = sys.argv[1].strip().upper()
secret += "=" * (-len(secret) % 8)
key = base64.b32decode(secret)
counter = int(time.time()) // 30
h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
o = h[-1] & 0x0F
print("%06d" % ((struct.unpack(">I", h[o:o+4])[0] & 0x7FFFFFFF) % 1000000))
PY
}

wait_api() { # espera o painel responder
  for _ in $(seq 1 60); do
    [[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/api/health" || true)" == "200" ]] && return 0
    sleep 2
  done
  return 1
}

recreate_vm() {
  head_ "Recriando a VM do zero (Debian pelado, sem nftables/kea/unbound/chrony)"
  "$VM_DIR/destroy.sh"  >/dev/null 2>&1 || true
  "$VM_DIR/recreate.sh" >/dev/null 2>&1 || { bad "recreate.sh falhou"; exit 1; }
  ok "VM recriada e acessível por SSH"
}

install_deb() { # install_deb ARQUIVO ROTULO
  local file="$1" label="$2"
  scp -i "$VM_DIR/vm_key" -P 2222 -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      "$file" root@127.0.0.1:/tmp/pkg.deb >/dev/null 2>&1 \
    || { bad "scp do .deb ($label) falhou"; return 1; }
  # DEBIAN_FRONTEND=noninteractive + confold: um prompt de conffile aqui trava a
  # instalação para sempre, e já travou uma vez.
  if vm "DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confold /tmp/pkg.deb" >/tmp/lgv_install 2>&1; then
    ok "instalação do .deb ($label) sem prompt e sem erro"
  else
    bad "instalação do .deb ($label) falhou" "$(tail -5 /tmp/lgv_install)"
    return 1
  fi
  vm "systemctl enable --now linkguard-fw" >/dev/null 2>&1 || true

  # O padrão do produto é escutar em 127.0.0.1. Dentro da VM isso é o loopback
  # da guest, e o hostfwd do qemu entrega na NIC (10.0.2.15) — então o painel
  # fica inalcançável do host. Abrir o listen_addr é o que uma instalação real
  # faz de qualquer jeito (o painel precisa ser alcançável da LAN), e não muda
  # nenhum comportamento que este script verifica.
  vm "sed -i 's/\"listen_addr\": \"127.0.0.1\"/\"listen_addr\": \"0.0.0.0\"/' /etc/linkguard-fw/config.json && systemctl restart linkguard-fw" >/dev/null 2>&1

  wait_api || {
    bad "o painel não respondeu depois de instalar ($label)" \
        "$(vm 'systemctl is-active linkguard-fw; ss -tlnp | grep 9997 || echo "nada escutando em 9997"' 2>&1 | tr '\n' ' ')"
    return 1
  }
  ok "serviço no ar e /api/health respondendo ($label)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Bateria A — instalação do zero
# ─────────────────────────────────────────────────────────────────────────────
battery_fresh() {
  recreate_vm
  head_ "A. Instalação do zero"
  install_deb "$DEB" "novo" || return

  # A1 — a senha inicial existe, é aleatória e o arquivo é 0600.
  local mode initial
  mode=$(vm "stat -c %a /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r')
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  if [[ "$mode" == "600" ]]; then ok "senha inicial gravada com modo 0600"
  else bad "modo do arquivo de senha inicial é '$mode', esperado 600"; fi
  if [[ ${#initial} -ge 16 ]]; then ok "senha inicial tem ${#initial} caracteres (aleatória)"
  else bad "senha inicial curta ou ausente: '${initial}'"; fi
  if vm "journalctl -u linkguard-fw --no-pager | grep -qi 'PRIMEIRA EXECU'"; then
    ok "a senha inicial também foi para o log do serviço"
  else bad "o log não registrou a senha inicial"; fi

  # A2 — admin/admin NÃO entra mais. É o coração do GHSA-mmx5.
  if [[ -z "$(login admin admin)" ]]; then ok "admin/admin recusado (senha de fábrica não existe mais)"
  else bad "admin/admin AINDA ENTRA — a senha de fábrica voltou"; fi

  local tok; tok=$(login admin "$initial")
  if [[ -n "$tok" ]]; then ok "login com a senha gerada funciona"
  else bad "não consegui entrar com a senha gerada"; fi

  # Recuo deliberado para admin/admin quando não há senha gerada. Não é
  # complacência: é o que permite rodar esta bateria contra um pacote ANTIGO,
  # de controle, e ver as checagens de segurança abaixo ficarem vermelhas. Um
  # script de validação que aborta no primeiro tropeço nunca prova que as
  # verificações seguintes exercitam alguma coisa.
  if [[ -z "$tok" ]]; then
    tok=$(login admin admin)
    [[ -n "$tok" ]] && printf '       (seguindo com admin/admin — modo controle)\n'
  fi
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; o resto da bateria não roda"; return; }

  # A3 — troca da própria senha (rota que não existia).
  local st
  st=$(status POST /api/auth/change-password "$tok" '{"current_password":"errada","new_password":"NovaSenhaForte123"}')
  if [[ "$st" == "403" ]]; then ok "change-password recusa senha atual errada (403)"
  else bad "change-password com senha atual errada devolveu $st, esperado 403"; fi

  st=$(status POST /api/auth/change-password "$tok" "{\"current_password\":\"$initial\",\"new_password\":\"NovaSenhaForte123\"}")
  if [[ "$st" == "200" ]]; then ok "change-password troca a senha (200)"
  else bad "change-password devolveu $st, esperado 200"; fi

  st=$(status GET /api/auth/me "$tok")
  if [[ "$st" == "401" ]]; then ok "o token antigo foi invalidado pela troca (401)"
  else bad "o token antigo ainda vale depois da troca ($st)"; fi

  if [[ -z "$(login admin "$initial")" ]]; then ok "a senha antiga não entra mais"
  else bad "a senha antiga continua valendo"; fi

  local newtok; newtok=$(login admin "NovaSenhaForte123")
  if [[ -n "$newtok" ]]; then ok "a senha nova entra"; tok="$newtok"
  else bad "a senha nova não entra"; fi
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; o resto da bateria não roda"; return; }

  # A4 — GHSA-8mxq: a rota de mutação legada sumiu.
  st=$(status DELETE /api/firewall/rules "$tok" '{"table":"filter","chain":"DOCKER-USER","line":1}')
  if [[ "$st" == "405" || "$st" == "404" ]]; then ok "DELETE /api/firewall/rules não existe mais ($st)"
  else bad "DELETE /api/firewall/rules respondeu $st — a rota que apaga chain do Docker voltou"; fi

  # A5 — GHSA-wj8j: o setup de 2FA não desliga um 2FA ativo.
  local secret code
  secret=$(body POST /api/auth/2fa/setup "$tok" '{}' | jqf secret)
  if [[ -n "$secret" ]]; then ok "2FA: setup devolve um segredo"
  else bad "2FA: setup não devolveu segredo"; fi
  if [[ -n "$secret" ]]; then
    code=$(totp "$secret")
    st=$(status POST /api/auth/2fa/activate "$tok" "{\"code\":\"$code\"}")
    if [[ "$st" == "200" ]]; then ok "2FA: ativado com código válido"
    else bad "2FA: activate devolveu $st"; fi

    st=$(status POST /api/auth/2fa/setup "$tok" '{}')
    if [[ "$st" == "409" ]]; then ok "2FA: setup em conta já protegida é recusado (409)"
    else bad "2FA: setup respondeu $st com 2FA ativo — o desligamento silencioso voltou"; fi

    local enabled; enabled=$(body GET /api/auth/2fa "$tok" | jqf enabled)
    if [[ "$enabled" == "True" || "$enabled" == "true" ]]; then ok "2FA continua ativo depois da tentativa de setup"
    else bad "2FA foi DESLIGADO por uma chamada de setup"; fi

    code=$(totp "$secret")
    st=$(status POST /api/auth/2fa/disable "$tok" "{\"code\":\"$code\"}")
    [[ "$st" == "200" ]] && ok "2FA: desativado com código válido" || bad "2FA: disable devolveu $st"
  fi

  # A6 — GHSA-xh59: a senha do SMTP não vai para um host trocado.
  status PUT /api/notifications "$tok" \
    '{"email":{"enabled":true,"host":"smtp.empresa.local","port":587,"username":"u@empresa.local","password":"SenhaCorporativa1","from":"a@b","to":"c@d"}}' >/dev/null
  # ATENÇÃO: conferir só o status 400 aqui NÃO prova nada — o build vulnerável
  # também devolve 400, porque a conexão SMTP com o host do atacante falha. Foi
  # exatamente assim que esta verificação passou verde num pacote sem a
  # correção, na primeira rodada de controle. O que separa os dois casos é a
  # MENSAGEM: a recusa da correção acontece antes de qualquer conexão.
  local resp
  resp=$(api POST "/api/notifications/test?channel=email" "$tok" \
    '{"email":{"enabled":true,"host":"smtp.atacante.tld","port":587,"username":"u@empresa.local","password":"********","from":"a@b","to":"c@d"}}')
  st=$(head -1 <<<"$resp")
  local msg; msg=$(tail -n +2 <<<"$resp")
  if [[ "$st" == "400" ]] && grep -q 'servidor SMTP mudou' <<<"$msg"; then
    ok "notificações: host trocado + senha mascarada recusado ANTES de conectar (400)"
  else
    bad "notificações: host trocado respondeu $st sem a recusa do mergeSecrets — a senha pode estar indo ao host novo" "$msg"
  fi

  # E o contraponto: mesma requisição com o host ORIGINAL tem que passar do
  # mergeSecrets (a falha, se houver, vira erro de conexão, não a recusa).
  resp=$(api POST "/api/notifications/test?channel=email" "$tok" \
    '{"email":{"enabled":true,"host":"smtp.empresa.local","port":587,"username":"u@empresa.local","password":"********","from":"a@b","to":"c@d"}}')
  if grep -q 'servidor SMTP mudou' <<<"$(tail -n +2 <<<"$resp")"; then
    bad "notificações: host INALTERADO foi recusado — a correção apertou demais e quebrou a edição legítima"
  else
    ok "notificações: host inalterado não é recusado pelo mergeSecrets"
  fi

  # A7 — GHSA-f7f2: users.manage sozinho não redefine a senha de um admin.
  local hd_role hd_user hd_tok admin_id
  hd_role=$(body POST /api/roles "$tok" '{"name":"Helpdesk VM","description":"só users.manage","permissions":["users.manage"]}' | jqf id)
  if [[ -n "$hd_role" ]]; then
    hd_user=$(body POST /api/users "$tok" "{\"username\":\"helpdesk\",\"password\":\"SenhaHelpdesk1\",\"role_ids\":[\"$hd_role\"]}" | jqf id)
    hd_tok=$(login helpdesk "SenhaHelpdesk1")
    admin_id=$(body GET /api/auth/me "$tok" | jqf id)
    if [[ -n "$hd_tok" && -n "$admin_id" ]]; then
      st=$(status PUT "/api/users/$admin_id" "$hd_tok" '{"password":"SenhaTomada12345"}')
      if [[ "$st" == "403" ]]; then ok "helpdesk (users.manage) não redefine a senha do admin (403)"
      else bad "helpdesk redefiniu a senha do admin — resposta $st. ESCALAÇÃO PARA ROOT."; fi
      if [[ -z "$(login admin "SenhaTomada12345")" ]]; then ok "a senha do admin continua intacta"
      else bad "a senha do admin FOI TROCADA pelo helpdesk"; fi
      # e o auto-reset dele continua permitido
      st=$(status PUT "/api/users/$hd_user" "$hd_tok" '{"password":"MinhaSenhaNova1"}')
      if [[ "$st" == "200" ]]; then ok "helpdesk troca a PRÓPRIA senha normalmente (200)"
      else bad "helpdesk não consegue trocar a própria senha ($st) — a correção apertou demais"; fi
    else bad "não consegui preparar o cenário do helpdesk"; fi
  else bad "não consegui criar o papel de helpdesk"; fi

  # A8 — GHSA-jpcw: somente-leitura não resolve alerta.
  local viewer_role viewer_tok
  viewer_role=$(body POST /api/roles "$tok" '{"name":"Visualizador VM","description":"leitura","permissions":["monitoring.read","dashboard.read"]}' | jqf id)
  if [[ -n "$viewer_role" ]]; then
    body POST /api/users "$tok" "{\"username\":\"visualizador\",\"password\":\"SenhaViewer123\",\"role_ids\":[\"$viewer_role\"]}" >/dev/null
    viewer_tok=$(login visualizador "SenhaViewer123")
    if [[ -n "$viewer_tok" ]]; then
      st=$(status GET /api/alerts "$viewer_tok")
      [[ "$st" == "200" ]] && ok "visualizador continua LENDO alertas (200)" || bad "visualizador perdeu a leitura de alertas ($st)"
      st=$(status PUT "/api/alerts/qualquer-id/resolve" "$viewer_tok")
      if [[ "$st" == "403" ]]; then ok "visualizador não resolve alerta (403)"
      else bad "visualizador resolveu alerta — resposta $st"; fi
    else bad "não consegui entrar como visualizador"; fi
  else bad "não consegui criar o papel de visualizador"; fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Bateria C — confirmar-ou-reverte (issue #20)
# ─────────────────────────────────────────────────────────────────────────────
#
# Por que esta bateria existe: o confirmar-ou-reverte é a rede que impede o
# admin de se trancar fora da máquina, e nenhuma das 37 verificações anteriores
# encostava nele. A #20 trouxe a ordem dos oito passos para um lugar só
# (firewallrules.ApplyGuarded), e um refactor dessa rede não pode ser dado por
# bom só porque a suíte Go passou: o que interessa é o comportamento por HTTP
# contra um sistema instalado, com nftables de verdade embaixo.
#
# Cada verificação abaixo é um dos becos que os comentários do mecanismo
# registram ter sido vividos — C-5, C-6, N-2, N-3, N-4 — mais a trava e o
# caminho feliz.

# jqk CHAVE — extrai uma chave do JSON no stdin (o jqf já existe, mas este
# aceita caminho aninhado "a.b").
jqk() {
  python3 -c "
import json,sys
d=json.load(sys.stdin)
for part in sys.argv[1].split('.'):
    d = (d or {}).get(part) if isinstance(d, dict) else None
print(d if d is not None else '')
" "$1" 2>/dev/null
}

battery_confirm_revert() {
  [[ -n "$FROM_DEB" ]] && recreate_vm || true
  head_ "C. Confirmar-ou-reverte"
  # A VM já está instalada pela bateria anterior quando --from-deb foi passado;
  # senão, reaproveita a instalação da bateria A.
  if [[ -n "$FROM_DEB" ]]; then
    install_deb "$DEB" "novo" || return
  fi

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria C não roda"; return; }

  local st resp

  # C1 — mutação de FORWARD não abre janela. Abrir uma para toda mutação
  # travaria a edição do firewall por 90 segundos a cada regra salva.
  st=$(status POST /api/nftables/groups "$tok" \
    '{"name":"Bateria C forward","scope":"forward","fallthrough":"continue","cond_saddr":"10.9.9.0/24"}')
  if [[ "$st" == "200" ]]; then ok "grupo de forward criado (200)"
  else bad "criação de grupo de forward devolveu $st"; fi
  if [[ "$(body GET /api/nftables/pending "$tok" | jqk pending)" == "" ]]; then
    ok "mutação de forward NÃO abriu janela de confirmação"
  else bad "uma mutação de forward abriu janela — a edição ficaria travada 90s à toa"; fi

  # C2 — o caminho que importa: mutação de INPUT abre a janela.
  resp=$(api POST /api/nftables/groups "$tok" \
    '{"name":"Bateria C input","scope":"input","fallthrough":"continue","cond_saddr":"10.9.9.0/24"}')
  st=$(head -1 <<<"$resp")
  local pend_id
  pend_id=$(tail -n +2 <<<"$resp" | jqk pending.id)
  if [[ "$st" == "200" && -n "$pend_id" ]]; then ok "mutação de escopo input abriu a janela de confirmação"
  else bad "mutação de input NÃO abriu janela (status $st) — ela valeria sem reversão automática"; fi

  # C3 — a TRAVA (spec §5.3). Com duas mudanças pendentes, "reverter ao estado
  # anterior" não teria resposta.
  resp=$(api POST /api/nftables/groups "$tok" \
    '{"name":"Bateria C segunda","scope":"forward","fallthrough":"continue"}')
  st=$(head -1 <<<"$resp")
  if [[ "$st" == "409" ]]; then ok "segunda mutação recusada com janela aberta (409)"
  else bad "segunda mutação passou com janela aberta (status $st)"; fi
  # E a recusa precisa NOMEAR a mudança e quem a aplicou: é o que o operador usa
  # para decidir entre confirmar e reverter.
  if grep -q 'aguardando confirmação' <<<"$(tail -n +2 <<<"$resp")"; then
    ok "a recusa nomeia a mudança pendente"
  else bad "a recusa de 409 não diz qual mudança está pendente"; fi

  # C4 — confirmar resolve a janela e libera a edição.
  #
  # O id no corpo é OBRIGATÓRIO, e não burocracia: sem ele a ação valeria sobre
  # a janela que estivesse aberta no instante da chamada, e não sobre a que o
  # operador viu na faixa. Escrever esta bateria sem o id rendeu um 400 com
  # exatamente essa explicação — o produto está certo, o teste é que estava.
  local janela
  janela=$(body GET /api/nftables/pending "$tok" | jqk pending.id)
  if [[ -n "$janela" ]]; then ok "o painel devolve o id da janela aberta"
  else bad "GET /pending não trouxe o id da janela"; fi
  st=$(status POST /api/nftables/pending/confirm "$tok" "{\"id\":\"$janela\"}")
  if [[ "$st" == "200" ]]; then ok "confirmar acesso resolveu a janela (200)"
  else bad "confirmar devolveu $st"; fi
  if [[ "$(body GET /api/nftables/pending "$tok" | jqk pending)" == "" ]]; then
    ok "não há mais pendente depois de confirmar"
  else bad "o pendente sobreviveu ao confirmar"; fi
  st=$(status POST /api/nftables/groups "$tok" \
    '{"name":"Bateria C pos-confirm","scope":"forward","fallthrough":"continue"}')
  if [[ "$st" == "200" ]]; then ok "a edição voltou a ser aceita depois de confirmar"
  else bad "a edição continua travada depois de confirmar ($st)"; fi

  # C4b — e sem o id a ação é RECUSADA. Isto é uma garantia, não um detalhe de
  # validação: aceitar "confirme o que estiver aberto" faria o operador
  # confirmar a janela de outro admin que tivesse nascido no meio do caminho.
  st=$(status POST /api/nftables/pending/confirm "$tok" '{}')
  if [[ "$st" == "400" ]]; then ok "confirmar sem o id da janela é recusado (400)"
  else bad "confirmar sem id devolveu $st — agiria sobre a janela que estivesse aberta"; fi

  # C5 — REVERTER desfaz a mudança no banco E no firewall vivo.
  resp=$(api POST /api/nftables/groups "$tok" \
    '{"name":"Bateria C reverter","scope":"input","fallthrough":"continue","cond_saddr":"10.9.9.0/24"}')
  local gid
  gid=$(tail -n +2 <<<"$resp" | jqk id)
  if [[ -n "$gid" ]]; then ok "grupo de input criado para o teste de reversão"
  else bad "não consegui criar o grupo de input para reverter"; fi

  janela=$(body GET /api/nftables/pending "$tok" | jqk pending.id)
  st=$(status POST /api/nftables/pending/revert "$tok" "{\"id\":\"$janela\"}")
  if [[ "$st" == "200" ]]; then ok "reverter agora concluiu (200)"
  else bad "reverter devolveu $st"; fi

  # O grupo tem que ter SUMIDO — é o que "voltar ao estado anterior" significa.
  if body GET /api/nftables/groups "$tok" | grep -q "Bateria C reverter"; then
    bad "a reversão respondeu 200 e o grupo continua no banco"
  else ok "a reversão apagou do banco o grupo que a janela criou"; fi

  # E o firewall VIVO não pode ter ficado com a chain do grupo revertido: banco
  # e nft discordando é a confiança falsa que este painel existe para eliminar.
  if vm "nft list ruleset 2>/dev/null" | grep -q "$(cut -c1-12 <<<"${gid//-/}")"; then
    bad "a chain do grupo revertido continua no nftables vivo"
  else ok "o nftables vivo não tem mais a chain do grupo revertido"; fi

  # C6 — N-2, o beco sem saída: a trava LIBERA quando a reversão já terminou no
  # banco. Travar aí prendia o operador sem saída — não dava para apagar a regra
  # que quebra o reconcile, nem confirmar, nem reverter, e o reboot repetia tudo.
  st=$(status POST /api/nftables/groups "$tok" \
    '{"name":"Bateria C pos-revert","scope":"forward","fallthrough":"continue"}')
  if [[ "$st" == "200" ]]; then ok "a edição voltou a ser aceita depois de reverter"
  else bad "a edição ficou travada depois de uma reversão concluída ($st) — é o beco N-2"; fi

  # C7 — C-5: corpo inválido é recusado com 400, e a mensagem fala do CAMPO.
  # Antes da correção original, ler o banco primeiro fazia um corpo inválido
  # virar 500 quando o banco estava fora do ar, e o admin não ficava sabendo que
  # o problema era o que ele mandou.
  resp=$(api POST /api/nftables/groups "$tok" \
    '{"name":"Bateria C invalida","scope":"nao-existe","fallthrough":"continue"}')
  st=$(head -1 <<<"$resp")
  if [[ "$st" == "400" ]]; then ok "escopo inválido recusado com 400 (validação antes do banco)"
  else bad "escopo inválido devolveu $st, esperado 400"; fi

  # C8 — o pré-voo `nft -c`: uma regra que o nft recusa não pode chegar ao
  # banco. Porta 99999 não existe.
  local fwd_gid
  fwd_gid=$(body GET /api/nftables/groups "$tok" | python3 -c "
import json,sys
for g in json.load(sys.stdin).get('groups',[]):
    if g.get('name')=='Bateria C forward': print(g['id']); break
" 2>/dev/null)
  if [[ -n "$fwd_gid" ]]; then
    st=$(status POST /api/nftables/rules "$tok" \
      "{\"group_id\":\"$fwd_gid\",\"action\":\"drop\",\"proto\":\"tcp\",\"dport\":\"99999\"}")
    if [[ "$st" == "400" ]]; then ok "porta inválida recusada antes de chegar ao banco (400)"
    else bad "porta 99999 devolveu $st, esperado 400"; fi
    if body GET /api/nftables/rules "$tok" | grep -q '99999'; then
      bad "a regra recusada pelo pré-voo foi gravada no banco assim mesmo"
    else ok "a regra recusada não existe no banco"; fi
  else bad "não achei o grupo de forward para o teste de pré-voo"; fi

  # C9 — reiniciar com a janela aberta REVERTE a mudança
  # (firewallrules.RevertPendingOnBoot).
  #
  # A primeira versão desta verificação afirmava o contrário — que a janela
  # sobreviveria ao restart — e ficou vermelha. O produto é que está certo, e a
  # razão é a melhor possível: se o serviço reiniciou, o motivo pode muito bem
  # ter sido a própria mudança tirando o acesso à máquina. Esperar confirmação
  # de alguém que talvez não consiga mais chegar ao painel é apostar contra o
  # operador. O boot desfaz e pronto.
  #
  # O que mora no banco, e é isso que o pendente garante, é a MARCA de que a
  # reversão começou: sem ela, um processo novo voltava a aceitar "confirmar"
  # uma mudança cujo estado anterior já tinha sido restaurado.
  api POST /api/nftables/groups "$tok" \
    '{"name":"Bateria C restart","scope":"input","fallthrough":"continue","cond_saddr":"10.9.9.0/24"}' >/dev/null
  vm "systemctl restart linkguard-fw" >/dev/null 2>&1
  wait_api || { bad "o serviço não voltou depois do restart"; return; }
  tok=$(login admin "$initial"); [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  if [[ -z "$(body GET /api/nftables/pending "$tok" | jqk pending.id)" ]]; then
    ok "o restart resolveu a janela em aberto (reversão no boot)"
  else bad "a janela continua pendente depois do restart"; fi
  if body GET /api/nftables/groups "$tok" | grep -q "Bateria C restart"; then
    bad "o restart não desfez a mudança de input que ninguém confirmou"
  else ok "o restart desfez a mudança de input não confirmada"; fi

  # C10 — e a reversão automática por PRAZO acontece sozinha, sem ninguém pedir.
  # É a promessa inteira do mecanismo: "se você não confirmar, volta".
  api POST /api/nftables/groups "$tok" \
    '{"name":"Bateria C prazo","scope":"input","fallthrough":"continue","cond_saddr":"10.9.9.0/24"}' >/dev/null
  printf '       (aguardando o prazo de 90s vencer para a reversão automática)\n'
  local i
  for i in $(seq 1 24); do
    sleep 5
    [[ -z "$(body GET /api/nftables/pending "$tok" | jqk pending.id)" ]] && break
  done
  if [[ -z "$(body GET /api/nftables/pending "$tok" | jqk pending.id)" ]]; then
    ok "a janela venceu e foi revertida automaticamente"
  else bad "o prazo passou e a janela continua aberta — a reversão automática não aconteceu"; fi
  if body GET /api/nftables/groups "$tok" | grep -q "Bateria C prazo"; then
    bad "a reversão automática não desfez o grupo de input"
  else ok "a reversão automática desfez o grupo que ninguém confirmou"; fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Bateria B — upgrade sobre uma instalação que já roda
# ─────────────────────────────────────────────────────────────────────────────
battery_upgrade() {
  if [[ -z "$FROM_DEB" ]]; then
    pular "B. Upgrade sobre instalação existente" \
          "sem --from-deb; produção é upgrade, não instalação nova — esta rodada não mediu esse caminho"
    return 0
  fi
  recreate_vm
  head_ "B. Upgrade sobre instalação existente"
  install_deb "$FROM_DEB" "anterior" || return

  # A senha da versão anterior depende de QUAL versão ela é. Até a v1.0.93 toda
  # instalação nascia com admin/admin; da v1.0.94 em diante a senha é gerada e
  # fica em /etc/linkguard-fw/initial-admin-password. O script precisa servir
  # aos dois casos, senão ele passa a só conseguir testar upgrades a partir de
  # pacotes antigos — e é justamente o upgrade a partir do ATUAL que interessa
  # daqui para a frente.
  local basepw tok
  basepw=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  if [[ -n "$basepw" ]]; then
    tok=$(login admin "$basepw")
    [[ -n "$tok" ]] && ok "versão anterior: entra com a senha gerada na instalação"
  else
    basepw="admin"
    tok=$(login admin admin)
    [[ -n "$tok" ]] && ok "versão anterior: admin/admin entra (comportamento de fábrica até a v1.0.93)"
  fi
  [[ -n "$tok" ]] || { bad "não consegui entrar na versão anterior — o cenário de upgrade não foi montado"; return; }

  # Papel operacional de antes do upgrade, com monitoring.read e uma escrita.
  local op_role
  op_role=$(body POST /api/roles "$tok" '{"name":"Operador VM","description":"operacional","permissions":["monitoring.read","firewall.write"]}' | jqf id)
  local view_role
  view_role=$(body POST /api/roles "$tok" '{"name":"Visualizador VM","description":"leitura","permissions":["monitoring.read"]}' | jqf id)
  [[ -n "$op_role" && -n "$view_role" ]] && ok "papéis de antes do upgrade criados" || bad "não consegui criar os papéis"

  # Estado da base, para as asserções pós-upgrade compararem contra ele em vez
  # de contra uma suposição.
  local pwfile_antes base_conhece_mw
  pwfile_antes=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  if body GET /api/permissions "$tok" | grep -q 'monitoring.write'; then
    base_conhece_mw="sim"
    printf '       (a base já conhece monitoring.write — a migração já rodou nela)\n'
  else
    base_conhece_mw="nao"
  fi

  head_ "B. Instalando a versão nova por cima"
  install_deb "$DEB" "novo" || return

  tok=$(login admin "$basepw")
  if [[ -n "$tok" ]]; then ok "a senha do admin sobreviveu ao upgrade (o seed não sobrescreve)"
  else bad "a senha do admin mudou no upgrade — instalação existente ficaria inacessível"; return; fi

  # Existência sozinha não diz nada: da v1.0.94 em diante o pacote BASE já cria
  # este arquivo na instalação limpa. O que o upgrade não pode fazer é gerar uma
  # senha NOVA — isso significaria ter recriado ou sobrescrito a conta. Por isso
  # a comparação é do conteúdo, capturado antes de subir a versão nova.
  local pwfile_depois
  pwfile_depois=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  if [[ "$pwfile_depois" == "$pwfile_antes" ]]; then
    if [[ -z "$pwfile_antes" ]]; then ok "o upgrade não criou arquivo de senha inicial (a conta já existia)"
    else ok "o arquivo de senha inicial ficou intacto no upgrade"; fi
  else
    bad "o upgrade mexeu na senha inicial gravada — sinal de conta recriada ou sobrescrita"
  fi

  # A asserção certa depende de QUAL base foi instalada, e presumir uma só foi o
  # que fez esta verificação falhar por engano quando a base virou a v1.0.94:
  #
  #   - base ANTERIOR à permissão: o papel foi criado sem monitoring.write
  #     porque ela não existia. A migração tem que concedê-la, senão um Operador
  #     legítimo perde no upgrade algo que fazia ontem.
  #   - base que JÁ tem a permissão: a migração já rodou e está marcada. Um papel
  #     criado depois disso tem exatamente o que o admin escolheu, e o upgrade
  #     NÃO pode acrescentar permissão nenhuma por conta própria.
  local perms
  perms=$(role_perms "$tok" "$op_role")
  if [[ "$base_conhece_mw" == "sim" ]]; then
    if grep -qx 'monitoring.write' <<<"$perms"; then
      bad "o upgrade acrescentou monitoring.write a um papel que o admin criou sem ela"
    else ok "o upgrade não mexeu nas permissões de um papel criado pelo admin"; fi
  else
    if grep -qx 'monitoring.write' <<<"$perms"; then
      ok "a migração deu monitoring.write ao papel operacional (não perdeu capacidade)"
    else bad "o papel operacional perdeu o resolver-alerta no upgrade"; fi
  fi

  perms=$(role_perms "$tok" "$view_role")
  if grep -qx 'monitoring.write' <<<"$perms"; then
    bad "o papel somente-leitura ganhou monitoring.write — é o que a correção existe para impedir"
  else ok "o papel somente-leitura NÃO ganhou monitoring.write"; fi

  # A migração não pode reverter uma revogação do admin: roda de novo no reboot.
  #
  # A permissão precisa ESTAR no papel para haver o que revogar. Antes, quando
  # ela não estava, a asserção inteira sumia sem imprimir nada — e ela não
  # estava justamente no caso que mais interessa: upgrade a partir de uma
  # versão recente, em que a migração já rodou na base e portanto não
  # acrescenta nada. O caminho mais testado do produto era o único não medido.
  #
  # Concedê-la explicitamente quando falta não enfraquece a asserção: o que se
  # mede é "o admin revogou, o serviço reiniciou, e a migração não devolveu" —
  # e isso independe de como o papel ganhou a permissão.
  local before after
  before=$(role_perms "$tok" "$op_role")
  if ! grep -qx 'monitoring.write' <<<"$before"; then
    body PUT "/api/roles/$op_role" "$tok" '{"name":"Operador VM","description":"operacional","permissions":["monitoring.read","firewall.write","monitoring.write"]}' >/dev/null
    before=$(role_perms "$tok" "$op_role")
  fi
  if grep -qx 'monitoring.write' <<<"$before"; then
    body PUT "/api/roles/$op_role" "$tok" '{"name":"Operador VM","description":"operacional","permissions":["monitoring.read","firewall.write"]}' >/dev/null
    vm "systemctl restart linkguard-fw" >/dev/null 2>&1
    wait_api || { bad "o serviço não voltou depois do restart"; return; }
    tok=$(login admin "$basepw")
    after=$(role_perms "$tok" "$op_role")
    if grep -qx 'monitoring.write' <<<"$after"; then
      bad "o reboot devolveu uma permissão que o admin tinha revogado"
    else ok "revogação do admin sobrevive ao restart (a migração não roda de novo)"; fi
  else
    bad "não consegui pôr monitoring.write no papel; a asserção de revogação não foi medida"
  fi
}


# ─────────────────────────────────────────────────────────────────────────────
# Bateria D — a postura padrão do firewall (issues #78 e #92)
# ─────────────────────────────────────────────────────────────────────────────
#
# Esta bateria existe porque a bateria C, com dez verificações de
# confirmar-ou-reverte, não trocava a POSTURA em nenhuma delas — e a postura é a
# única mutação do produto que muda a chain inteira em vez de acrescentar uma
# linha a ela. Os testes de unidade provam o que o renderizador emite; só a VM
# prova o que o kernel faz com aquilo, e o que sobra no disco para o próximo
# boot.
#
# As três perguntas que só aqui têm resposta:
#
#   1. bloquear o que ATRAVESSA deixa o painel e o SSH de pé? (é a diferença
#      entre as chains forward e input, e errá-la é o operador se trancar fora);
#   2. a troca é atômica de verdade — a chain nunca aparece vazia com política
#      drop, que seria a rede inteira caindo a cada reconciliação;
#   3. o bloqueio sobrevive ao reboot, e a reversão também.
battery_policy() {
  head_ "D. Postura padrão do firewall"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria D não roda"; return; }

  local resp st janela

  # D1 — o padrão de fábrica. Toda máquina instalada roda liberada nas duas
  # chains, e um upgrade que mude isso é o firewall se fechando sozinho.
  resp=$(body GET /api/nftables/policy "$tok")
  if [[ "$(jqk policy <<<"$resp")" == "accept" && "$(jqk forward <<<"$resp")" == "accept" ]]; then
    ok "a máquina nasce liberada nas duas chains"
  else bad "postura inicial inesperada: $resp"; fi

  # D2 — trocar a postura da FORWARD. Sem `chain` no corpo é a forward, que é o
  # que o admin quer dizer quando fala em "bloquear tudo".
  resp=$(api PUT /api/nftables/policy "$tok" '{"policy":"drop"}')
  st=$(head -1 <<<"$resp")
  janela=$(tail -n +2 <<<"$resp" | jqk pending.id)
  if [[ "$st" == "200" ]]; then ok "postura da forward trocada para bloquear (200)"
  else bad "a troca de postura devolveu $st"; fi
  if [[ -n "$janela" ]]; then ok "a troca de postura abriu a janela de confirmação"
  else bad "a troca de postura NÃO abriu janela — valeria para sempre sem ninguém confirmar"; fi

  # D3 — o kernel. `policy drop` na forward, com as duas linhas de sobrevivência
  # ANTES de tudo. Sem `established,related` na frente, "bloquear tudo" derruba
  # cada conexão que a rede já tinha no instante em que é aplicado.
  local fwd
  fwd=$(vm "nft list chain inet linkguard forward 2>/dev/null")
  if grep -q 'policy drop' <<<"$fwd"; then ok "a chain forward viva está com policy drop"
  else bad "a forward viva não bloqueia: $(tr '\n' ' ' <<<"$fwd")"; fi
  if grep -q 'ct state established,related.*accept' <<<"$fwd"; then
    ok "as conexões já estabelecidas continuam passando"
  else bad "não há liberação de established na forward — a rede cairia inteira, não só o que não foi liberado"; fi
  if grep -q 'ct status dnat.*accept' <<<"$fwd"; then
    ok "os encaminhamentos de porta continuam funcionando"
  else bad "sem a liberação do DNAT: todo redirecionamento seria traduzido e descartado"; fi
  # E a ordem: a sobrevivência tem de vir antes de qualquer drop administrativo.
  #
  # A linha da DECLARAÇÃO sai antes da conta, e é essa a correção da #98: ela
  # contém `policy drop`, e a primeira versão desta asserção a tomava como se
  # fosse a primeira regra. O resultado não era só um falso positivo — era um
  # falso positivo PERMANENTE justamente no caso que importa. Com a postura em
  # `accept` a declaração diz `policy accept` e a asserção passava; com a
  # postura em `drop`, o único estado em que a ordem das regras de sobrevivência
  # decide se a rede fica de pé, ela sempre falhava. Nunca chegou a olhar para
  # uma regra.
  local primeira
  primeira=$(grep -v 'type filter hook' <<<"$fwd" | grep -E 'accept|drop' | head -1)
  if grep -q 'accept' <<<"$primeira"; then
    ok "a primeira regra da forward é de liberação, não de bloqueio"
  else bad "há um drop acima das regras de sobrevivência" "primeira regra: $(echo "$primeira" | tr -s ' ')"; fi

  # D4 — a pergunta que decide se o operador continua dentro da máquina:
  # bloquear o que ATRAVESSA não pode tocar no que CHEGA ao firewall.
  local inp
  inp=$(vm "nft list chain inet linkguard input 2>/dev/null")
  if grep -q 'policy accept' <<<"$inp"; then
    ok "a chain input continua liberada (painel e SSH de pé)"
  else bad "bloquear a forward bloqueou também o acesso à própria máquina — é assim que o admin se tranca fora"; fi
  # E o painel responde de verdade, não só a chain parece certa.
  if [[ -n "$(body GET /api/nftables/policy "$tok" | jqk forward)" ]]; then
    ok "o painel continua respondendo com a forward bloqueada"
  else bad "o painel parou de responder depois de bloquear a forward"; fi

  # D5 — reverter devolve a postura E limpa as linhas de sobrevivência. Elas não
  # podem sobrar numa chain permissiva: entrariam ACIMA dos jumps dos grupos e
  # anulariam, em silêncio, um bloqueio que o admin criou.
  st=$(status POST /api/nftables/pending/revert "$tok" "{\"id\":\"$janela\"}")
  if [[ "$st" == "200" ]]; then ok "reverter a troca de postura concluiu (200)"
  else bad "reverter a postura devolveu $st"; fi
  if [[ "$(body GET /api/nftables/policy "$tok" | jqk forward)" == "accept" ]]; then
    ok "a reversão devolveu a postura da forward para liberar"
  else bad "a reversão respondeu 200 e a postura continua bloqueando"; fi
  fwd=$(vm "nft list chain inet linkguard forward 2>/dev/null")
  if grep -q 'policy accept' <<<"$fwd"; then ok "o firewall vivo voltou a liberar"
  else bad "banco e nftables discordam depois da reversão — a confiança falsa que o painel existe para eliminar"; fi
  if grep -q 'ct state established,related' <<<"$fwd"; then
    bad "as regras de sobrevivência ficaram numa chain permissiva; elas anulariam os bloqueios dos grupos"
  else ok "as regras de sobrevivência saíram junto com a política restritiva"; fi

  # D6 — o bloqueio SOBREVIVE ao reboot. É a pergunta que nenhum teste de
  # unidade responde: a persistência do ruleset acontece depois da confirmação,
  # e um firewall que esquece a postura no boot é pior que um que nunca a teve.
  resp=$(api PUT /api/nftables/policy "$tok" '{"policy":"drop"}')
  janela=$(tail -n +2 <<<"$resp" | jqk pending.id)
  st=$(status POST /api/nftables/pending/confirm "$tok" "{\"id\":\"$janela\"}")
  if [[ "$st" == "200" ]]; then ok "a troca de postura foi confirmada"
  else bad "confirmar a troca de postura devolveu $st"; fi
  if vm "grep -c 'policy drop' /etc/nftables.conf 2>/dev/null" | grep -qv '^0$'; then
    ok "a postura restritiva foi gravada no ruleset de boot"
  else bad "o /etc/nftables.conf não tem a postura restritiva — o bloqueio sumiria no próximo boot"; fi

  vm "systemctl restart linkguard-fw" >/dev/null 2>&1
  wait_api || { bad "o serviço não voltou depois do restart"; return; }
  tok=$(login admin "$initial"); [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  if [[ "$(body GET /api/nftables/policy "$tok" | jqk forward)" == "accept" ]]; then
    bad "o restart esqueceu a postura que o admin confirmou"
  else ok "a postura confirmada sobreviveu ao restart"; fi
  if vm "nft list chain inet linkguard forward 2>/dev/null" | grep -q 'policy drop'; then
    ok "o firewall vivo voltou bloqueando depois do restart"
  else bad "o serviço voltou e a forward está liberada — a rede ficaria aberta após um reboot"; fi

  # D7 — e dá para VOLTAR. Uma máquina bloqueada que não pode ser liberada é
  # uma armadilha: `flush chain` não mexe em política, e sem a redeclaração da
  # chain no caminho permissivo o `drop` ficaria para sempre.
  resp=$(api PUT /api/nftables/policy "$tok" '{"policy":"accept"}')
  janela=$(tail -n +2 <<<"$resp" | jqk pending.id)
  status POST /api/nftables/pending/confirm "$tok" "{\"id\":\"$janela\"}" >/dev/null
  if vm "nft list chain inet linkguard forward 2>/dev/null" | grep -q 'policy accept'; then
    ok "a máquina bloqueada pôde ser liberada de volta"
  else bad "a forward continua em drop depois de pedir accept — a máquina ficou trancada em modo bloqueio"; fi

  # D8 — a outra chain, a perigosa. Ela existe e é escolhida explicitamente com
  # `chain: input`, nunca por engano.
  resp=$(api PUT /api/nftables/policy "$tok" '{"policy":"drop","chain":"input"}')
  janela=$(tail -n +2 <<<"$resp" | jqk pending.id)
  if [[ -n "$janela" ]]; then ok "a postura da input também abre janela"
  else bad "trocar a postura da input não abriu janela — é a mudança que tranca o admin fora"; fi
  # E a janela é revertida SEM confirmar, que é o comportamento que salva quem
  # errou: não confirmamos de propósito.
  status POST /api/nftables/pending/revert "$tok" "{\"id\":\"$janela\"}" >/dev/null
  if vm "nft list chain inet linkguard input 2>/dev/null" | grep -q 'policy accept'; then
    ok "reverter devolveu o acesso à própria máquina"
  else bad "a input continua bloqueada depois da reversão"; fi

  # D9 — valor inválido não vira accept nem drop em silêncio.
  st=$(status PUT /api/nftables/policy "$tok" '{"policy":"reject"}')
  if [[ "$st" == "400" ]]; then ok "postura inválida recusada com 400"
  else bad "postura inválida devolveu $st"; fi
}


# ─── E. Captura de pacotes (issue #114) ──────────────────────────────────────
#
# O que esta bateria existe para pegar, e que teste em Go NÃO pega: a captura
# depende de um binário externo, de escrita em disco dentro do sandbox da
# unidade e do perfil AppArmor `usr.sbin.tcpdump` do Debian. As três coisas só
# existem numa máquina de verdade. Na primeira validação (2026-08-20) o arquivo
# foi gravado normalmente, com o diretório entregue ao usuário `tcpdump` — é
# esse resultado que as asserções abaixo congelam, para que um upgrade de
# distribuição que aperte o perfil apareça aqui e não em produção.
battery_capture() {
  head_ "E. Captura de pacotes"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria E não roda"; return; }

  local resp st

  # E1 — a permissão nova existe no catálogo. Sem ela no papel, a aba não
  # aparece para ninguém e a feature fica invisível depois de instalada.
  if body GET /api/permissions "$tok" | grep -q 'traffic.capture'; then
    ok "traffic.capture está no catálogo de permissões"
  else bad "traffic.capture não aparece no catálogo — nenhum papel consegue receber a permissão"; fi

  # E2 — os tetos são do backend, não da tela. Quem chama a API direto não
  # escapa deles.
  resp=$(body GET /api/traffic/capture "$tok")
  if [[ "$(jqk limits.snaplen <<<"$resp")" == "96" ]]; then
    ok "o snaplen de 96 bytes é declarado pela API"
  else bad "snaplen inesperado: $resp"; fi

  # E3 — nome de interface que começa com hífen viraria flag do tcpdump.
  st=$(status POST /api/traffic/capture "$tok" '{"interface":"-i","duration_sec":5}')
  if [[ "$st" == "400" ]]; then ok "interface começando com hífen recusada (400)"
  else bad "interface \"-i\" devolveu $st — o valor entra no argv logo depois de -i"; fi

  # E4 — filtro é montado por campos validados; host que não é endereço não vira
  # expressão BPF crua.
  st=$(status POST /api/traffic/capture "$tok" '{"interface":"enp0s2","filter":{"host":"1.2.3.4 or -r /etc/shadow"},"duration_sec":5}')
  if [[ "$st" == "400" ]]; then ok "filtro com expressão embutida recusado (400)"
  else bad "filtro arbitrário aceito ($st) — -r e -w do tcpdump leem e gravam arquivo"; fi

  # E5 — a captura de verdade, guardando o arquivo.
  st=$(status POST /api/traffic/capture "$tok" '{"interface":"enp0s2","duration_sec":6,"save_file":true}')
  if [[ "$st" == "200" ]]; then ok "captura iniciada (200)"
  else bad "a captura não iniciou: $st"; return; fi

  # E6 — uma por vez. Duas capturas simultâneas em link cheio derrubam a
  # máquina de referência, e o serviço guarda uma só.
  st=$(status POST /api/traffic/capture "$tok" '{"interface":"enp0s2","duration_sec":5}')
  if [[ "$st" == "400" ]]; then ok "segunda captura simultânea recusada (400)"
  else bad "duas capturas ao mesmo tempo foram aceitas ($st)"; fi

  # O SSH desta própria validação é o tráfego que a captura enxerga.
  vm "ping -c 4 -i 0.3 10.0.2.2 >/dev/null 2>&1" >/dev/null 2>&1
  sleep 9

  resp=$(body GET /api/traffic/capture "$tok")
  if [[ "$(jqk capture.state <<<"$resp")" == "done" ]]; then ok "a captura terminou sozinha no prazo"
  else bad "estado inesperado: $(jqk capture.state <<<"$resp") — $(jqk capture.message <<<"$resp")"; fi

  local linhas; linhas=$(jqk capture.rows_shown <<<"$resp")
  if [[ -n "$linhas" && "$linhas" -gt 0 ]]; then ok "a captura trouxe $linhas linhas"
  else bad "captura sem nenhuma linha" "$(jqk capture.message <<<"$resp")"; fi

  # E7 — O ARQUIVO. Este é o AppArmor: se o perfil barrar a escrita, has_file
  # vem falso e a mensagem explica. É a asserção que justifica a bateria.
  # O `tr` não é enfeite: jqk imprime o booleano do Python ("True"), não o do
  # JSON. A primeira versão desta asserção comparava com "true" e acusou falha
  # com o arquivo de 5.396 bytes gravado no disco — falso negativo que custou
  # uma rodada inteira da bateria.
  if [[ "$(jqk capture.has_file <<<"$resp" | tr 'A-Z' 'a-z')" == "true" ]]; then
    ok "o .pcap foi gravado (AppArmor não barrou a escrita)"
  else bad "o .pcap não foi gravado" "$(jqk capture.message <<<"$resp")"; fi

  # E8 — e é um pcap de verdade, legível, com o snaplen que prometemos.
  local leitura
  leitura=$(vm "tcpdump -r /var/lib/linkguard-fw/captures/*.pcap -nn -c 1 2>&1 | head -2" | tr -d '\r')
  if grep -q 'snapshot length 96' <<<"$leitura"; then
    ok "o arquivo é um pcap válido, com snapshot length 96"
  else bad "o .pcap não abriu como esperado" "$leitura"; fi

  # E9 — o dono do diretório. O tcpdump do Debian rebaixa privilégio para o
  # usuário `tcpdump` antes de abrir o arquivo; se o diretório não for dele, a
  # captura "funciona" e o arquivo não aparece.
  if vm "stat -c %U /var/lib/linkguard-fw/captures" | tr -d '\r' | grep -qE 'tcpdump|root'; then
    ok "o diretório de capturas tem dono compatível com o rebaixamento do tcpdump"
  else bad "dono inesperado do diretório de capturas: $(vm 'stat -c %U /var/lib/linkguard-fw/captures')"; fi

  # E10 — download, que é o que sai da máquina.
  st=$(status GET /api/traffic/capture/file "$tok")
  if [[ "$st" == "200" ]]; then ok "o download do .pcap responde 200"
  else bad "o download devolveu $st"; fi

  # E11 — auditoria. Capturar tráfego alheio é poder de vigilância; sem rastro
  # de quem capturou e com que filtro, a feature não deveria existir.
  local logs; logs=$(body GET "/api/logs?limit=40" "$tok")
  if grep -q 'traffic.capture.start' <<<"$logs"; then ok "o início da captura foi para a auditoria"
  else bad "captura sem registro de auditoria"; fi
  if grep -q 'traffic.capture.download' <<<"$logs"; then ok "o download foi para a auditoria"
  else bad "download do .pcap sem registro de auditoria"; fi
}

# ─── F. Franquia por link (issue #126) ───────────────────────────────────────
#
# O que só uma máquina de verdade prova aqui: o consumo vem dos contadores de
# byte da interface, passa pelo amostrador de 1s e só vira linha no banco no
# flush de um minuto. Teste em Go exercita a aritmética; ele não prova que o
# número que chega no painel é o que o kernel contou.
battery_quota() {
  head_ "F. Franquia por link"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria F não roda"; return; }

  # Precisa de pelo menos um link. O auto-detect é o caminho do próprio produto.
  status POST /api/links/auto-detect "$tok" >/dev/null
  local link
  link=$(body GET /api/links "$tok" | python3 -c "
import json,sys
ls=json.load(sys.stdin)
print(ls[0]['id'] if ls else '')" 2>/dev/null)
  [[ -n "$link" ]] || { bad "nenhum link detectado; a bateria F não roda"; return; }

  local resp st

  # F1 — todo link aparece, com ou sem franquia declarada. Um link ausente da
  # lista é um link que ninguém consegue proteger.
  resp=$(body GET /api/quotas "$tok")
  if grep -q "$link" <<<"$resp"; then ok "o link aparece na lista de franquias"
  else bad "o link não veio em /api/quotas"; fi

  # F2 — dia de fechamento acima de 28 não existe em fevereiro.
  st=$(status PUT "/api/quotas/$link" "$tok" '{"limit_gb":1,"cycle_day":31,"alert_pct":80}')
  if [[ "$st" == "400" ]]; then ok "dia de fechamento 31 recusado (400)"
  else bad "dia 31 aceito ($st) — o ciclo sumiria em fevereiro"; fi

  # F3 — percentual de aviso fora da faixa.
  st=$(status PUT "/api/quotas/$link" "$tok" '{"limit_gb":1,"cycle_day":10,"alert_pct":150}')
  if [[ "$st" == "400" ]]; then ok "aviso em 150% recusado (400)"
  else bad "percentual fora da faixa aceito ($st)"; fi

  # F4 — franquia válida, e o ciclo calculado.
  st=$(status PUT "/api/quotas/$link" "$tok" '{"limit_gb":1,"cycle_day":28,"alert_pct":80}')
  if [[ "$st" == "200" ]]; then ok "franquia declarada (200)"
  else bad "declarar franquia devolveu $st"; fi

  resp=$(body GET /api/quotas "$tok")
  local ini fim
  ini=$(python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['link_id']=='$link': print(q['cycle_start'])" <<<"$resp" 2>/dev/null)
  fim=$(python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['link_id']=='$link': print(q['cycle_end'])" <<<"$resp" 2>/dev/null)
  if [[ -n "$ini" && -n "$fim" && "$fim" -gt "$ini" ]]; then
    ok "o ciclo tem início e fim, nessa ordem"
  else bad "ciclo inválido: início=$ini fim=$fim"; fi

  # F5 — O NÚMERO. Gera tráfego e espera o flush de um minuto. É a asserção que
  # prova a cadeia inteira: contador da interface → amostrador → banco → API.
  vm "ping -c 60 -s 20000 -i 0.02 10.0.2.2 >/dev/null 2>&1" >/dev/null 2>&1
  printf '       (aguardando o flush de 1 minuto do acumulador)\n'
  sleep 70
  local usado
  usado=$(body GET /api/quotas "$tok" | python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['link_id']=='$link': print(q['used_bytes'])" 2>/dev/null)
  if [[ -n "$usado" && "$usado" -gt 0 ]]; then ok "o consumo medido chegou ao painel ($usado bytes)"
  else bad "o consumo continuou zerado depois do flush — a cadeia de medição não fechou"; fi

  # F6 — remover a franquia não pode apagar o que já foi medido: é o histórico
  # do mês, e o admin pode declarar a franquia de novo amanhã.
  st=$(status DELETE "/api/quotas/$link" "$tok")
  if [[ "$st" == "200" ]]; then ok "franquia removida (200)"
  else bad "remover franquia devolveu $st"; fi
  resp=$(body GET /api/quotas "$tok")
  local aindaUsado config
  aindaUsado=$(python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['link_id']=='$link': print(q['used_bytes'])" <<<"$resp" 2>/dev/null)
  config=$(python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['link_id']=='$link': print(str(q['configured']).lower())" <<<"$resp" 2>/dev/null)
  # O `tr` não é enfeite: jqk/python imprimem "False", não "false".
  if [[ "$(tr 'A-Z' 'a-z' <<<"$config")" == "false" ]]; then ok "a franquia saiu da configuração"
  else bad "a franquia continua declarada depois do DELETE"; fi
  if [[ -n "$aindaUsado" && "$aindaUsado" -gt 0 ]]; then
    ok "o consumo medido sobreviveu à remoção da franquia"
  else bad "remover a franquia escondeu o consumo já medido — a chave do ciclo mudou debaixo da leitura"; fi
}


# ─── G. Contabilidade por host (issue #112) ──────────────────────────────────
#
# O QUE SÓ UMA MÁQUINA DE VERDADE PROVA. A contabilidade conta tráfego
# FORWARDED, e teste em Go não tem tráfego atravessando nada. Aqui a bateria
# cria um cliente numa netns atrás do firewall, gera tráfego que de fato
# atravessa, e confere o número no kernel e no painel.
#
# E confere a coisa que dá nome à issue: o consumo tem de sobreviver ao fim do
# fluxo. A fonte antiga (/proc/net/nf_conntrack) só tinha conexão viva, então o
# host que baixou 5 GB há dez minutos aparecia com zero.
battery_accounting() {
  head_ "G. Contabilidade por host"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria G não roda"; return; }

  # A bateria D pode ter deixado a forward bloqueando. Sem tráfego atravessando
  # não há o que contar, e a falha apareceria como se fosse da contabilidade.
  status PUT /api/nftables/policy "$tok" '{"policy":"accept"}' >/dev/null

  # A contabilidade deriva da lista de WANs, então precisa existir pelo menos
  # um link. Esta bateria cria o seu em vez de depender de a F ter rodado
  # antes: teste que só passa por causa da ordem das baterias é teste frágil.
  # E o auto-detect é o caminho do próprio produto — se ele parar de disparar
  # a reconciliação, esta bateria é quem descobre (foi assim que se descobriu
  # que a contabilidade só aparecia no boot seguinte).
  status POST /api/links/auto-detect "$tok" >/dev/null

  # G1 — a chain existe, no hook e na prioridade que fazem ela contar só o que
  # PASSOU pela filtragem. Prioridade errada aqui conta pacote descartado como
  # se fosse consumo.
  local chain; chain=$(vm "nft list chain inet linkguard acct 2>/dev/null" | tr -d '\r')
  if grep -q 'hook forward priority filter + 10' <<<"$chain"; then
    ok "a chain de contabilidade está depois da filtragem (priority filter + 10)"
  else bad "chain de contabilidade ausente ou na prioridade errada" "$(tr '\n' ' ' <<<"$chain")"; fi

  # G2 — escopada por interface. Sem isso, `ip saddr` do tráfego de entrada
  # criaria um elemento por endereço da internet e o set (65.535) enche.
  if grep -qE 'iifname != .* update @acct_up' <<<"$chain" && grep -qE 'oifname != .* update @acct_down' <<<"$chain"; then
    ok "as regras estão escopadas pelas interfaces WAN"
  else bad "regras de contabilidade fora do formato esperado" "$(tr '\n' ' ' <<<"$chain")"; fi

  # G3 — cliente de verdade atrás do firewall, e tráfego que atravessa.
  vm "ip netns del lgclient 2>/dev/null; ip link del veth-lgfw 2>/dev/null; true" >/dev/null 2>&1
  vm "nft flush set inet linkguard acct_up; nft flush set inet linkguard acct_down" >/dev/null 2>&1
  vm "ip netns add lgclient && \
      ip link add veth-lgfw type veth peer name veth-lgcl && \
      ip link set veth-lgcl netns lgclient && \
      ip addr add 192.168.3.1/24 dev veth-lgfw && ip link set veth-lgfw up && \
      ip netns exec lgclient ip link set lo up && \
      ip netns exec lgclient ip addr add 192.168.3.200/24 dev veth-lgcl && \
      ip netns exec lgclient ip link set veth-lgcl up && \
      ip netns exec lgclient ip route add default via 192.168.3.1" >/dev/null 2>&1
  vm "ip netns exec lgclient ping -c 10 -s 1400 -i 0.05 10.0.2.2" >/dev/null 2>&1

  # 10 pacotes de 1400 bytes de payload = 10 x 1428 no fio. Números exatos, e
  # não "maior que zero": contagem dobrada (o mesmo pacote casando as duas
  # regras) passaria despercebida por um teste frouxo.
  local up down
  up=$(vm "nft list set inet linkguard acct_up 2>/dev/null" | grep -oE '192\.168\.3\.200 counter packets [0-9]+ bytes [0-9]+' | grep -oE 'bytes [0-9]+' | grep -oE '[0-9]+')
  down=$(vm "nft list set inet linkguard acct_down 2>/dev/null" | grep -oE '192\.168\.3\.200 counter packets [0-9]+ bytes [0-9]+' | grep -oE 'bytes [0-9]+' | grep -oE '[0-9]+')
  if [[ "$up" == "14280" ]]; then ok "o que o cliente enviou foi contado exatamente (14280 bytes)"
  else bad "upload contado errado: ${up:-vazio} (esperado 14280 — dobrado seria 28560)"; fi
  if [[ "$down" == "14280" ]]; then ok "o que chegou ao cliente foi contado exatamente (14280 bytes)"
  else bad "download contado errado: ${down:-vazio} (esperado 14280)"; fi

  # G4 — o número chega ao painel, pela LAN configurada.
  local api_bytes
  api_bytes=$(body GET /api/hosts/traffic "$tok" | python3 -c "
import json,sys
for h in json.load(sys.stdin):
    if h['ip']=='192.168.3.200': print(h['rx_bytes'])" 2>/dev/null)
  if [[ "$api_bytes" == "14280" ]]; then ok "o painel devolve o mesmo número que o kernel contou"
  else bad "o painel devolveu ${api_bytes:-nada} para o host de teste"; fi

  # G5 — A ASSERÇÃO QUE DÁ NOME À ISSUE. Os fluxos ICMP envelhecem e somem do
  # conntrack; o consumo NÃO pode sumir junto.
  # A espera é MEDIDA, e o resultado dela decide se a asserção seguinte pode
  # ser cobrada. Antes eram 45 segundos cegos e, se algum fluxo tivesse
  # sobrevivido, o script imprimia uma nota dizendo "a asserção seguinte vale
  # do mesmo jeito" e seguia — mas ela NÃO vale: "o consumo sobreviveu ao fim
  # dos fluxos" com fluxo vivo afirma o que ninguém mediu. Pior, a variável
  # vinha VAZIA quando /proc/net/nf_conntrack não existe, e falha de medição
  # caía no mesmo silêncio que a condição legítima.
  printf '       (aguardando os fluxos saírem do conntrack)\n'
  local vivos="" i
  for i in $(seq 1 12); do
    sleep 10
    # `grep -c` imprime 0 E sai com código 1 quando não acha; o `|| echo 0`
    # acrescentava um segundo zero e a variável virava "0\n0".
    vivos=$(vm "test -r /proc/net/nf_conntrack && { grep -c 192.168.3.200 /proc/net/nf_conntrack; true; } || echo sem-conntrack" | tr -d '\r' | head -1)
    [[ "$vivos" == "0" ]] && break
  done
  local depois
  depois=$(vm "nft list set inet linkguard acct_up 2>/dev/null" | grep -oE '192\.168\.3\.200 counter packets [0-9]+ bytes [0-9]+' | grep -oE 'bytes [0-9]+' | grep -oE '[0-9]+')
  if [[ "$vivos" == "0" ]]; then
    ok "os fluxos do host saíram do conntrack (a fonte antiga diria zero)"
    if [[ "$depois" == "14280" ]]; then ok "o consumo sobreviveu ao fim dos fluxos — é o defeito da #112, corrigido"
    else bad "o consumo mudou depois de os fluxos morrerem: ${depois:-vazio}"; fi
  elif [[ "$vivos" == "sem-conntrack" ]]; then
    bad "não consegui ler /proc/net/nf_conntrack; a asserção da #112 não foi medida"
  else
    bad "os fluxos não saíram do conntrack em 120s ($vivos vivo(s)); a asserção da #112 não foi medida" \
        "consumo lido no acct_up: ${depois:-vazio}"
  fi

  # G6 — a SÉRIE por host (issue #113). O contador é acumulado; a série é o
  # histórico. Ela só existe depois de duas amostras (cadência de 10s), então
  # aqui o tráfego roda em segundo plano enquanto a bateria espera.
  local mac
  mac=$(vm "ip netns exec lgclient cat /sys/class/net/veth-lgcl/address" | tr -d '\r')
  vm "nohup ip netns exec lgclient ping -c 120 -i 0.25 -s 1400 10.0.2.2 >/dev/null 2>&1 &" >/dev/null 2>&1
  printf '       (30s de tráfego para a série ter mais de uma amostra)\n'
  sleep 32

  # A consulta é por MAC — a identidade do inventário. E a janela é a curta,
  # que é a que a tela abre por padrão: ela resolve para passo de 1s nas
  # interfaces, e a série por host não tem balde de 1s. Se o piso de 10s
  # regredir, é aqui que aparece.
  local pontos
  pontos=$(body GET "/api/hosts/traffic/history?mac=$mac&range=30m" "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(sum(1 for p in d.get('points',[]) if (p.get('rx_bps') or 0) > 0))" 2>/dev/null)
  if [[ -n "$pontos" && "$pontos" -gt 0 ]]; then
    ok "a série por host tem $pontos ponto(s) com consumo na janela curta"
  else bad "a série por host veio vazia para $mac (janela 30m)"; fi

  # G7 — MAC desconhecido não pode virar erro nem série inventada.
  local st_mac
  st_mac=$(status GET "/api/hosts/traffic/history?mac=nao-eh-mac&range=30m" "$tok")
  if [[ "$st_mac" == "400" ]]; then ok "MAC inválido recusado (400)"
  else bad "MAC inválido devolveu $st_mac"; fi

  vm "ip netns del lgclient 2>/dev/null; ip link del veth-lgfw 2>/dev/null; true" >/dev/null 2>&1
}

# ─── Y. Cota por aparelho (issue #126, metade "por host") ────────────────────
#
# O que só uma máquina de verdade prova aqui: o consumo sai dos contadores por
# endereço do nftables, é resolvido para MAC pela tabela de vizinhança, passa
# pelo amostrador de 10 s e só vira linha no banco no flush de um minuto. Teste
# em Go exercita a aritmética; ele não prova que o número do painel é o que o
# kernel contou.
#
# E METADE DESTA BATERIA É SILÊNCIO. A decisão de produto desta entrega é que a
# cota AVISA e não corta: sem as asserções de que o ruleset não mudou, de que
# ninguém foi bloqueado e de que não apareceu qdisc nenhuma, as asserções
# positivas não significam nada — elas passariam igual numa versão que trancou
# o aparelho do admin.
battery_host_quota() {
  head_ "Y. Cota por aparelho"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d "\\r\\n")
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  # PULAR, e não só FALHAR: sem isto o resumo conta cobertura que não houve.
  # As asserções de silêncio desta bateria são a única prova executável de que
  # a cota não tranca ninguém — dizer em voz alta que elas não rodaram é a
  # diferença entre nada quebrou e ninguém olhou.
  [[ -n "$tok" ]] || { pular "Y. Cota por aparelho" "sem sessão administrativa"; return; }

  # Sem tráfego atravessando não há o que contar, e a falha apareceria como se
  # fosse da cota. Mesma precaução da bateria G.
  status PUT /api/nftables/policy "$tok" '{"policy":"accept"}' >/dev/null
  status POST /api/links/auto-detect "$tok" >/dev/null

  # Cliente de verdade atrás do firewall: a cota é medida no FORWARD, e ping
  # para a própria caixa não atravessa nada.
  vm "ip netns del lgclient 2>/dev/null; ip link del veth-lgfw 2>/dev/null; true" >/dev/null 2>&1
  vm "nft flush set inet linkguard acct_up; nft flush set inet linkguard acct_down" >/dev/null 2>&1
  vm "ip netns add lgclient && \
      ip link add veth-lgfw type veth peer name veth-lgcl && \
      ip link set veth-lgcl netns lgclient && \
      ip addr add 192.168.3.1/24 dev veth-lgfw && ip link set veth-lgfw up && \
      ip netns exec lgclient ip link set lo up && \
      ip netns exec lgclient ip addr add 192.168.3.200/24 dev veth-lgcl && \
      ip netns exec lgclient ip link set veth-lgcl up && \
      ip netns exec lgclient ip route add default via 192.168.3.1" >/dev/null 2>&1
  # Um pacote para o firewall aprender o MAC do cliente: sem vizinhança
  # resolvida o amostrador não tem como atribuir os bytes a um aparelho.
  vm "ip netns exec lgclient ping -c 2 192.168.3.1" >/dev/null 2>&1
  local mac
  mac=$(vm "ip netns exec lgclient cat /sys/class/net/veth-lgcl/address" | tr -d "\\r")
  [[ -n "$mac" ]] || { bad "não consegui descobrir o endereço físico do cliente de teste"; return; }
  if vm "ip neigh" | grep -qi "$mac"; then ok "o firewall enxerga o endereço físico do cliente ($mac)"
  else bad "o cliente de teste não apareceu na tabela de vizinhança; a cota não teria como nomeá-lo"; fi

  local resp st

  # Y1 — todo aparelho do inventário aparece, com ou sem cota declarada. Um
  # aparelho ausente da lista é um aparelho que ninguém consegue proteger.
  #
  # O AVISTAMENTO É GRAVADO PELO CAMINHO DO PRODUTO, e a bateria tem de percorrê-lo.
  #
  # Snapshot() lista quem está no INVENTÁRIO (host_metadata), e quem popula o
  # inventário é o handler de GET /api/hosts, ao ver o aparelho na vizinhança.
  # Estar no `ip neigh` do kernel não basta: é o produto que decide o que entra
  # no inventário dele. A primeira versão desta asserção olhava a vizinhança e
  # pulava esse passo — cobrava do produto uma lista que ninguém tinha mandado
  # ele montar. A bateria V já tinha aprendido isso e documentado lá.
  #
  # A espera continua porque o upsert é best-effort dentro do handler, mas agora
  # ela espera algo que foi PEDIDO, em vez de torcer.
  body GET /api/hosts "$tok" >/dev/null 2>&1
  sleep 2
  body GET /api/hosts "$tok" >/dev/null 2>&1
  local i
  for i in $(seq 1 12); do
    resp=$(body GET /api/hosts/quotas "$tok")
    grep -qi "$mac" <<<"$resp" && break
    sleep 5
  done
  if grep -qi "$mac" <<<"$resp"; then ok "o aparelho aparece na lista de cotas"
  else bad "o aparelho não veio em /api/hosts/quotas em 60s, mesmo depois de o inventário ser consultado" "$(head -c 200 <<<"$resp")"; fi

  # Y2 — o que não existe é recusado na entrada, e não gravado para falhar
  # depois em silêncio.
  st=$(status PUT "/api/hosts/quotas/$mac" "$tok" '{"limit_gb":1,"period":"monthly","cycle_day":31,"alert_pct":80}')
  if [[ "$st" == "400" ]]; then ok "dia de fechamento 31 recusado (400)"
  else bad "dia 31 aceito ($st) — o ciclo sumiria em fevereiro"; fi
  st=$(status PUT "/api/hosts/quotas/$mac" "$tok" '{"limit_gb":1,"period":"monthly","cycle_day":10,"alert_pct":150}')
  if [[ "$st" == "400" ]]; then ok "aviso em 150% recusado (400)"
  else bad "percentual fora da faixa aceito ($st)"; fi
  st=$(status PUT "/api/hosts/quotas/$mac" "$tok" '{"limit_gb":1,"period":"semanal","cycle_day":1,"alert_pct":80}')
  if [[ "$st" == "400" ]]; then ok "período inventado recusado (400)"
  else bad "período semanal aceito ($st)"; fi
  st=$(status PUT "/api/hosts/quotas/nao-eh-mac" "$tok" '{"limit_gb":1,"period":"monthly","cycle_day":1,"alert_pct":80}')
  if [[ "$st" == "400" ]]; then ok "endereço físico malformado recusado (400)"
  else bad "MAC malformado aceito ($st) — a cota nasceria numa chave que nunca casa"; fi

  # ─── o ruleset ANTES. Tudo o que vier depois é comparado com esta foto. ───
  # Os contadores e prazos dos sets mudam sozinhos: normalizar é o que faz o
  # diff falar de REGRA, e não de tráfego.
  vm "nft list ruleset | grep -E '^[[:space:]]*(table|chain|type|policy|set|map|flags|timeout|size|counter|ip|ip6|meta|ct|tcp|udp|icmp|iifname|oifname|jump|goto|accept|drop|reject|return|log|limit|masquerade|snat|dnat|redirect|update|ether|th)[[:space:]]' | grep -vE '^[[:space:]]*elements' | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter N/g' > /tmp/rs-antes.txt" >/dev/null 2>&1
  vm "tc qdisc show > /tmp/tc-antes.txt" >/dev/null 2>&1

  # Y3 — cota diária: o ciclo dura exatamente um dia. Se o dia de fechamento
  # vazasse para o diário, o ciclo duraria um mês e a cota "de hoje" mentiria.
  st=$(status PUT "/api/hosts/quotas/$mac" "$tok" '{"limit_gb":0.001,"period":"daily","cycle_day":1,"alert_pct":80}')
  if [[ "$st" == "200" ]]; then ok "cota diária de 1 MB declarada (200)"
  else bad "declarar cota diária devolveu $st"; fi
  local ini fim
  resp=$(body GET /api/hosts/quotas "$tok")
  ini=$(python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['mac'].lower()=='$mac'.lower(): print(q['cycle_start'])" <<<"$resp" 2>/dev/null)
  fim=$(python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['mac'].lower()=='$mac'.lower(): print(q['cycle_end'])" <<<"$resp" 2>/dev/null)
  if [[ -n "$ini" && -n "$fim" && $(( fim - ini )) -eq 86400 ]]; then
    ok "o ciclo diário dura exatamente 24 horas"
  else bad "ciclo diário inválido: início=$ini fim=$fim"; fi

  # Y4 — A CADEIA INTEIRA. Sem esta, tudo o mais é aritmética em Go.
  # ~2 MB atravessando o firewall: 1400 pacotes de 1400 bytes.
  vm "ip netns exec lgclient ping -c 1400 -s 1400 -i 0.01 10.0.2.2" >/dev/null 2>&1
  local kernel_bytes
  kernel_bytes=$(vm "nft list set inet linkguard acct_up 2>/dev/null" | grep -oE "192\\.168\\.3\\.200 counter packets [0-9]+ bytes [0-9]+" | grep -oE "bytes [0-9]+" | grep -oE "[0-9]+")
  if [[ -n "$kernel_bytes" && "$kernel_bytes" -gt 0 ]]; then
    ok "o kernel contou $kernel_bytes bytes do cliente"
  else bad "o contador do kernel ficou vazio; a cota não teria de onde ler"; fi

  printf "       (aguardando o flush de 1 minuto do acumulador)\\n"
  sleep 70
  local usado
  usado=$(body GET /api/hosts/quotas "$tok" | python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['mac'].lower()=='$mac'.lower(): print(q['used_bytes'])" 2>/dev/null)
  if [[ -n "$usado" && "$usado" -gt 0 ]]; then
    ok "o consumo medido chegou ao painel para o aparelho ($usado bytes)"
  else bad "o consumo do aparelho continuou zerado depois do flush — a cadeia de medição não fechou"; fi

  # Y5 — o número BATE com o kernel, com folga declarada. Não é rigor de
  # contador: é a prova de que ninguém está integrando host.rx_bps, que erraria
  # por ordens de grandeza e não por 10%.
  if [[ -n "$usado" && -n "$kernel_bytes" && "$kernel_bytes" -gt 0 ]]; then
    local piso teto
    piso=$(( kernel_bytes / 2 ))
    teto=$(( kernel_bytes * 3 ))
    if [[ "$usado" -ge "$piso" && "$usado" -le "$teto" ]]; then
      ok "o consumo do painel tem a mesma ordem de grandeza do contador do kernel"
    else bad "o painel diz $usado e o kernel contou $kernel_bytes — alguém está integrando taxa em vez de somar bytes"; fi
  fi

  # Y6 — o alerta nasce, com número LEGÍVEL. Cota de 1 MB com 2 MB gastos: é
  # exatamente o caso em que "%.1f GB" produzia "0.0 GB de 0 GB".
  local alertas
  alertas=$(body GET "/api/alerts?limit=50" "$tok")
  if grep -q "host_quota_exceeded" <<<"$alertas"; then ok "o alerta de cota estourada existe"
  else bad "a cota de 1 MB foi estourada e nenhum alerta apareceu"; fi
  if grep -q "0.0 GB" <<<"$alertas"; then
    bad "o alerta saiu ilegível (contém \\"0.0 GB\\") — é o defeito que a metade de link já pagou"
  else ok "o texto do alerta usa unidade compatível com a grandeza"; fi

  # ─── ASSERÇÕES DE SILÊNCIO. Sem estas, Y4 e Y6 não significam nada. ───

  # S1 — o ruleset não mudou de FORMA. Nenhuma regra nova, nenhuma chain nova,
  # nenhum limit rate, nenhum drop. Declarar cota e estourá-la não toca no
  # firewall.
  #
  # A COMPARAÇÃO MANTÉM SÓ O QUE É FORMA, EM VEZ DE APAGAR O QUE NÃO É.
  #
  # A primeira tentativa apagava o bloco de elementos por intervalo, e o
  # intervalo comeu a chave de fechamento do set num lado só — o "antes" não
  # tinha elementos, o "depois" tinha, e o diff acusou um `}` de diferença.
  # Diff de texto de ruleset é frágil assim: qualquer regra de exclusão erra
  # quando os dois lados têm formas diferentes.
  #
  # Manter só as linhas que SÃO forma (tabela, chain, tipo, política,
  # declaração de set, regra) responde a pergunta certa e não depende de os dois
  # lados terem o mesmo formato. Conferido contra a caixa de produção: 86 linhas
  # de forma, zero elementos sobrando.
  #
  # A COMPARAÇÃO IGNORA OS ELEMENTOS DOS SETS, E TEM DE IGNORAR. A primeira
  # versão comparava o ruleset inteiro e acusava a cota disto:
  #
  #   48a49 > elements = { 192.168.3.200 counter N expires N58m... }
  #
  # Aquele elemento é a CONTABILIDADE ganhando uma linha porque esta mesma
  # bateria gerou tráfego daquele endereço — o comportamento normal que
  # ALIMENTA a cota. A bateria acusava a si mesma, e acusava a cota do crime
  # que ela existe para não cometer, com a prova errada na mão.
  #
  # O que se mede aqui é forma: chain, regra, veredito. Elemento de set
  # dinâmico é medição, muda a cada pacote, e não pertence a esta pergunta.
  # Quem cobra que a contabilidade não vire bloqueio são as asserções logo
  # abaixo, que olham a chain e o inventário.
  vm "nft list ruleset | grep -E '^[[:space:]]*(table|chain|type|policy|set|map|flags|timeout|size|counter|ip|ip6|meta|ct|tcp|udp|icmp|iifname|oifname|jump|goto|accept|drop|reject|return|log|limit|masquerade|snat|dnat|redirect|update|ether|th)[[:space:]]' | grep -vE '^[[:space:]]*elements' | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter N/g' > /tmp/rs-depois.txt" >/dev/null 2>&1
  local rsdiff
  rsdiff=$(vm "diff /tmp/rs-antes.txt /tmp/rs-depois.txt | head -40" | tr -d "\\r")
  if [[ -z "$rsdiff" ]]; then ok "nenhuma regra, chain ou veredito novo depois de declarar e estourar a cota"
  else bad "a cota mexeu na FORMA do ruleset" "$(tr "\\n" " " <<<"$rsdiff")"; fi

  # S2 — ninguém foi bloqueado. Estourar cota NÃO pode trancar aparelho: o que
  # estourou pode ser o do próprio admin.
  local bh bm
  bh=$(vm "nft list set inet linkguard blocked_hosts 2>/dev/null" | grep -oE "elements = \\{[^}]*\\}" | tr -d "\\r")
  bm=$(vm "nft list set inet linkguard blocked_mac 2>/dev/null" | grep -oE "elements = \\{[^}]*\\}" | tr -d "\\r")
  if [[ -z "$bh" && -z "$bm" ]]; then ok "nenhum aparelho foi bloqueado pelo estouro da cota"
  else bad "a cota bloqueou alguém — é a tranca que esta entrega existe para NÃO fazer" "hosts=$bh mac=$bm"; fi
  local bloqueado
  bloqueado=$(body GET /api/hosts "$tok" | python3 -c "
import json,sys
for h in json.load(sys.stdin):
    if (h.get('mac') or '').lower()=='$mac'.lower(): print(str(h['blocked']).lower())" 2>/dev/null)
  if [[ "$bloqueado" != "true" ]]; then ok "o aparelho que estourou continua liberado no inventário"
  else bad "o aparelho que estourou a cota aparece bloqueado"; fi

  # S3 — nada de tc. Se aparecer cake ou htb, alguém entregou a #121 por
  # acidente — e limitação de banda não estava nesta entrega.
  vm "tc qdisc show > /tmp/tc-depois.txt" >/dev/null 2>&1
  local tcdiff
  tcdiff=$(vm "diff /tmp/tc-antes.txt /tmp/tc-depois.txt | head -20" | tr -d "\\r")
  if [[ -z "$tcdiff" ]]; then ok "nenhuma qdisc nova apareceu"
  else bad "a cota mexeu na disciplina de fila" "$(tr "\\n" " " <<<"$tcdiff")"; fi

  # S4 — a contabilidade não foi contaminada: nenhum endereço fora da LAN no
  # acct_up. Um endereço público ali é o set caminhando para o teto de 65.535.
  local forasteiros
  forasteiros=$(vm "nft list set inet linkguard acct_up 2>/dev/null" | grep -oE "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" | grep -vcE "^(192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)" || true)
  if [[ "${forasteiros:-0}" == "0" ]]; then ok "o set de contabilidade só tem endereços da LAN"
  else bad "$forasteiros endereço(s) fora da LAN no acct_up — o set vai encher"; fi

  # S5 — a chain de contabilidade continua idêntica: duas regras, nem uma a
  # mais. Acrescentar regra ali derruba a medição de todo mundo em silêncio.
  local nregras
  nregras=$(vm "nft list chain inet linkguard acct 2>/dev/null" | grep -cE "update @acct_(up|down)")
  if [[ "$nregras" == "2" ]]; then ok "a chain de contabilidade continua com as duas regras de sempre"
  else bad "a chain acct tem $nregras regra(s) de update — a cota não pode escrever ali"; fi


  # Y10 — TROCAR O PERÍODO NÃO PODE ESCONDER O CONSUMO. É o mesmo defeito de
  # 2026-08-20 que a Y7 protege no DELETE, entrando pela porta do PUT: mexer em
  # período ou dia de fechamento move a chave (aparelho, período, início do
  # ciclo), e sem migrar o consumo junto a barra volta a 0% com o alerta ainda
  # aberto no painel.
  status PUT "/api/hosts/quotas/$mac" "$tok" '{"limit_gb":0.001,"period":"daily","cycle_day":1,"alert_pct":80}' >/dev/null
  local antesDaTroca depoisDaTroca
  antesDaTroca=$(body GET /api/hosts/quotas "$tok" | python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['mac'].lower()=='$mac'.lower(): print(q['used_bytes'])" 2>/dev/null)
  status PUT "/api/hosts/quotas/$mac" "$tok" '{"limit_gb":0.001,"period":"monthly","cycle_day":15,"alert_pct":80}' >/dev/null
  depoisDaTroca=$(body GET /api/hosts/quotas "$tok" | python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['mac'].lower()=='$mac'.lower(): print(q['used_bytes'])" 2>/dev/null)
  if [[ -n "$antesDaTroca" && "$antesDaTroca" -gt 0 && "$depoisDaTroca" == "$antesDaTroca" ]]; then
    ok "trocar o período levou o consumo já medido junto ($depoisDaTroca bytes)"
  else bad "o consumo caiu de ${antesDaTroca:-?} para ${depoisDaTroca:-?} ao trocar o período — a chave do ciclo mudou debaixo da leitura"; fi
  # E volta para o diário, que é o estado que a Y7 espera logo abaixo.
  status PUT "/api/hosts/quotas/$mac" "$tok" '{"limit_gb":0.001,"period":"daily","cycle_day":1,"alert_pct":80}' >/dev/null
  # Y7 — remover a cota NÃO pode esconder o consumo já medido. É o defeito de
  # 2026-08-20, agora na chave (aparelho, início do ciclo).
  st=$(status DELETE "/api/hosts/quotas/$mac" "$tok")
  if [[ "$st" == "200" ]]; then ok "cota removida (200)"
  else bad "remover a cota devolveu $st"; fi
  resp=$(body GET /api/hosts/quotas "$tok")
  local aindaUsado config
  aindaUsado=$(python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['mac'].lower()=='$mac'.lower(): print(q['used_bytes'])" <<<"$resp" 2>/dev/null)
  config=$(python3 -c "
import json,sys
for q in json.load(sys.stdin):
    if q['mac'].lower()=='$mac'.lower(): print(str(q['configured']).lower())" <<<"$resp" 2>/dev/null)
  if [[ "$config" == "false" ]]; then ok "a cota saiu da configuração"
  else bad "a cota continua declarada depois do DELETE"; fi
  if [[ -n "$aindaUsado" && "$aindaUsado" -gt 0 ]]; then
    ok "o consumo medido sobreviveu à remoção da cota ($aindaUsado bytes)"
  else bad "remover a cota escondeu o consumo já medido — a chave do ciclo mudou debaixo da leitura"; fi

  # Y8 — o aparelho SEM cota declarada continua sendo medido. É o que permite
  # ao admin descobrir ONDE declarar um teto.
  if [[ -n "$aindaUsado" && "$aindaUsado" -gt 0 && "$config" == "false" ]]; then
    ok "aparelho sem cota declarada continua medido"
  fi

  # Y9 — auditoria. Declarar e remover cota são atos administrativos sobre um
  # aparelho: sem rastro de quem fez, a feature não deveria existir.
  local logs; logs=$(body GET "/api/logs?limit=60" "$tok")
  if grep -q "host_quota" <<<"$logs"; then ok "as mudanças de cota foram para a auditoria"
  else bad "cota alterada sem registro de auditoria"; fi

  # ─── S6/S7. A OUTRA metade do silêncio: a superfície de EXPOSIÇÃO. ─────────
  #
  # S1-S5 provam que o FIREWALL ficou calado. Nenhuma delas toca em quem
  # consegue LER o que a cota mede — e o que ela mede é "o aparelho X consumiu N
  # bytes neste mês", que é histórico de comportamento, não evento.

  # S6 — as quatro rotas novas estão DENTRO do grupo autenticado. Sem token,
  # 401. Um /api/hosts/quotas aberto publicaria o inventário da rede do cliente
  # com o consumo de cada aparelho, sem senha.
  local semtok
  for rota in "GET /api/hosts/quotas" "GET /api/hosts/quotas/$mac/history" "PUT /api/hosts/quotas/$mac" "DELETE /api/hosts/quotas/$mac"; do
    semtok=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -X "${rota%% *}" "$API${rota##* }" 2>/dev/null)
    if [[ "$semtok" == "401" ]]; then ok "sem token, $rota devolve 401"
    else bad "$rota respondeu $semtok sem autenticação — inventário da LAN sem senha"; fi
  done

  # S7 — nada de identidade de aparelho no /metrics, que é ABERTO e que a
  # própria suíte exige que responda pela WAN. A regra está escrita em
  # internal/metrics/exposicao.go; aqui ela é medida na caixa.
  local metricas
  metricas=$(curl -s --max-time 6 "$API/metrics" 2>/dev/null)
  if [[ -z "$metricas" ]]; then
    bad "o /metrics não respondeu — a asserção de exposição não mediu nada"
  else
    if grep -qiF "$mac" <<<"$metricas"; then
      bad "o endereço físico do aparelho aparece no /metrics, que é aberto"
    else ok "o /metrics não publica o endereço físico do aparelho"; fi
    if grep -qE '^linkguard_(host|hostquota|cota|device|client)_' <<<"$metricas"; then
      bad "há série de identidade de aparelho no /metrics aberto" "$(grep -oE '^linkguard_(host|hostquota|cota|device|client)_[a-z_]+' <<<"$metricas" | sort -u | tr '\n' ' ')"
    else ok "nenhuma série por aparelho no /metrics aberto"; fi
  fi

  # S8 — o aviso não atravessou a fronteira da caixa. notificar_aparelho é
  # falso por padrão, e nenhum canal está configurado nesta VM: se algo tivesse
  # saído, teria falhado no envio e deixado rastro.
  local envio
  envio=$(vm "journalctl -u linkguard-fw --since '-5 min' --no-pager 2>/dev/null | grep -ci 'notify' || true" | tr -d "\\r")
  if [[ "${envio:-0}" == "0" ]]; then ok "o alerta de cota não tentou sair da caixa"
  else bad "houve $envio linha(s) de notificação com o portão de identidade fechado"; fi

  vm "ip netns del lgclient 2>/dev/null; ip link del veth-lgfw 2>/dev/null; true" >/dev/null 2>&1
}


# ─── H. Roteamento de retorno por WAN (issue #120) ───────────────────────────
#
# O DEFEITO QUE ESTA BATERIA REPRODUZ. Numa caixa com mais de uma WAN, o que
# ENTRA por uma delas responde pela rota default — multipath em modo
# balanceado, link principal em failover. Quando a resposta sai pela WAN
# errada, leva o endereço de origem da outra e o provedor descarta. Do lado de
# fora parece porta fechada.
#
# COMO ELA REPRODUZ ISSO SEM UMA SEGUNDA OPERADORA. Cria uma WAN simulada com
# veth + netns e coloca o "cliente remoto" ATRÁS dela, num endereço que não
# está na sub-rede do enlace. Assim a resposta precisa mesmo escolher entre dois
# defaults — que é a única condição em que o defeito aparece.
#
# E ELA FAZ O TESTE A/B. Depois de provar que responde, esvazia as chains e
# prova que PARA de responder. Sem essa metade, a asserção passaria mesmo se a
# feature não fizesse nada (o caminho poderia estar funcionando por outro
# motivo), e ninguém saberia.
battery_replyrouting() {
  head_ "H. Roteamento de retorno por WAN"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria H não roda"; return; }

  # WAN simulada com um cliente atrás dela.
  vm "ip netns del wan2sim 2>/dev/null; ip link del lg-wan2 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add wan2sim && \
      ip link add lg-wan2 type veth peer name wan2-far && \
      ip link set wan2-far netns wan2sim && \
      ip addr add 10.66.0.1/24 dev lg-wan2 && ip link set lg-wan2 up && \
      ip netns exec wan2sim ip link set lo up && \
      ip netns exec wan2sim ip addr add 10.66.0.2/24 dev wan2-far && \
      ip netns exec wan2sim ip link set wan2-far up && \
      ip netns exec wan2sim ip addr add 203.0.113.5/32 dev lo && \
      ip netns exec wan2sim ip route add 10.66.0.1 dev wan2-far" >/dev/null 2>&1

  # Cadastrar a WAN pelo painel é o caminho do produto — e é o que dispara a
  # reconciliação. Se ela parar de disparar na criação de link, é aqui que
  # aparece.
  local st
  st=$(status POST /api/links "$tok" '{"name":"WAN2 simulada","interface":"lg-wan2","gateway":"10.66.0.2","ip_address":"10.66.0.1","weight":1,"enabled":true,"monitor_hosts":"10.66.0.2","dns_test":"10.66.0.2"}')
  if [[ "$st" == "200" || "$st" == "201" ]]; then ok "WAN simulada cadastrada pelo painel ($st)"
  else bad "não consegui cadastrar a WAN simulada: $st"; return; fi

  local tabela
  tabela=$(body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l['interface']=='lg-wan2': print(l['table_id'])" 2>/dev/null)
  [[ -n "$tabela" ]] || { bad "a WAN simulada não recebeu tabela de rota"; return; }

  # H1 — as duas chains, e o TIPO da de saída. `type filter` no hook output
  # escreveria a marca sem o kernel refazer a rota: pareceria configurado e não
  # faria nada.
  local pre out
  pre=$(vm "nft list chain inet linkguard conn_mark 2>/dev/null" | tr -d '\r')
  out=$(vm "nft list chain inet linkguard output_mark 2>/dev/null" | tr -d '\r')
  if grep -q 'hook prerouting priority mangle + 10' <<<"$pre"; then
    ok "a chain de marcação está no prerouting, depois da mark_hosts"
  else bad "chain conn_mark ausente ou na prioridade errada" "$(tr '\n' ' ' <<<"$pre")"; fi
  if grep -q 'type route hook output' <<<"$out"; then
    ok "a chain de saída é do tipo route (o kernel refaz a rota)"
  else bad "chain output_mark não é type route — a marca seria escrita e ignorada" "$(tr '\n' ' ' <<<"$out")"; fi

  # H2 — memória por WAN, e a restauração por último.
  if grep -q 'iifname "lg-wan2" ct state new' <<<"$pre"; then
    ok "a WAN nova ganhou regra de memória"
  else bad "sem regra de memória para lg-wan2" "$(tr '\n' ' ' <<<"$pre")"; fi
  local ultima
  ultima=$(grep -E 'ct mark|iifname' <<<"$pre" | tail -1)
  if grep -q 'meta mark set ct mark' <<<"$ultima"; then
    ok "a restauração é a última regra da chain"
  else bad "a restauração não é a última: $(echo "$ultima" | tr -s ' ')"; fi

  # H3/H4 — a metade de roteamento: regra e tabela.
  if vm "ip rule show" | grep -q "lookup $tabela"; then
    ok "existe ip rule apontando a marca para a tabela do link"
  else bad "nenhuma ip rule para a tabela $tabela"; fi
  if vm "ip route show table $tabela" | grep -q 'default via 10.66.0.2'; then
    ok "a tabela do link tem o default dele"
  else bad "tabela $tabela sem default" "$(vm "ip route show table $tabela" | tr '\n' ' ')"; fi

  # H5 — o teste que importa: cliente ATRÁS da WAN secundária é respondido.
  if vm "ip netns exec wan2sim ping -c 3 -W 2 -I 203.0.113.5 10.66.0.1 >/dev/null 2>&1 && echo ok" | grep -q ok; then
    ok "o cliente atrás da WAN secundária recebe resposta"
  else bad "sem resposta para o cliente atrás da WAN secundária — é o defeito da #120"; fi

  # H6 — A OUTRA METADE DO A/B. Sem as chains, tem de PARAR de responder. Se
  # continuar respondendo, o teste acima não estava testando nada.
  vm "nft flush chain inet linkguard conn_mark; nft flush chain inet linkguard output_mark; conntrack -F 2>/dev/null; true" >/dev/null 2>&1
  if vm "ip netns exec wan2sim ping -c 2 -W 2 -I 203.0.113.5 10.66.0.1 >/dev/null 2>&1 && echo ok" | grep -q ok; then
    bad "respondeu mesmo SEM a marcação — a asserção anterior não prova nada"
  else ok "sem a marcação o cliente fica sem resposta (o defeito, reproduzido)"; fi

  # H7 — e a reconciliação devolve.
  vm "systemctl restart linkguard-fw" >/dev/null 2>&1
  sleep 8
  if vm "ip netns exec wan2sim ping -c 3 -W 2 -I 203.0.113.5 10.66.0.1 >/dev/null 2>&1 && echo ok" | grep -q ok; then
    ok "a reconciliação do boot devolve o caminho de volta"
  else bad "depois do restart o caminho de volta não voltou"; fi

  vm "ip netns del wan2sim 2>/dev/null; ip link del lg-wan2 2>/dev/null; true" >/dev/null 2>&1
}


# ─── I. Fuga de DNS (issue #124) ─────────────────────────────────────────────
#
# O QUE SÓ UMA MÁQUINA PROVA. As duas medidas são comportamento de rede: uma
# captura a consulta de quem não quer usar o resolver local, a outra recusa um
# transporte alternativo. Nenhuma das duas se prova lendo texto de regra — a
# pergunta é o que acontece com o pacote.
#
# A bateria cria um cliente atrás da interface de LAN configurada e mede: a
# consulta para 8.8.8.8 é capturada? A conexão para a 853 é recusada NA HORA
# (RST) ou fica pendurada? A diferença entre recusar e descartar é a diferença
# entre "cai de volta em DNS comum na hora" e "o usuário acha que a internet
# está lenta".
battery_dnsleak() {
  head_ "I. Fuga de DNS"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria I não roda"; return; }

  # A configuração padrão serve a LAN em br10; a VM não tem essa interface,
  # então a bateria cria uma com o mesmo nome e pendura o cliente nela. Assim o
  # teste exercita a configuração REAL do produto, sem inventar caminho.
  vm "ip netns del lgdns 2>/dev/null; ip link del br10 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add lgdns && \
      ip link add br10 type veth peer name br10-cl && \
      ip link set br10-cl netns lgdns && \
      ip addr add 192.168.3.3/24 dev br10 && ip link set br10 up && \
      ip netns exec lgdns ip link set lo up && \
      ip netns exec lgdns ip addr add 192.168.3.77/24 dev br10-cl && \
      ip netns exec lgdns ip link set br10-cl up && \
      ip netns exec lgdns ip route add default via 192.168.3.3" >/dev/null 2>&1

  local st
  # I1 — desligado é o padrão, e desligado tem de significar chain vazia.
  st=$(status PUT /api/dns/config "$tok" '{"upstreams":[],"log_queries":false,"force_local_dns":false,"block_dot":false}')
  [[ "$st" == "200" ]] || { bad "não consegui salvar a configuração de DNS: $st"; return; }
  sleep 3
  local redir
  redir=$(vm "nft list chain inet linkguard dns_redirect 2>/dev/null" | grep -c 'dport 53' || true)
  if [[ "${redir:-0}" == "0" ]]; then ok "com o controle desligado, nenhuma consulta é capturada"
  else bad "há $redir regra(s) de captura com o controle desligado"; fi

  # I2 — ligar as duas medidas.
  st=$(status PUT /api/dns/config "$tok" '{"upstreams":[],"log_queries":false,"force_local_dns":true,"block_dot":true,"dns_except_ips":["192.168.3.99"]}')
  [[ "$st" == "200" ]] || { bad "não consegui ligar o controle: $st"; return; }
  sleep 3

  local chain
  chain=$(vm "nft list chain inet linkguard dns_redirect 2>/dev/null" | tr -d '\r')
  if grep -q 'udp dport 53' <<<"$chain" && grep -q 'tcp dport 53' <<<"$chain"; then
    ok "a captura cobre UDP e TCP"
  else bad "captura incompleta" "$(tr '\n' ' ' <<<"$chain")"; fi
  if grep -q '192.168.3.99' <<<"$chain"; then ok "o aparelho isento entrou na regra"
  else bad "a exceção não chegou ao firewall" "$(tr '\n' ' ' <<<"$chain")"; fi

  # I3 — COMPORTAMENTO: a consulta para um resolver externo é capturada. O
  # contador da regra é a prova de que o pacote passou por ela.
  vm "nft flush chain inet linkguard dns_redirect >/dev/null 2>&1; true" >/dev/null 2>&1
  # (o flush acima zera contadores; a reconciliação seguinte reescreve as regras)
  status PUT /api/dns/config "$tok" '{"upstreams":[],"log_queries":false,"force_local_dns":true,"block_dot":true}' >/dev/null
  sleep 3
  vm "ip netns exec lgdns timeout 3 python3 -c \"
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
try:
    s.sendto(b'\\x00\\x00\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01', ('8.8.8.8', 53))
    s.recvfrom(512)
except Exception: pass
\"" >/dev/null 2>&1
  local capturados
  capturados=$(vm "nft list chain inet linkguard dns_redirect 2>/dev/null" | grep -oE 'counter packets [0-9]+' | grep -oE '[0-9]+' | head -1)
  if [[ -n "$capturados" && "$capturados" -gt 0 ]]; then
    ok "consulta enviada a 8.8.8.8 foi capturada pelo firewall ($capturados pacote(s))"
  else bad "a consulta para o resolver externo NÃO foi capturada"; fi

  # I4 — COMPORTAMENTO: DoT é recusado na hora, e não descartado. A diferença
  # aparece no erro: recusa dá ConnectionRefused imediato; descarte dá timeout.
  local dot
  dot=$(vm "ip netns exec lgdns timeout 6 python3 -c \"
import socket, time
s=socket.socket(); s.settimeout(4)
t0=time.time()
try:
    s.connect(('1.1.1.1', 853)); print('CONECTOU')
except ConnectionRefusedError: print('RECUSADO', round(time.time()-t0,1))
except Exception as e: print(type(e).__name__, round(time.time()-t0,1))
\"" | tr -d '\r')
  if grep -q 'RECUSADO' <<<"$dot"; then ok "DoT recusado imediatamente (RST): $dot"
  elif grep -q 'CONECTOU' <<<"$dot"; then bad "a conexão DoT passou: $dot"
  else bad "DoT não foi recusado com RST — o cliente fica pendurado até o timeout: $dot"; fi

  # I5 — desligar tem de desligar de verdade.
  status PUT /api/dns/config "$tok" '{"upstreams":[],"log_queries":false,"force_local_dns":false,"block_dot":false}' >/dev/null
  sleep 3
  local sobrou
  sobrou=$(vm "nft list chain inet linkguard dns_redirect 2>/dev/null; nft list chain inet linkguard dns_guard 2>/dev/null" | grep -cE 'dport 53|dport 853' || true)
  if [[ "${sobrou:-0}" == "0" ]]; then ok "desligar no painel removeu as regras"
  else bad "sobraram $sobrou regra(s) depois de desligar"; fi

  vm "ip netns del lgdns 2>/dev/null; ip link del br10 2>/dev/null; true" >/dev/null 2>&1
}


# ─── J. Ajuste de MSS (issue #130) ───────────────────────────────────────────
#
# POR QUE ISTO PRECISA DE UMA MÁQUINA. A regra usa `rt mtu`: ela não carrega
# número, pega a MTU da rota no momento do pacote. Ler o texto da regra não diz
# nada sobre o valor que chega no fio — e o valor é a feature inteira.
#
# A bateria baixa a MTU da WAN para 1400, faz um cliente da LAN abrir uma
# conexão que atravessa o firewall, e LÊ O MSS do SYN que sai. Com o ajuste, tem
# de ser 1360 (1400 - 20 de IP - 20 de TCP). Sem ele, seria 1460 — o valor que
# o cliente anunciou achando que cabia, e que é a origem do sintoma da issue.
battery_mssclamp() {
  head_ "J. Ajuste de MSS"

  local chain
  chain=$(vm "nft list chain inet linkguard mss_clamp 2>/dev/null" | tr -d '\r')
  if grep -q 'maxseg size set rt mtu' <<<"$chain"; then
    ok "o ajuste usa a MTU da rota, sem número cravado"
  else bad "chain de ajuste de MSS ausente ou com valor fixo" "$(tr '\n' ' ' <<<"$chain")"; fi
  if grep -q 'priority mangle' <<<"$chain"; then
    ok "o ajuste roda antes da filtragem"
  else bad "prioridade inesperada" "$(tr '\n' ' ' <<<"$chain")"; fi

  # Cliente atrás do firewall e MTU reduzida na saída.
  vm "ip netns del lgmss 2>/dev/null; ip link del veth-mss 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add lgmss && \
      ip link add veth-mss type veth peer name veth-mss-cl && \
      ip link set veth-mss-cl netns lgmss && \
      ip addr add 192.168.44.1/24 dev veth-mss && ip link set veth-mss up && \
      ip netns exec lgmss ip link set lo up && \
      ip netns exec lgmss ip addr add 192.168.44.2/24 dev veth-mss-cl && \
      ip netns exec lgmss ip link set veth-mss-cl up && \
      ip netns exec lgmss ip route add default via 192.168.44.1" >/dev/null 2>&1
  vm "ip link set enp0s2 mtu 1400" >/dev/null 2>&1

  # Captura o SYN que sai pela WAN. O destino não precisa responder: o ajuste
  # acontece na saída, e é o SYN que carrega o MSS.
  # O filtro é pelo DESTINO, e não pela origem: quando o pacote sai pela WAN o
  # masquerade já trocou o endereço de origem, e a primeira versão desta
  # asserção capturava zero pacote por causa disso. E o destino é o gateway do
  # enlace, que existe: para um endereço inexistente o ARP falha e o SYN nunca
  # chega ao fio.
  vm "nohup timeout 12 tcpdump -i enp0s2 -nn -c 1 -v 'tcp[tcpflags] & tcp-syn != 0 and dst host 10.0.2.2' > /tmp/mss.txt 2>&1 &" >/dev/null 2>&1
  sleep 2
  vm "ip netns exec lgmss timeout 4 python3 -c \"
import socket
s=socket.socket(); s.settimeout(3)
try: s.connect(('10.0.2.2', 9))
except Exception: pass
\"" >/dev/null 2>&1
  sleep 4

  local capturado
  capturado=$(vm "cat /tmp/mss.txt 2>/dev/null" | tr -d '\r')
  local mss
  mss=$(grep -oE 'mss [0-9]+' <<<"$capturado" | head -1 | grep -oE '[0-9]+')
  if [[ "$mss" == "1360" ]]; then
    ok "o MSS que sai pela WAN foi ajustado para a MTU do link (1360 em MTU 1400)"
  elif [[ "$mss" == "1460" ]]; then
    bad "o MSS saiu em 1460 — o cliente anunciou o que não cabe, que é o defeito da #130"
  else
    bad "não consegui ler o MSS do SYN capturado" "mss=${mss:-vazio} — $(tr '\n' ' ' <<<"$capturado" | head -c 200)"
  fi

  vm "ip link set enp0s2 mtu 1500; ip netns del lgmss 2>/dev/null; ip link del veth-mss 2>/dev/null; true" >/dev/null 2>&1
}


# ─── K. Janela de horário do grupo (issue #125) ──────────────────────────────
#
# O QUE SÓ UMA MÁQUINA PROVA. A condição é avaliada pelo KERNEL a cada pacote
# (`meta day` / `meta hour`), então o que decide se a feature funciona é o
# relógio da caixa — não o texto da regra. A bateria move o relógio e mede o
# tráfego real atravessando o firewall dentro e fora da janela.
#
# E MEDE O FUSO. `meta hour` usa a hora LOCAL do kernel, não UTC — foi medido
# no nft 1.1.3 e é do que a feature depende. Se uma versão futura mudar isso, o
# controle parental passaria a disparar três horas fora em qualquer máquina que
# não esteja em UTC, sem nenhum erro aparecer. A bateria roda com a VM em -03
# justamente para essa regressão não passar despercebida.
battery_schedule() {
  head_ "K. Janela de horário do grupo"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria K não roda"; return; }

  status PUT /api/nftables/policy "$tok" '{"policy":"accept"}' >/dev/null

  # Fuso diferente de UTC: é o que torna a asserção de hora local significativa.
  vm "timedatectl set-timezone America/Sao_Paulo; timedatectl set-ntp false" >/dev/null 2>&1

  # Cliente atrás do firewall.
  vm "ip netns del lgsched 2>/dev/null; ip link del veth-sch 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add lgsched && \
      ip link add veth-sch type veth peer name veth-sch-cl && \
      ip link set veth-sch-cl netns lgsched && \
      ip addr add 192.168.55.1/24 dev veth-sch && ip link set veth-sch up && \
      ip netns exec lgsched ip link set lo up && \
      ip netns exec lgsched ip addr add 192.168.55.2/24 dev veth-sch-cl && \
      ip netns exec lgsched ip link set veth-sch-cl up && \
      ip netns exec lgsched ip route add default via 192.168.55.1" >/dev/null 2>&1

  # Grupo com janela noturna, bloqueando o cliente de teste.
  local grupo
  grupo=$(body POST /api/nftables/groups "$tok" '{"name":"Janela K","cond_saddr":"192.168.55.2","fallthrough":"continue","scope":"forward","conn_state":"any","schedule":{"days":"","start":"22:00","end":"06:00"}}' | jqk id)
  [[ -n "$grupo" ]] || { bad "não consegui criar o grupo com janela"; return; }
  status POST /api/nftables/rules "$tok" "{\"group_id\":\"$grupo\",\"action\":\"drop\",\"saddr\":\"192.168.55.2\",\"enabled\":true,\"description\":\"bloqueio da bateria K\"}" >/dev/null
  sleep 2

  # K1 — a janela chegou ao ruleset vivo, e na ordem canônica.
  local fwd
  fwd=$(vm "nft list chain inet linkguard forward 2>/dev/null" | tr -d '\r')
  if grep -q 'meta hour "22:00"-"06:00"' <<<"$fwd"; then
    ok "a janela está na linha do jump do grupo"
  else bad "a janela não chegou ao firewall" "$(grep jump <<<"$fwd" | tr '\n' ' ')"; fi

  # K2/K3 — O TESTE QUE IMPORTA: o mesmo tráfego, dois horários.
  testa_horario() {
    vm "date -s '$1' >/dev/null 2>&1; conntrack -F >/dev/null 2>&1; true" >/dev/null 2>&1
    sleep 1
    if vm "ip netns exec lgsched ping -c 2 -W 2 10.0.2.2 >/dev/null 2>&1 && echo passou" | grep -q passou; then
      echo "passou"
    else
      echo "bloqueado"
    fi
  }
  local dentro fora
  dentro=$(testa_horario "23:30:00")
  fora=$(testa_horario "12:00:00")

  if [[ "$dentro" == "bloqueado" ]]; then ok "dentro da janela (23:30) o grupo bloqueia"
  else bad "dentro da janela o tráfego passou — a janela não está valendo"; fi
  if [[ "$fora" == "passou" ]]; then ok "fora da janela (12:00) o mesmo tráfego passa"
  else bad "fora da janela o tráfego continuou bloqueado — o grupo vale 24h"; fi

  # K4 — hora LOCAL, e não UTC. Às 23:30 locais são 02:30 UTC, que também cai
  # dentro de 22:00-06:00 — então esse par não distingue. O par que distingue é
  # 20:00 local (23:00 UTC): local está FORA da janela, UTC está DENTRO.
  local limite
  limite=$(testa_horario "20:00:00")
  if [[ "$limite" == "passou" ]]; then
    ok "a janela segue a hora local (20:00 local = 23:00 UTC, e passou)"
  else bad "às 20:00 locais o tráfego foi bloqueado — a janela está seguindo UTC, e o controle dispararia 3h fora"; fi

  # Limpeza: o grupo sai, o relógio volta.
  status DELETE /api/nftables/groups "$tok" "{\"id\":\"$grupo\"}" >/dev/null 2>&1
  vm "timedatectl set-ntp true; ip netns del lgsched 2>/dev/null; ip link del veth-sch 2>/dev/null; true" >/dev/null 2>&1
}


# ─── L. Registro de bloqueios (issue #122) ───────────────────────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. Em nft, `limit` é um CASAMENTO, não um
# modificador: numa regra `... limit rate 10/second counter drop`, o pacote que
# EXCEDE a taxa não casa a regra — e portanto NÃO é bloqueado. Escrever o
# limite no lugar errado transformaria o registro de bloqueios num buraco no
# firewall, e o painel continuaria dizendo que o host está bloqueado.
#
# Por isso a bateria manda mais pacotes do que a taxa de log permite e exige
# que TODOS continuem sendo descartados.
battery_blocklog() {
  head_ "L. Registro de bloqueios"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria L não roda"; return; }

  status PUT /api/nftables/policy "$tok" '{"policy":"accept"}' >/dev/null

  # Cliente atrás do firewall, para ser bloqueado de verdade.
  vm "ip netns del lgblk 2>/dev/null; ip link del veth-blk 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add lgblk && \
      ip link add veth-blk type veth peer name veth-blk-cl && \
      ip link set veth-blk-cl netns lgblk && \
      ip addr add 192.168.66.1/24 dev veth-blk && ip link set veth-blk up && \
      ip netns exec lgblk ip link set lo up && \
      ip netns exec lgblk ip addr add 192.168.66.2/24 dev veth-blk-cl && \
      ip netns exec lgblk ip link set veth-blk-cl up && \
      ip netns exec lgblk ip route add default via 192.168.66.1" >/dev/null 2>&1

  # L1 — desligado é o padrão, e a chain forward não pode ter linha de log.
  local st fwd
  st=$(status PUT /api/nftables/block-log "$tok" '{"enabled":false}')
  [[ "$st" == "200" ]] || { bad "não consegui desligar o registro: $st"; return; }
  sleep 2
  fwd=$(vm "nft list chain inet linkguard forward 2>/dev/null" | tr -d '\r')
  if ! grep -q 'log prefix' <<<"$fwd"; then ok "com o registro desligado não há linha de log"
  else bad "há linha de log com o registro desligado" "$(grep 'log prefix' <<<"$fwd" | tr '\n' ' ')"; fi

  # Bloqueia o cliente de teste (o host entra no set do grupo do sistema).
  status POST /api/hosts/block "$tok" '{"mac":"","blocked":true}' >/dev/null 2>&1
  vm "nft add element inet linkguard blocked_hosts { 192.168.66.2 }" >/dev/null 2>&1

  # L2 — ligar cria a linha de log SEM tirar a de drop.
  st=$(status PUT /api/nftables/block-log "$tok" '{"enabled":true}')
  [[ "$st" == "200" ]] || { bad "não consegui ligar o registro: $st"; return; }
  sleep 2
  fwd=$(vm "nft list chain inet linkguard forward 2>/dev/null" | tr -d '\r')
  if grep -q 'log prefix "lg:blk:host' <<<"$fwd"; then ok "a linha de log apareceu na forward"
  else bad "a linha de log não apareceu" "$(tr '\n' ' ' <<<"$fwd" | head -c 200)"; fi
  local drops
  drops=$(grep -c 'counter.*drop' <<<"$fwd" || true)
  if [[ "${drops:-0}" -ge 4 ]]; then ok "as quatro linhas de bloqueio continuam lá ($drops)"
  else bad "o registro comeu linhas de bloqueio: só $drops sobraram"; fi

  # L3 — A ASSERÇÃO CENTRAL: com o registro ligado, o bloqueio continua
  # bloqueando ACIMA da taxa de log. Se o limite estivesse na regra de drop,
  # parte destes pacotes passaria.
  vm "nft add element inet linkguard blocked_hosts { 192.168.66.2 } 2>/dev/null; true" >/dev/null 2>&1
  local passou
  passou=$(vm "ip netns exec lgblk ping -c 30 -i 0.05 -W 1 10.0.2.2 2>&1 | grep -oE '[0-9]+ received' | grep -oE '^[0-9]+'" | tr -d '\r')
  if [[ "${passou:-0}" == "0" ]]; then
    ok "30 pacotes acima da taxa de log e nenhum passou (o limite está na regra certa)"
  else bad "$passou de 30 pacotes passaram com o registro ligado — o limite está na regra de drop e abriu um buraco"; fi

  # L4 — e o painel mostra o que foi bloqueado.
  local n
  n=$(body GET "/api/nftables/block-log/entries?limit=50" "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(len([e for e in d.get('entries',[]) if e.get('src')=='192.168.66.2']))" 2>/dev/null)
  if [[ -n "$n" && "$n" -gt 0 ]]; then ok "o painel lista $n descarte(s) do host bloqueado"
  else bad "o painel não mostrou nenhum descarte do host bloqueado"; fi

  # L5 — desligar remove as linhas de log.
  status PUT /api/nftables/block-log "$tok" '{"enabled":false}' >/dev/null
  sleep 2
  if ! vm "nft list chain inet linkguard forward 2>/dev/null" | grep -q 'log prefix'; then
    ok "desligar removeu as linhas de log"
  else bad "as linhas de log sobreviveram ao desligamento"; fi

  vm "nft delete element inet linkguard blocked_hosts { 192.168.66.2 } 2>/dev/null; ip netns del lgblk 2>/dev/null; ip link del veth-blk 2>/dev/null; true" >/dev/null 2>&1
}

# ─── M. DNS dinâmico (issue #129) ────────────────────────────────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. Um cliente de DDNS falha de dois jeitos
# que teste de unidade não pega e que o painel esconde:
#
#  1. Ele amarra a requisição ao endereço do link (numa caixa com duas WANs,
#     sair pela WAN errada publica o endereço errado). Amarrar socket a um
#     endereço só falha de verdade numa máquina de verdade.
#  2. Os provedores do protocolo dyndns respondem HTTP 200 com o erro NO CORPO
#     ("badauth", "nohost"). Um cliente que olha só o código diz "atualizado"
#     para sempre enquanto o nome aponta para o endereço antigo — e o
#     encaminhamento de porta, que é o motivo de tudo isto existir, fica quebrado
#     sem nenhum sinal.
#
# Por isso a bateria sobe um provedor de mentira NA PRÓPRIA VM, num endereço
# público de teste (203.0.113.0/24, TEST-NET-3), e confere o que chegou nele.
# Endereço público na interface também exercita o caminho que NÃO consulta
# serviço externo nenhum — a bateria roda offline de propósito.
battery_ddns() {
  head_ "M. DNS dinâmico"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria M não roda"; return; }

  # Provedor de mentira: /upd responde "good", /badauth responde 200 com erro
  # no corpo. Todos os acessos ficam registrados.
  vm "pkill -f ddns-fake >/dev/null 2>&1; ip link del lg-ddns 2>/dev/null; rm -f /tmp/ddns-hits.log; true" >/dev/null 2>&1
  vm "ip link add lg-ddns type dummy && ip addr add 203.0.113.7/24 dev lg-ddns && ip link set lg-ddns up" >/dev/null 2>&1
  vm "cat > /tmp/ddns-fake.py <<'PYEOF'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        open('/tmp/ddns-hits.log','a').write(self.path + '\n')
        corpo = b'badauth' if self.path.startswith('/badauth') else b'good 203.0.113.7'
        self.send_response(200)
        self.send_header('Content-Length', str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('203.0.113.7', 18080), H).serve_forever()
PYEOF
      setsid python3 /tmp/ddns-fake.py >/dev/null 2>&1 < /dev/null &
      sleep 1" >/dev/null 2>&1

  # Sanidade: se o provedor de mentira não responde, a bateria não tem como
  # distinguir "DDNS quebrado" de "listener quebrado" — então nem tenta.
  local vivo
  vivo=$(vm "curl -s -o /dev/null -w '%{http_code}' --max-time 3 'http://203.0.113.7:18080/ping'" | tr -d '\r')
  if [[ "$vivo" != "200" ]]; then
    bad "o provedor de mentira não subiu na VM (HTTP '$vivo'); a bateria M não roda"
    vm "pkill -f ddns-fake; ip link del lg-ddns 2>/dev/null; true" >/dev/null 2>&1
    return
  fi
  vm "rm -f /tmp/ddns-hits.log" >/dev/null 2>&1

  # Link com endereço PÚBLICO na interface, cadastrado pelo painel.
  local st
  st=$(status POST /api/links "$tok" '{"name":"WAN DDNS","interface":"lg-ddns","gateway":"203.0.113.1","ip_address":"203.0.113.7","weight":1,"enabled":true,"monitor_hosts":"203.0.113.1","dns_test":"203.0.113.1"}')
  if [[ "$st" != "200" && "$st" != "201" ]]; then bad "não consegui cadastrar o link de teste: $st"; return; fi
  local link
  link=$(body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l['interface']=='lg-ddns': print(l['id'])" 2>/dev/null)
  [[ -n "$link" ]] || { bad "o link de teste não apareceu na listagem"; return; }

  local bom="http://203.0.113.7:18080/upd?h={hostname}&ip={ip}"
  local ruim="http://203.0.113.7:18080/badauth?h={hostname}&ip={ip}"

  # M1 — modelo sem {ip} é recusado NA HORA. Sem o {ip}, o provedor usa o
  # endereço de quem chamou: acerta por acidente enquanto a caixa fala pela WAN
  # certa e erra em silêncio no dia em que ela troca de link.
  st=$(status PUT /api/ddns "$tok" "{\"link_id\":\"$link\",\"enabled\":true,\"hostname\":\"casa.teste\",\"url_template\":\"http://203.0.113.7:18080/upd?h={hostname}\"}")
  if [[ "$st" == "400" ]]; then ok "modelo de URL sem {ip} é recusado ao salvar"
  else bad "modelo sem {ip} foi aceito (HTTP $st) — o nome apontaria para o endereço de quem chamou"; fi

  # M2 — salvar de verdade, com segredo.
  st=$(status PUT /api/ddns "$tok" "{\"link_id\":\"$link\",\"enabled\":true,\"hostname\":\"casa.teste\",\"url_template\":\"$bom\",\"username\":\"u1\",\"secret\":\"tok-secreto-123\"}")
  if [[ "$st" == "200" ]]; then ok "configuração aceita pelo painel"
  else bad "não consegui salvar a configuração: $st"; return; fi

  # M3 — o segredo NUNCA volta pela API, mas o painel sabe que existe um.
  local linha
  linha=$(body GET /api/ddns "$tok" | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r.get('interface')=='lg-ddns': print(json.dumps(r))" 2>/dev/null)
  if grep -q '"secret_set": *true' <<<"$linha" && ! grep -q 'tok-secreto-123' <<<"$linha"; then
    ok "o segredo não volta pela API, mas a tela sabe que há um guardado"
  else bad "a API expôs o segredo ou perdeu o secret_set" "$(head -c 200 <<<"$linha")"; fi

  # M4 — A ASSERÇÃO CENTRAL: a verificação publica de verdade, amarrada ao
  # endereço do link, com hostname e IP substituídos.
  status POST /api/ddns/check "$tok" >/dev/null
  local hits
  hits=$(vm "cat /tmp/ddns-hits.log 2>/dev/null" | tr -d '\r')
  if grep -q 'h=casa.teste' <<<"$hits" && grep -q 'ip=203.0.113.7' <<<"$hits"; then
    ok "o provedor recebeu o nome e o endereço do link substituídos"
  else bad "o provedor não recebeu a atualização" "recebido: $(tr '\n' ' ' <<<"$hits" | head -c 200)"; fi

  # M5 — endereço público na interface não consulta serviço externo nenhum, e o
  # painel mostra o resultado sem erro.
  local estado
  estado=$(body GET /api/ddns "$tok" | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r.get('interface')=='lg-ddns':
        s=r.get('state') or {}
        print(s.get('public_ip',''), s.get('behind_nat'), repr(s.get('last_error','')))" 2>/dev/null)
  if [[ "$estado" == "203.0.113.7 False ''" ]]; then
    ok "o painel mostra o endereço publicado, sem CGNAT e sem erro ($estado)"
  else bad "o estado publicado está errado" "$estado"; fi

  # M6 — mesma configuração, mesmo endereço: NÃO incomoda o provedor de novo.
  # Vários deles bloqueiam a conta por atualização repetida.
  local antes depois
  antes=$(vm "grep -c '^/upd' /tmp/ddns-hits.log 2>/dev/null || echo 0" | tr -d '\r')
  status POST /api/ddns/check "$tok" >/dev/null
  depois=$(vm "grep -c '^/upd' /tmp/ddns-hits.log 2>/dev/null || echo 0" | tr -d '\r')
  if [[ "$antes" == "$depois" ]]; then ok "endereço inalterado não gera nova atualização ($depois)"
  else bad "o provedor foi chamado de novo sem nada ter mudado ($antes → $depois)"; fi

  # M7 — trocar a configuração REPUBLICA mesmo com o endereço igual. Sem isto,
  # o admin que corrige o nome errado espera o provedor trocar o IP — semanas.
  status PUT /api/ddns "$tok" "{\"link_id\":\"$link\",\"enabled\":true,\"hostname\":\"casa2.teste\",\"url_template\":\"$bom\",\"username\":\"u1\"}" >/dev/null
  status POST /api/ddns/check "$tok" >/dev/null
  if vm "cat /tmp/ddns-hits.log" | grep -q 'h=casa2.teste'; then
    ok "corrigir o nome republica na hora, sem esperar o endereço mudar"
  else bad "o nome corrigido não foi publicado — ficaria parado até o provedor trocar o IP"; fi

  # M8 — A OUTRA ASSERÇÃO CENTRAL: HTTP 200 com erro no corpo é FALHA. É assim
  # que o protocolo dyndns responde a token errado, e é onde um cliente ingênuo
  # mente "atualizado" para sempre.
  status PUT /api/ddns "$tok" "{\"link_id\":\"$link\",\"enabled\":true,\"hostname\":\"casa3.teste\",\"url_template\":\"$ruim\",\"username\":\"u1\"}" >/dev/null
  status POST /api/ddns/check "$tok" >/dev/null
  local erro
  erro=$(body GET /api/ddns "$tok" | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r.get('interface')=='lg-ddns': print((r.get('state') or {}).get('last_error',''))" 2>/dev/null)
  if [[ -n "$erro" ]]; then ok "200 com \"badauth\" no corpo é registrado como falha ($erro)"
  else bad "o provedor recusou a atualização e o painel diz que deu certo"; fi

  # M9 — e a falha é TENTADA DE NOVO na verificação seguinte. Erro que não é
  # retentado é erro permanente por acidente.
  antes=$(vm "grep -c '^/badauth' /tmp/ddns-hits.log 2>/dev/null || echo 0" | tr -d '\r')
  status POST /api/ddns/check "$tok" >/dev/null
  depois=$(vm "grep -c '^/badauth' /tmp/ddns-hits.log 2>/dev/null || echo 0" | tr -d '\r')
  if [[ "${depois:-0}" -gt "${antes:-0}" ]]; then ok "depois de falhar, a verificação seguinte tenta de novo"
  else bad "a falha não foi retentada ($antes → $depois) — ficaria parada para sempre"; fi

  # Limpeza: o link de teste, o provedor de mentira e a interface saem.
  status DELETE "/api/links/$link" "$tok" >/dev/null 2>&1
  vm "pkill -f ddns-fake >/dev/null 2>&1; ip link del lg-ddns 2>/dev/null; rm -f /tmp/ddns-fake.py /tmp/ddns-hits.log; true" >/dev/null 2>&1
}

# ─── N. Proteção de entrada das WANs (issue #119, fase 1) ────────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA, E ELA MUDOU DEPOIS DE A VM FALAR.
#
# A primeira versão desta proteção descartava TUDO que chegasse como conexão
# nova pelas WANs. Esta bateria foi escrita para contornar o efeito colateral —
# e o efeito colateral chegou antes dela: a bateria F chama
# `POST /api/links/auto-detect`, o caminho normal do produto, o auto-detect
# cadastrou como WAN a interface por onde o arnês fala com a VM, e a máquina
# descartou a porta 22 e a do painel. SSH e painel mortos na bateria F; as
# baterias de G a M falharam todas por não ter mais com quem falar.
#
# Não é caso de canto: numa caixa de uma NIC só, "detectar links" é a primeira
# coisa que se faz numa instalação nova.
#
# Por isso a asserção central desta bateria hoje é o CONTRÁRIO da que ela
# nasceu: a gerência tem de continuar respondendo pela WAN, e o descarte tem de
# valer para todo o resto. E o fato de as baterias G a N rodarem depois de a F
# ter chamado o auto-detect é, sozinho, metade da prova.
battery_waninput() {
  head_ "N. Proteção de entrada das WANs"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria N não roda"; return; }

  # N0 — A PROVA QUE VALE MAIS: chegamos aqui. A bateria F cadastrou a NIC de
  # gerência como WAN e o arnês continua conversando com a máquina.
  local wans
  wans=$(vm "nft list chain inet linkguard input 2>/dev/null" | grep -oE 'iifname \{[^}]*\}' | head -1 | tr -d '\r')
  if [[ -n "$wans" ]]; then
    ok "a proteção está ligada nas WANs detectadas e o painel continua respondendo ($wans)"
  else bad "a proteção não está na chain input; o resto da bateria não significa nada"; return; fi

  # A "internet" do outro lado de uma WAN de mentira, para testar de FORA.
  vm "pkill -f wanecho >/dev/null 2>&1; ip netns del lgwan 2>/dev/null; ip link del lg-win 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add lgwan && \
      ip link add lg-win type veth peer name lg-win-net && \
      ip link set lg-win-net netns lgwan && \
      ip addr add 198.51.100.1/24 dev lg-win && ip link set lg-win up && \
      ip netns exec lgwan ip link set lo up && \
      ip netns exec lgwan ip addr add 198.51.100.2/24 dev lg-win-net && \
      ip netns exec lgwan ip link set lg-win-net up" >/dev/null 2>&1

  local st
  st=$(status POST /api/links "$tok" '{"name":"WAN 119","interface":"lg-win","gateway":"198.51.100.2","ip_address":"198.51.100.1","weight":1,"enabled":true,"monitor_hosts":"198.51.100.2","dns_test":"198.51.100.2"}')
  if [[ "$st" != "200" && "$st" != "201" ]]; then bad "não consegui cadastrar a WAN de mentira: $st"; return; fi
  sleep 2

  local chain
  chain=$(vm "nft list chain inet linkguard input 2>/dev/null" | tr -d '\r')

  # N1 — o descarte é a ÚLTIMA linha, e a liberação da gerência vem ANTES dele.
  local ultima
  ultima=$(grep -vE '^\s*$|^table |^\s*chain |^\s*type filter|^\s*\}' <<<"$chain" | tail -1)
  if grep -q 'ct state new counter.*drop' <<<"$ultima"; then ok "o descarte é a última linha da chain input"
  else bad "a última linha da chain não é o descarte" "$ultima"; fi
  if grep -q 'tcp dport {.*9997' <<<"$chain"; then ok "a porta do painel está liberada nas WANs"
  else bad "a porta do painel NÃO está liberada — a caixa se tranca no próximo reboot" "$(grep 'tcp dport' <<<"$chain" | tr '\n' ' ')"; fi

  # N2 — as liberações que evitam quebra dias depois.
  local faltando="" token
  for token in "nd-router-advert" "nd-neighbor-advert" "packet-too-big" "udp dport 68" "udp dport 546" "ct status dnat"; do
    grep -q "$token" <<<"$chain" || faltando="$faltando $token"
  done
  if [[ -z "$faltando" ]]; then ok "as liberações de DHCP, vizinhança IPv6, PMTUD e DNAT estão na chain"
  else bad "faltam liberações na chain:$faltando"; fi

  # N3 — A ASSERÇÃO ANTI-TRANCA: o painel responde pela WAN.
  local code
  code=$(vm "ip netns exec lgwan curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://198.51.100.1:9997/api/health 2>/dev/null" | tr -d '\r')
  if [[ "$code" == "200" ]]; then ok "o painel responde pela WAN: ninguém é trancado do lado de fora"
  else bad "O PAINEL NÃO RESPONDE PELA WAN (curl '${code:-nada}') — é a tranca que a bateria F sofreu"; fi

  # N4 — E o descarte vale para todo o resto: uma porta que não é de gerência,
  # escutando no MESMO endereço, não pode responder.
  vm "cat > /tmp/wanserv.py <<'PYEOF'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('0.0.0.0', 18082), H).serve_forever()
PYEOF
      setsid python3 /tmp/wanserv.py >/dev/null 2>&1 < /dev/null &
      sleep 1" >/dev/null 2>&1
  local interno externo
  interno=$(vm "curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://198.51.100.1:18082/ 2>/dev/null" | tr -d '\r')
  externo=$(vm "ip netns exec lgwan curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://198.51.100.1:18082/ 2>/dev/null" | tr -d '\r')
  if [[ "$interno" == "200" && "$externo" != "200" ]]; then
    ok "porta que não é de gerência escuta, responde localmente e é descartada na WAN"
  else bad "o descarte não está valendo (local '$interno', da WAN '$externo')"; fi

  # N5 — conexão aberta de DENTRO continua viva. Se o descarte deixar de casar
  # só `ct state new`, é aqui que aparece — e é o defeito que mataria o apt e o
  # próprio atualizador do painel.
  vm "cat > /tmp/wanecho.py <<'PYEOF'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        corpo = b'de fora'
        self.send_response(200); self.send_header('Content-Length', str(len(corpo))); self.end_headers(); self.wfile.write(corpo)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('198.51.100.2', 18081), H).serve_forever()
PYEOF
      ip netns exec lgwan setsid python3 /tmp/wanecho.py >/dev/null 2>&1 < /dev/null &
      sleep 1" >/dev/null 2>&1
  local saida
  saida=$(vm "curl -s --max-time 5 http://198.51.100.2:18081/ 2>/dev/null" | tr -d '\r')
  if [[ "$saida" == "de fora" ]]; then
    ok "conexão aberta de dentro para fora continua respondendo (o descarte não pega estabelecida)"
  else bad "a resposta de uma conexão de SAÍDA foi bloqueada ('$saida')"; fi

  # N6 — a saída de emergência ao contrário: um grupo de escopo input FECHA a
  # gerência na WAN, porque os jumps são avaliados antes das nossas linhas. É o
  # que a fase 3 vai oferecer com um botão.
  #
  # ATENÇÃO AO CONFIRMAR: mutação de escopo INPUT abre a janela de
  # confirmação-ou-reverte (bateria C), e enquanto ela está aberta o produto
  # RECUSA a mutação seguinte. A primeira versão desta bateria criava o grupo e
  # tentava criar a regra em seguida, tomava 400 e concluía que o descarte
  # estava acima dos jumps — diagnóstico errado a partir de um sintoma real. A
  # janela é justamente o mecanismo que a fase 3 vai usar para fechar a
  # gerência com segurança.
  # confirma_janela LÊ O ID DA JANELA DO CORPO DA RESPOSTA e confirma. Sem o
  # corpo `{"id":...}` o endpoint devolve 400 — e uma confirmação que falha em
  # silêncio deixa a janela aberta, a mutação seguinte é recusada, e a bateria
  # acusa o firewall por um erro que é dela.
  confirma_janela() {
    local janela
    janela=$(jqk pending.id <<<"$1")
    [[ -n "$janela" ]] || return 0
    status POST /api/nftables/pending/confirm "$tok" "{\"id\":\"$janela\"}" >/dev/null
  }

  local resp grupo
  resp=$(body POST /api/nftables/groups "$tok" '{"name":"Fecha gerencia N","scope":"input","fallthrough":"continue","conn_state":"any"}')
  grupo=$(jqk id <<<"$resp")
  if [[ -n "$grupo" ]]; then
    confirma_janela "$resp"
    resp=$(body POST /api/nftables/rules "$tok" "{\"group_id\":\"$grupo\",\"action\":\"drop\",\"saddr\":\"198.51.100.2\",\"proto\":\"tcp\",\"dport\":\"9997\",\"enabled\":true,\"description\":\"fecha gerencia da bateria N\"}")
    confirma_janela "$resp"
    sleep 2
    code=$(vm "ip netns exec lgwan curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://198.51.100.1:9997/api/health 2>/dev/null" | tr -d '\r')
    if [[ "$code" != "200" ]]; then ok "um grupo de escopo input fecha a gerência na WAN (o admin manda mais que a nossa liberação)"
    else
      # A MENSAGEM NÃO CONCLUI NADA, E ISSO É PROPOSITAL. Ela já afirmou duas
      # vezes que "as nossas linhas estão acima dos jumps" quando a causa era
      # outra (a janela de confirmação recusando a criação da regra). Quem lê
      # uma falha precisa da EVIDÊNCIA para decidir, não da hipótese de quem
      # escreveu o teste.
      bad "a gerência continuou respondendo pela WAN com o grupo do admin no lugar" \
          "ordem na chain: $(vm "nft list chain inet linkguard input" | grep -cE 'jump grp_') jump(s) de grupo; regras no grupo: $(vm "nft list table inet linkguard" | grep -A4 "chain grp_" | grep -c 'drop')"
    fi
    confirma_janela "$(body DELETE /api/nftables/groups "$tok" "{\"id\":\"$grupo\"}")"
  else bad "não consegui criar o grupo de escopo input" "$(head -c 200 <<<"$resp")"; fi

  # N7 — apagar o link tira a proteção dele da chain na hora.
  local linkid
  linkid=$(body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l['interface']=='lg-win': print(l['id'])" 2>/dev/null)
  if [[ -n "$linkid" ]]; then
    status DELETE "/api/links/$linkid" "$tok" >/dev/null 2>&1
    sleep 2
    if ! vm "nft list chain inet linkguard input 2>/dev/null" | grep -q 'lg-win'; then
      ok "apagar o link tira a proteção dele da chain na hora"
    else bad "a chain continua casando uma interface que não é mais WAN"; fi
  else
    bad "não achei o link lg-win para apagar; a asserção de remoção não foi medida" \
        "$(body GET /api/links "$tok" | head -c 200)"
  fi

  vm "pkill -f wanecho >/dev/null 2>&1; pkill -f wanserv >/dev/null 2>&1; ip netns del lgwan 2>/dev/null; ip link del lg-win 2>/dev/null; rm -f /tmp/wanecho.py /tmp/wanserv.py; true" >/dev/null 2>&1
}

# ─── O. Bloqueio de host nas duas famílias (issue #119, fase 2) ──────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. O bloqueio de host era `ip saddr
# @blocked_hosts` — só IPv4. A tabela é `inet`: o MESMO host, falando IPv6,
# atravessa a chain forward sem casar com nada e é encaminhado, com o painel
# dizendo "bloqueado". Não é proteção incompleta; é afirmação falsa na tela.
#
# HOJE ISSO NÃO APARECE, E É POR ISSO QUE PRECISA DE BATERIA. Medido em
# produção: `net.ipv6.conf.all.forwarding = 0`. O produto só liga o forwarding
# IPv4, então a caixa não roteia IPv6 para a LAN e o furo fica latente — ele
# nasce no dia em que alguém ligar delegação de prefixo. Esta bateria LIGA o
# forwarding IPv6 de propósito: ela encena esse dia, para o defeito ser
# encontrado antes dele.
#
# O A/B é a parte que dá valor: com o bloqueio por endereço físico o IPv6 morre;
# tirando SÓ esse set (e deixando o de IPv4 intacto), o IPv6 volta a passar
# enquanto o IPv4 continua bloqueado — que é exatamente o defeito, reproduzido.
battery_bloqueio_familias() {
  head_ "O. Bloqueio de host nas duas famílias"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria O não roda"; return; }

  status PUT /api/nftables/policy "$tok" '{"policy":"accept"}' >/dev/null

  # O ZERO — A TELA CONTA O QUE O RULESET FAZ (issue #119, fase 3).
  #
  # A asserção não é sobre texto bonito: é que a API e o `nft` NÃO PODEM
  # DISCORDAR. Uma tela com a própria cópia da verdade diverge em silêncio, que
  # é o defeito que a fase 3 existe para fechar — e é o mesmo formato dos quatro
  # erros de bateria de hoje, onde o teste supôs um detalhe em vez de perguntar.
  local exp portas_api portas_nft
  exp=$(body GET /api/nftables/policy "$tok")
  portas_api=$(python3 -c "
import json,sys
d=json.loads(sys.argv[1]).get('exposure') or {}
print(','.join(str(p) for p in (d.get('management_ports') or [])))" "$exp" 2>/dev/null)
  portas_nft=$(vm "nft list chain inet linkguard input 2>/dev/null" | grep -oE 'tcp dport \{[^}]*\}' | grep -oE '[0-9]+' | paste -sd, -)
  if [[ -n "$portas_api" && "$portas_api" == "$portas_nft" ]]; then
    ok "a tela anuncia exatamente as portas que a chain libera ($portas_api)"
  else bad "a tela e o ruleset discordam sobre as portas de gerência" "API '$portas_api' vs nft '$portas_nft'"; fi

  local fwd_api fwd_sys
  fwd_api=$(python3 -c "
import json,sys
print((json.loads(sys.argv[1]).get('exposure') or {}).get('ipv6_forwarding',''))" "$exp" 2>/dev/null)
  fwd_sys=$(vm "cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null" | tr -d '
')
  local esperado="unknown"
  [[ "$fwd_sys" == "0" ]] && esperado="off"
  [[ -n "$fwd_sys" && "$fwd_sys" != "0" ]] && esperado="on"
  if [[ "$fwd_api" == "$esperado" ]]; then ok "a tela diz o estado real do encaminhamento IPv6 ('$fwd_api')"
  else bad "a tela discorda do sysctl de IPv6" "API '$fwd_api', /proc '$fwd_sys' (esperado '$esperado')"; fi

  # O0 — A SET TEM DE EXISTIR NUMA MÁQUINA QUE VEIO DE UPGRADE.
  #
  # O DEFEITO QUE ESTA LINHA PEGA, e que escapou para produção: a set nascia só
  # no EnsureTable, que é NO-OP em caixa já provisionada. Depois do upgrade a
  # tabela já existia, o bootstrap não rodava, a set não aparecia — e a regra
  # que a referencia sumia em silêncio da forward. O painel continuava dizendo
  # "bloqueado" e o bloqueio valia só para IPv4.
  #
  # A bateria O inteira passava mesmo assim, porque as asserções dela olhavam
  # tráfego e o tráfego era bloqueado pelo set de IPv4. Só uma asserção sobre a
  # EXISTÊNCIA da set separa "está funcionando" de "está funcionando por outro
  # motivo".
  if vm "nft list set inet linkguard blocked_macs" >/dev/null 2>&1; then
    ok "a set de endereços físicos existe (inclusive vinda de upgrade)"
  else bad "a set blocked_macs não existe: o bloqueio vale só para IPv4 nesta caixa"; fi

  # Cliente e servidor, cada um do seu lado do firewall, com IPv4 e IPv6.
  vm "pkill -f duasfam >/dev/null 2>&1
      ip netns del lgcli 2>/dev/null; ip netns del lgsrv 2>/dev/null
      ip link del veth-cli 2>/dev/null; ip link del veth-srv 2>/dev/null; true" >/dev/null 2>&1
  vm "sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
      ip netns add lgcli && ip netns add lgsrv && \
      ip link add veth-cli type veth peer name veth-cli-p && \
      ip link add veth-srv type veth peer name veth-srv-p && \
      ip link set veth-cli-p netns lgcli && ip link set veth-srv-p netns lgsrv && \
      ip addr add 192.168.77.1/24 dev veth-cli && ip -6 addr add fd00:77::1/64 dev veth-cli nodad && ip link set veth-cli up && \
      ip addr add 192.168.88.1/24 dev veth-srv && ip -6 addr add fd00:88::1/64 dev veth-srv nodad && ip link set veth-srv up && \
      ip netns exec lgcli sh -c 'ip link set lo up; ip addr add 192.168.77.2/24 dev veth-cli-p; ip -6 addr add fd00:77::2/64 dev veth-cli-p nodad; ip link set veth-cli-p up; ip route add default via 192.168.77.1; ip -6 route add default via fd00:77::1' && \
      ip netns exec lgsrv sh -c 'ip link set lo up; ip addr add 192.168.88.2/24 dev veth-srv-p; ip -6 addr add fd00:88::2/64 dev veth-srv-p nodad; ip link set veth-srv-p up; ip route add default via 192.168.88.1; ip -6 route add default via fd00:88::1'" >/dev/null 2>&1

  # Servidor de mentira, escutando nas duas famílias.
  vm "cat > /tmp/duasfam.py <<'PYEOF'
import http.server, socketserver, socket
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
class S(socketserver.TCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
S(('::', 18090), H).serve_forever()
PYEOF
      ip netns exec lgsrv setsid python3 /tmp/duasfam.py >/dev/null 2>&1 < /dev/null &
      sleep 1" >/dev/null 2>&1

  # alcanca FAMILIA → código HTTP do cliente até o servidor.
  alcanca() {
    if [[ "$1" == "6" ]]; then
      vm "ip netns exec lgcli curl -s -o /dev/null -w '%{http_code}' --max-time 4 'http://[fd00:88::2]:18090/' 2>/dev/null" | tr -d '\r'
    else
      vm "ip netns exec lgcli curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://192.168.88.2:18090/ 2>/dev/null" | tr -d '\r'
    fi
  }

  # O1 — linha de base: sem bloqueio, as duas famílias atravessam. Sem isto o
  # resto da bateria não distingue "bloqueado" de "nunca funcionou".
  local v4 v6
  v4=$(alcanca 4); v6=$(alcanca 6)
  if [[ "$v4" == "200" && "$v6" == "200" ]]; then ok "sem bloqueio o host atravessa em IPv4 e IPv6"
  else bad "a linha de base não funciona (v4 '$v4', v6 '$v6'); a bateria O não prova nada"; return; fi

  # O2 — bloqueia pelo caminho do produto, com o endereço físico do cliente.
  local mac
  mac=$(vm "ip netns exec lgcli cat /sys/class/net/veth-cli-p/address" | tr -d '\r')
  [[ -n "$mac" ]] || { bad "não consegui ler o endereço físico do cliente"; return; }
  local st
  st=$(status POST /api/hosts/block "$tok" "{\"mac\":\"$mac\",\"blocked\":true}")
  if [[ "$st" == "200" ]]; then ok "host bloqueado pelo painel ($mac)"
  else bad "não consegui bloquear o host: $st"; return; fi
  sleep 2

  # O3 — BLOQUEIO VALE PARA HOST QUE O PRODUTO NUNCA VIU.
  #
  # Esta asserção nasceu de uma FALHA DA PRÓPRIA BATERIA: o A/B abaixo não
  # separava as famílias, e o motivo era que o set de IPv4 estava VAZIO — o
  # cliente nunca tinha sido listado, então não havia MAC→IP para traduzir e os
  # dois bloqueios vinham do endereço físico. Antes da fase 2 isso não seria
  # detalhe de teste: bloquear um host ainda não visto não escrevia NADA no
  # firewall, e a tela já dizia "bloqueado".
  local elementos
  elementos=$(vm "nft list set inet linkguard blocked_hosts" | tr -d '\r')
  if ! grep -q 'elements' <<<"$elementos"; then
    ok "host nunca visto pelo produto já fica bloqueado (o set de IPv4 está vazio)"
  else bad "o set de IPv4 tem elemento para um host que nunca foi listado" "$(tr '\n' ' ' <<<"$elementos")"; fi

  local v4 v6
  v4=$(alcanca 4); v6=$(alcanca 6)
  if [[ "$v4" != "200" ]]; then ok "host bloqueado não atravessa em IPv4"
  else bad "o host bloqueado continua atravessando em IPv4"; fi
  if [[ "$v6" != "200" ]]; then ok "host bloqueado não atravessa em IPv6 — a tela deixou de mentir"
  else bad "O HOST BLOQUEADO ATRAVESSA EM IPv6: o painel diz bloqueado e ele não está"; fi

  # O4 — agora com o host REGISTRADO, para o A/B ter os dois sets preenchidos.
  # GET /api/hosts é o que grava o avistamento (hosts.List) — o mesmo caminho
  # que a tela percorre sozinha quando alguém abre a página de Hosts.
  status POST /api/hosts/block "$tok" "{\"mac\":\"$mac\",\"blocked\":false}" >/dev/null
  sleep 1
  alcanca 4 >/dev/null   # tráfego para o firewall aprender o vizinho
  body GET /api/hosts "$tok" >/dev/null
  status POST /api/hosts/block "$tok" "{\"mac\":\"$mac\",\"blocked\":true}" >/dev/null
  sleep 2
  elementos=$(vm "nft list set inet linkguard blocked_hosts" | tr -d '\r')
  if grep -q '192.168.77.2' <<<"$elementos"; then
    ok "depois de o produto ver o host, o endereço dele entra no set de IPv4 também"
  else bad "o host foi listado e o endereço não entrou no set de IPv4" "$(tr '\n' ' ' <<<"$elementos")"; fi

  # O5 — O DEFEITO, REPRODUZIDO. Com os DOIS sets preenchidos, tirar só o de
  # endereços físicos devolve o IPv6 e mantém o IPv4 bloqueado. É isto que
  # impede as asserções acima de estarem medindo outra coisa.
  vm "nft flush set inet linkguard blocked_macs" >/dev/null 2>&1
  sleep 1
  v4=$(alcanca 4); v6=$(alcanca 6)
  if [[ "$v6" == "200" && "$v4" != "200" ]]; then
    ok "sem o set de endereços físicos o IPv6 volta a passar e o IPv4 não (o defeito, reproduzido)"
  else
    bad "o A/B não separou as famílias (v4 '$v4', v6 '$v6')" \
        "set de IPv4 agora: $(vm "nft list set inet linkguard blocked_hosts" | tr -d '\r' | tr '\n' ' ')"
  fi

  # O6 — e desbloquear devolve as duas.
  status POST /api/hosts/block "$tok" "{\"mac\":\"$mac\",\"blocked\":false}" >/dev/null
  sleep 2
  v4=$(alcanca 4); v6=$(alcanca 6)
  if [[ "$v4" == "200" && "$v6" == "200" ]]; then ok "desbloquear devolve as duas famílias"
  else bad "depois de desbloquear o host continua cortado (v4 '$v4', v6 '$v6')"; fi

  vm "pkill -f duasfam >/dev/null 2>&1
      ip netns del lgcli 2>/dev/null; ip netns del lgsrv 2>/dev/null
      ip link del veth-cli 2>/dev/null; ip link del veth-srv 2>/dev/null
      sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null
      rm -f /tmp/duasfam.py; true" >/dev/null 2>&1
}

# ─── P. Encaminhamento de porta por WAN secundária (issues #120 e #82) ───────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA, E A LACUNA QUE ELA FECHA. A bateria H
# valida o roteamento de resposta pingando o endereço da PRÓPRIA caixa
# (10.66.0.1). Esse pacote é resolvido pela tabela `local`, de prioridade 0, e
# nunca chega na `ip rule fwmark` — então H nunca exercitou TRAVESSIA.
#
# O defeito que passou por essa lacuna era meu, entregue na #120: a chain de
# prerouting está em `priority mangle + 10` (-140), ANTES do dstnat (-100), e a
# regra de restauração de marca não distinguia direção. O pacote que CHEGA da
# internet para um host da LAN recebia a marca da WAN; o DNAT reescrevia o
# destino; o kernel decidia a rota já com a marca posta, casava a
# `ip rule fwmark N lookup N` e caía na tabela do link — que contém APENAS
# `default via <gateway da WAN>`. O SYN destinado ao host da LAN voltava para o
# provedor.
#
# Sintoma para quem opera: o painel mostra o encaminhamento aplicado, a tradução
# está na chain de DNAT, e a câmera/NVR/servidor interno não responde de fora.
# Nada no ruleset parece errado.
battery_portforward_wan2() {
  head_ "P. Encaminhamento de porta por WAN secundária"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria P não roda"; return; }

  status PUT /api/nftables/policy "$tok" '{"policy":"accept"}' >/dev/null

  # "Internet" de um lado (wanp), host da LAN do outro (lanp).
  vm "pkill -f alvopf >/dev/null 2>&1
      ip netns del wanp 2>/dev/null; ip netns del lanp 2>/dev/null
      ip link del lg-wanp 2>/dev/null; ip link del lg-lanp 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add wanp && ip netns add lanp && \
      ip link add lg-wanp type veth peer name wanp-far && \
      ip link add lg-lanp type veth peer name lanp-far && \
      ip link set wanp-far netns wanp && ip link set lanp-far netns lanp && \
      ip addr add 10.77.0.1/24 dev lg-wanp && ip link set lg-wanp up && \
      ip addr add 192.168.99.1/24 dev lg-lanp && ip link set lg-lanp up && \
      ip netns exec wanp sh -c 'ip link set lo up; ip addr add 10.77.0.2/24 dev wanp-far; ip link set wanp-far up; ip route add default via 10.77.0.1' && \
      ip netns exec lanp sh -c 'ip link set lo up; ip addr add 192.168.99.2/24 dev lanp-far; ip link set lanp-far up; ip route add default via 192.168.99.1'" >/dev/null 2>&1

  # Servidor interno, o que o encaminhamento deve alcançar.
  vm "cat > /tmp/alvopf.py <<'PYEOF'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        corpo = b'servidor interno'
        self.send_response(200); self.send_header('Content-Length', str(len(corpo))); self.end_headers(); self.wfile.write(corpo)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('192.168.99.2', 18095), H).serve_forever()
PYEOF
      ip netns exec lanp setsid python3 /tmp/alvopf.py >/dev/null 2>&1 < /dev/null &
      sleep 1" >/dev/null 2>&1

  # P1 — a WAN entra pelo painel, e com ela a marcação de conexão e a tabela.
  local st
  st=$(status POST /api/links "$tok" '{"name":"WAN P","interface":"lg-wanp","gateway":"10.77.0.2","ip_address":"10.77.0.1","weight":1,"enabled":true,"monitor_hosts":"10.77.0.2","dns_test":"10.77.0.2"}')
  if [[ "$st" == "200" || "$st" == "201" ]]; then ok "WAN de teste cadastrada pelo painel"
  else bad "não consegui cadastrar a WAN de teste: $st"; return; fi
  sleep 2
  if vm "nft list chain inet linkguard conn_mark 2>/dev/null" | grep -q 'lg-wanp'; then
    ok "a marcação de conexão pegou a WAN nova"
  else bad "sem marcação de conexão para a WAN nova; a bateria não testaria o que quer"; fi

  # P2 — sanidade ANTES do encaminhamento: sem regra de DNAT, não responde.
  # Sem isto, um "responde" no P3 poderia ser qualquer outra coisa.
  local antes
  antes=$(vm "ip netns exec wanp curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://10.77.0.1:18095/ 2>/dev/null" | tr -d '\r')
  if [[ "$antes" != "200" ]]; then ok "sem encaminhamento, a porta não responde de fora ('${antes:-nada}')"
  else bad "a porta já respondia ANTES do encaminhamento: o P3 não prova nada"; fi

  # P3 — A ASSERÇÃO CENTRAL: o encaminhamento entrega ao host da LAN.
  st=$(status POST /api/portforward "$tok" '{"name":"servidor interno P","enabled":true,"proto":"tcp","interface":"lg-wanp","ext_port":18095,"dest_ip":"192.168.99.2","dest_port":18095}')
  if [[ "$st" != "200" && "$st" != "201" ]]; then bad "não consegui criar o encaminhamento: $st"; return; fi
  sleep 2
  # A chain de DNAT chama-se `prerouting_dnat` (nftables.DNATChain). A primeira
  # versão desta linha procurava numa chain "dnat" que não existe, e o
  # `2>/dev/null` transformava "chain inexistente" em "tradução ausente": o
  # teste acusava o produto por um nome errado dele mesmo — e acusava JUNTO com
  # a asserção de tráfego passando, o que já era a pista de que o errado era o
  # teste.
  if ! vm "nft list chain inet linkguard prerouting_dnat 2>/dev/null" | grep -q '192.168.99.2'; then
    bad "a tradução não chegou na chain de DNAT" "$(vm "nft list chain inet linkguard prerouting_dnat 2>&1" | tr '\n' ' ' | head -c 200)"
  fi
  local corpo
  corpo=$(vm "ip netns exec wanp curl -s --max-time 5 http://10.77.0.1:18095/ 2>/dev/null" | tr -d '\r')
  if [[ "$corpo" == "servidor interno" ]]; then
    ok "o encaminhamento entrega ao host da LAN pela WAN secundária"
  else
    bad "o encaminhamento não entregou ao host da LAN (resposta: '${corpo:-vazia}')" \
        "conn_mark: $(vm "nft list chain inet linkguard conn_mark 2>/dev/null" | tr -d '\r' | tr '\n' ' ' | head -c 200) | dnat: $(vm "nft list chain inet linkguard prerouting_dnat 2>&1" | tr -d '\r' | tr '\n' ' ' | head -c 200)"
  fi

  # P4 — e a regra de restauração casa SÓ a direção de resposta. É a asserção
  # estrutural que explica o P3: se ela voltar a casar as duas direções, o P3
  # quebra e esta linha diz por quê.
  local restaura
  restaura=$(vm "nft list chain inet linkguard conn_mark 2>/dev/null" | grep 'meta mark set ct mark' | tr -d '\r')
  if grep -q 'ct direction reply' <<<"$restaura"; then
    ok "a restauração de marca está limitada à direção de resposta"
  else bad "a restauração de marca casa as duas direções" "$restaura"; fi

  # Limpeza.
  local pfid
  pfid=$(body GET /api/portforward "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ls=d if isinstance(d,list) else d.get('forwards',[])
for f in ls:
    if f.get('dest_ip')=='192.168.99.2': print(f.get('id',''))" 2>/dev/null)
  [[ -n "$pfid" ]] && status DELETE /api/portforward "$tok" "{\"id\":\"$pfid\"}" >/dev/null 2>&1
  local lid
  lid=$(body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l['interface']=='lg-wanp': print(l['id'])" 2>/dev/null)
  [[ -n "$lid" ]] && status DELETE "/api/links/$lid" "$tok" >/dev/null 2>&1
  vm "pkill -f alvopf >/dev/null 2>&1
      ip netns del wanp 2>/dev/null; ip netns del lanp 2>/dev/null
      ip link del lg-wanp 2>/dev/null; ip link del lg-lanp 2>/dev/null
      rm -f /tmp/alvopf.py; true" >/dev/null 2>&1
}

# ─── Q. Fechar a gerência na WAN, e a rede que impede isso de virar tranca ───
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA, e ela é literalmente a tranca. Fechar as
# portas de gerência nas WANs é a única mutação do produto que corta o acesso de
# quem a fez SEM que ele perceba na hora: quem fecha estando na LAN não sente
# nada, porque a sessão dele não passa pela regra.
#
# Nesta VM o painel entra pela MESMA NIC que o auto-detect cadastra como WAN.
# Isso faz do arnês a cobaia perfeita: fechar aqui derruba o próprio arnês, que é
# exatamente o acidente que a janela de 90 segundos existe para desfazer.
#
# Por isso esta bateria é a ÚLTIMA: se a rede de segurança falhar, a VM fica
# inacessível, e nenhuma outra bateria paga por isso.
battery_fechar_gerencia() {
  head_ "Q. Fechar a gerência na WAN"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria Q não roda"; return; }

  # Precisa de pelo menos uma WAN cadastrada, senão a regra não existe.
  status POST /api/links/auto-detect "$tok" >/dev/null 2>&1
  sleep 2
  if ! vm "nft list chain inet linkguard input 2>/dev/null" | grep -q 'tcp dport'; then
    bad "sem liberação de gerência na chain; a bateria Q não tem o que fechar"; return
  fi

  # Q1 — a API confirma que a gerência está aberta antes de fechar.
  local aberta
  aberta=$(body GET /api/nftables/policy "$tok" | python3 -c "
import json,sys
print((json.loads(sys.stdin.read()).get('exposure') or {}).get('management_open_on_wan'))" 2>/dev/null)
  if [[ "$aberta" == "True" ]]; then ok "a tela diz que a gerência está aberta na WAN"
  else bad "a tela não reconhece a gerência aberta ('$aberta')"; return; fi

  # Q2 — fechar. A resposta volta pela conexão já estabelecida, então o 200
  # chega mesmo com a porta fechando para conexões NOVAS.
  # Q2b — a estrutura é afirmada ENQUANTO AINDA DÁ PARA PERGUNTAR.
  local antes
  antes=$(vm "nft list chain inet linkguard input 2>/dev/null" | tr -d '\r')
  if grep -q 'tcp dport' <<<"$antes" && grep -q 'ct state new counter.*drop' <<<"$antes"; then
    ok "antes de fechar: liberação e descarte estão os dois na chain"
  else bad "a chain não está no estado esperado antes de fechar" "$(tr '\n' ' ' <<<"$antes" | head -c 200)"; fi

  local st
  st=$(status PUT /api/nftables/wan-management "$tok" '{"closed":true}')
  if [[ "$st" == "200" ]]; then ok "o painel aceitou fechar a gerência ($st)"
  else bad "não consegui fechar a gerência: $st"; return; fi
  sleep 2

  # Q3 — NÃO EXISTE, E A RAZÃO É A DESCOBERTA DESTA BATERIA.
  #
  # A primeira versão lia a chain aqui, com a gerência já fechada, para afirmar
  # que a liberação saiu e o descarte ficou. Só que "gerência" inclui o SSH: o
  # `vm` desta bateria entra pela porta 22 da MESMA WAN, e ele morre junto. A
  # leitura devolvia string vazia, e sobre string vazia o `! grep -q 'tcp dport'`
  # PASSA — a asserção "a liberação saiu" ficava verde por não ter medido nada,
  # enquanto a irmã dela falhava e denunciava as duas.
  #
  # Ou seja: enquanto está fechado, esta bateria não alcança a máquina para
  # perguntar nada. É por isso que a estrutura da chain é afirmada ANTES (Q2b) e
  # DEPOIS da reversão (Q6b), e o que se mede DURANTE é só o comportamento — que
  # é justamente o que não depende de alcançar a máquina.
  #
  # Isso também é um fato do produto, e não um detalhe de teste: fechar a
  # gerência fecha o SSH junto. A tela diz isso com todas as letras.

  # Q4 — A TRANCA, MEDIDA: uma conexão NOVA ao painel não passa mais.
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$API/api/health" 2>/dev/null)
  if [[ "$code" != "200" ]]; then ok "conexão nova ao painel não passa mais pela WAN ('${code:-nada}')"
  else bad "o painel continuou respondendo pela WAN: o fechamento não valeu"; fi

  # Q5 — A REDE DE SEGURANÇA. Ninguém confirma, e a janela de 90 segundos tem
  # de desfazer sozinha. Sem o flag no stateSnapshot da reversão, é aqui que a
  # VM fica inacessível para sempre — que é exatamente o defeito que o campo
  # WANMgmtClosed existe para impedir.
  printf '       (esperando a janela de 90s vencer sem confirmar — a reversão é a asserção)\n'
  local voltou=""
  local i
  for i in $(seq 1 24); do
    sleep 10
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "$API/api/health" 2>/dev/null)
    if [[ "$code" == "200" ]]; then voltou="$((i*10))s"; break; fi
  done
  if [[ -n "$voltou" ]]; then
    ok "a reversão automática devolveu o acesso sozinha (em ~$voltou)"
  else
    bad "A JANELA VENCEU E O ACESSO NÃO VOLTOU: a reversão não desfaz o fechamento" \
        "é o defeito que o campo WANMgmtClosed no stateSnapshot existe para impedir; a VM está inacessível"
    return
  fi

  # Q6 — e o estado no banco voltou junto, não só a chain.
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  local depois
  depois=$(body GET /api/nftables/policy "$tok" | python3 -c "
import json,sys
print((json.loads(sys.stdin.read()).get('exposure') or {}).get('management_open_on_wan'))" 2>/dev/null)
  if [[ "$depois" == "True" ]]; then ok "a tela voltou a dizer que a gerência está aberta"
  else bad "a chain voltou mas a tela ainda diz fechada ('$depois'): banco e firewall discordam"; fi

  # Q6b — e a chain voltou INTEIRA, não só a liberação. Agora dá para perguntar
  # de novo, que é o motivo de esta asserção estar aqui e não lá em cima.
  local final
  final=$(vm "nft list chain inet linkguard input 2>/dev/null" | tr -d '\r')
  if grep -q 'tcp dport' <<<"$final" && grep -q 'ct state new counter.*drop' <<<"$final"; then
    ok "depois da reversão: liberação de volta E descarte preservado"
  else bad "a chain não voltou inteira depois da reversão" "$(tr '\n' ' ' <<<"$final" | head -c 200)"; fi
}

# ─── R. Reserva de DHCP que trava tudo (issue #152) ──────────────────────────
#
# A FORMA DO DEFEITO, e é a que interessa mais que o campo: a API aceitava um
# valor que o `kea-dhcp4` recusa depois. Como o apply é assíncrono, o handler já
# tinha respondido 200 — e o valor FICAVA no banco, refeito em todo apply
# seguinte. O estrago não era uma requisição perdida: era o subsistema de
# DHCP/DNS inteiro parado, com a única mensagem disponível sendo a do kea, que
# não nomeia a reserva culpada.
#
# Ficou mais provável por causa da #119: a tela de Hosts passou a mostrar o
# endereço IPv6 de um aparelho, e é de lá que o admin copia o endereço.
battery_reserva_dhcp() {
  head_ "R. Reserva de DHCP que trava tudo"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria R não roda"; return; }

  # R1 — o endereço IPv6 é recusado NA HORA, com 400.
  local st
  st=$(status POST /api/dhcp/reservations "$tok" '{"mac":"aa:bb:cc:dd:ee:52","ip":"fd00::52","hostname":"teste152"}')
  if [[ "$st" == "400" ]]; then ok "reserva com endereço IPv6 é recusada na hora (400)"
  else bad "reserva IPv6 aceita com HTTP $st — o apply de DHCP/DNS travaria a partir daqui"; fi

  # R2 — e a mensagem diz POR QUE, não só "inválido". O admin acabou de copiar
  # esse endereço da tela de Hosts; "IP inválido" o mandaria conferir a digitação.
  local corpo
  corpo=$(body POST /api/dhcp/reservations "$tok" '{"mac":"aa:bb:cc:dd:ee:52","ip":"fd00::52","hostname":"teste152"}')
  # A mensagem tem de falar de FAMÍLIA, não de sub-rede: o admin acabou de
  # copiar esse endereço da tela de Hosts. Dizer "fora da sub-rede" sobre um
  # IPv6 é tecnicamente verdade e inútil — manda conferir a coisa errada.
  if grep -qi "IPv4" <<<"$corpo"; then ok "a mensagem explica que a reserva precisa ser IPv4"
  else bad "a mensagem não explica o motivo" "$(head -c 160 <<<"$corpo")"; fi

  # R3 — o IPv4 continua entrando. Sem isto, a guarda poderia estar recusando
  # tudo e as duas asserções acima passariam do mesmo jeito.
  st=$(status POST /api/dhcp/reservations "$tok" '{"mac":"aa:bb:cc:dd:ee:53","ip":"192.168.3.153","hostname":"ok152"}')
  if [[ "$st" == "200" || "$st" == "201" ]]; then ok "reserva IPv4 continua sendo aceita ($st)"
  else bad "a guarda recusou também o IPv4: $st"; fi

  # R4 — e o DHCP continua aplicando depois de tudo isso. É a asserção que mede
  # o dano real do defeito: não é a requisição recusada, é o subsistema parado.
  sleep 4
  local kea
  kea=$(vm "systemctl is-active kea-dhcp4-server 2>/dev/null" | tr -d '\r')
  if [[ "$kea" == "active" ]]; then ok "o servidor de DHCP continua de pé depois das tentativas"
  else bad "o DHCP não está ativo depois da bateria ('$kea')"; fi
  # A VM NÃO TEM A INTERFACE DE LAN DE FÁBRICA (br10), então o kea recusa a
  # config por um motivo que não tem nada a ver com a reserva:
  # "Failed to select interface: interface 'br10' doesn't exist". Exigir que a
  # reserva chegue na config aqui seria cobrar do produto uma coisa que o
  # ambiente impede — e a asserção falharia para sempre, ensinando a ignorá-la.
  local lan_existe
  lan_existe=$(vm "ip -o link show br10 2>/dev/null | wc -l" | tr -d '\r')
  if [[ "${lan_existe:-0}" == "0" ]]; then
    ok "a reserva foi aceita (esta VM não tem a interface de LAN, então o Kea não aplica — fora do escopo desta bateria)"
  elif vm "grep -q '192.168.3.153' /etc/kea/kea-dhcp4.conf" 2>/dev/null; then
    ok "a reserva boa chegou na config do Kea"
  else
    bad "a reserva IPv4 não chegou na config do Kea" \
        "último apply: $(body GET /api/dhcp "$tok" | python3 -c "
import json,sys
d=(json.load(sys.stdin).get('last_apply') or {})
print(('ok' if d.get('ok') else 'FALHOU') + ' ' + (d.get('error') or d.get('warning') or ''))" 2>/dev/null | head -c 200)"
  fi

  # R5 — a família da #161: valor bem formado que o daemon recusa depois.
  # Cada um destes travava TODO apply de DHCP/DNS, e o do gateway derrubava o
  # DNS da rede — os arquivos eram escritos e o unbound morria sem conseguir
  # escutar.
  local caso desc
  for caso in     'ip-fora-da-subrede|{"mac":"aa:bb:cc:dd:ee:54","ip":"10.9.9.9","hostname":"fora"}|/api/dhcp/reservations'     'mac-do-windows|{"mac":"aa-bb-cc-dd-ee-55","ip":"192.168.3.155","hostname":"win"}|/api/dhcp/reservations'
  do
    desc="${caso%%|*}"; local resto="${caso#*|}"; local corpo_req="${resto%%|*}"; local rota="${resto##*|}"
    st=$(status POST "$rota" "$tok" "$corpo_req")
    if [[ "$st" == "400" ]]; then ok "recusado na hora: $desc"
    else bad "$desc foi aceito (HTTP $st) — travaria todo apply de DHCP/DNS"; fi
  done

  # R6 — O QUE DERRUBA: gateway num endereço que a máquina não tem.
  local atual
  # GET /api/dhcp, e não /api/dhcp/config — o PUT é que tem o sufixo. Com a
  # rota errada o corpo vinha vazio, o python quebrava, o PUT ia com lixo e
  # tomava 400: a asserção PASSAVA pelo motivo errado.
  atual=$(body GET /api/dhcp "$tok" | python3 -c "
import json,sys
print(json.dumps(json.load(sys.stdin).get('config') or {}))" 2>/dev/null)
  local sub
  sub=$(jqk subnet_cidr <<<"$atual")
  st=$(status PUT /api/dhcp/config "$tok" "$(python3 -c "
import json,sys
d=json.loads(sys.argv[1]); d['gateway']='203.0.113.9'
print(json.dumps(d))" "$atual")")
  if [[ "$st" == "400" ]]; then ok "gateway fora da sub-rede é recusado antes de escrever"
  else bad "gateway inalcançável aceito (HTTP $st) — o unbound morreria e a LAN ficaria sem DNS"; fi

  # R7 — e o DNS continua de pé depois de todas as tentativas. É a asserção que
  # mede o dano real: não é a requisição recusada, é o serviço que não pode cair.
  sleep 3
  local unb
  unb=$(vm "systemctl is-active unbound 2>/dev/null" | tr -d '\r')
  if [[ "$unb" == "active" ]]; then ok "o servidor de DNS continua de pé (sub-rede $sub)"
  else bad "o unbound não está ativo depois da bateria ('$unb')"; fi

  status DELETE /api/dhcp/reservations "$tok" '{"mac":"aa:bb:cc:dd:ee:53"}' >/dev/null 2>&1
}

# ─── S. Contenção de tentativa repetida (issue #127) ─────────────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. Contenção por taxa que pega o próprio
# admin é tranca com outro nome, e este projeto já pagou por uma hoje (a fase 1
# da #119, que trancou a VM ao clicar em "detectar links").
#
# Aqui o risco não é mitigado, é ELIMINADO por construção: a regra que ADICIONA
# ao set casa `iifname` das WANs, então origem que entra pela LAN não pode ser
# contida por caminho nenhum. A bateria prova as duas metades — que quem
# martela de fora é contido, e que quem vem de dentro não é, por mais que
# martele.
#
# `limit rate over` casa o EXCEDENTE; `limit rate` sem o `over` casa o que CABE
# na taxa. Trocar um pelo outro conteria exatamente quem se comporta.
battery_contencao() {
  head_ "S. Contenção de tentativa repetida"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria S não roda"; return; }

  status POST /api/links/auto-detect "$tok" >/dev/null 2>&1
  sleep 2

  # S0 — DESLIGADA POR PADRÃO, e esta asserção é a mais importante da bateria.
  #
  # Ela nasceu LIGADA, e a execução da v1.0.157 mostrou o custo: o próprio arnês
  # faz centenas de chamadas de API, cada uma uma conexão nova pela NIC que o
  # auto-detect classifica como WAN. Excedeu a taxa, se conteve sozinho, e a
  # suíte inteira caiu a partir da bateria F — 20 falhas em cascata, todas
  # "sem sessão administrativa".
  #
  # No nível do firewall não dá para distinguir automação legítima de varredura
  # só pela taxa. Este produto já decidiu, no survival.go, que não trancar o
  # admin vale mais do que fechar tudo.
  local chain0
  chain0=$(vm "nft list chain inet linkguard input 2>/dev/null" | tr -d '\r')
  if ! grep -q 'add @abusers' <<<"$chain0"; then
    ok "a contenção nasce DESLIGADA: nenhuma regra a alimenta"
  else bad "a contenção veio ligada de fábrica — foi assim que o arnês se trancou"; fi

  # S3 — A ASSERÇÃO CENTRAL, LADO DE FORA: martelar pela WAN contém.
  vm "ip netns del lgabus 2>/dev/null; ip link del lg-abus 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add lgabus && \
      ip link add lg-abus type veth peer name abus-far && \
      ip link set abus-far netns lgabus && \
      ip addr add 198.18.0.1/24 dev lg-abus && ip link set lg-abus up && \
      ip netns exec lgabus ip link set lo up && \
      ip netns exec lgabus ip addr add 198.18.0.2/24 dev abus-far && \
      ip netns exec lgabus ip link set abus-far up" >/dev/null 2>&1
  local st
  st=$(status POST /api/links "$tok" '{"name":"WAN abuso","interface":"lg-abus","gateway":"198.18.0.2","ip_address":"198.18.0.1","weight":1,"enabled":true,"monitor_hosts":"198.18.0.2","dns_test":"198.18.0.2"}')
  if [[ "$st" != "200" && "$st" != "201" ]]; then bad "não consegui cadastrar a WAN de abuso: $st"; return; fi
  sleep 2

  # ISOLAMENTO DEPOIS DE A WAN DE MENTIRA EXISTIR, e a ordem é o erro que a
  # execução da v1.0.160 pegou: desligar os links detectados ANTES de cadastrar
  # a lg-abus deixava a caixa sem WAN nenhuma — e sem WAN a proteção de entrada
  # não emite regra, então as quatro asserções seguintes falhavam dizendo que a
  # contenção não existia. Ela não existia porque não havia o que proteger.
  #
  # O isolamento em si continua necessário: com a contenção ligada, o próprio
  # arnês seria contido, porque fala com o painel pela NIC que o auto-detect
  # cadastra como WAN e faz centenas de chamadas.
  local detectados id
  detectados=$(body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l.get('enabled') and l.get('interface')!='lg-abus': print(l['id'])" 2>/dev/null)
  for id in $detectados; do
    local atual
    atual=$(body GET "/api/links/$id" "$tok")
    python3 -c "
import json,sys
d=json.loads(sys.argv[1]); d['enabled']=False
print(json.dumps(d))" "$atual" > /tmp/lgv_link.json 2>/dev/null
    status PUT "/api/links/$id" "$tok" "$(cat /tmp/lgv_link.json)" >/dev/null 2>&1
  done

  # Agora sim, LIGADA de propósito, para medir o que ela faz.
  status PUT /api/nftables/edge-containment "$tok" '{"enabled":true}' >/dev/null
  sleep 2

  local chain
  chain=$(vm "nft list chain inet linkguard input 2>/dev/null" | tr -d '\r')

  # S1 — o set existe e a regra que a alimenta está na chain, escopada por WAN.
  if vm "nft list set inet linkguard abusers" >/dev/null 2>&1; then ok "a set de contenção existe"
  else bad "a set de contenção não existe: a regra que a referencia sumiria da chain"; fi
  local add
  add=$(grep 'add @abusers' <<<"$chain")
  if [[ -n "$add" ]]; then ok "a regra que contém está na chain"
  else bad "nenhuma regra alimenta a contenção" "$(tr '\n' ' ' <<<"$chain" | head -c 200)"; fi
  if grep -q '^\s*iifname' <<<"$add"; then ok "a regra que contém é escopada por interface de WAN"
  else bad "a regra que contém NÃO é escopada: o admin da LAN pode ser contido" "$add"; fi
  if grep -q 'limit rate over' <<<"$add"; then ok "o limite casa o excedente, e não quem cabe na taxa"
  else bad "o limite está invertido: conteria quem se comporta" "$add"; fi

  # S2 — a ordem: o descarte de contido vem ANTES da liberação de gerência.
  local i_drop i_accept
  i_drop=$(grep -n 'ip saddr @abusers' <<<"$chain" | head -1 | cut -d: -f1)
  # O nft imprime `counter packets N bytes N accept` — casar "counter accept"
  # não encontra nada, e o índice vazio virava "a ordem está errada", acusando o
  # produto por um erro de leitura.
  i_accept=$(grep -n 'tcp dport {.*accept' <<<"$chain" | head -1 | cut -d: -f1)
  if [[ -n "$i_drop" && -n "$i_accept" && "$i_drop" -lt "$i_accept" ]]; then
    ok "o descarte de contido vem antes da liberação de gerência ($i_drop < $i_accept)"
  else bad "a ordem está errada (descarte $i_drop, liberação $i_accept)" "$(tr '\n' ' ' <<<"$chain" | head -c 220)"; fi

  # 25 conexões novas em rajada, muito acima de 10/minuto.
  vm "ip netns exec lgabus sh -c 'for i in \$(seq 1 25); do timeout 1 bash -c \"exec 3<>/dev/tcp/198.18.0.1/9997\" 2>/dev/null; done'" >/dev/null 2>&1
  sleep 2
  if vm "nft list set inet linkguard abusers" | grep -q '198.18.0.2'; then
    ok "quem martela pela WAN é contido"
  else bad "a origem não foi contida depois de 25 conexões" "$(vm "nft list set inet linkguard abusers" | tr -d '\r' | tr '\n' ' ' | head -c 200)"; fi

  # S4 — A OUTRA METADE, E A QUE IMPORTA MAIS: martelar pela LAN NÃO contém.
  # É esta propriedade que torna seguro ligar a contenção sem o admin pedir.
  local antes_lan
  antes_lan=$(vm "nft list set inet linkguard abusers" | grep -c 'elements' || true)
  vm "for i in \$(seq 1 40); do timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9997' 2>/dev/null; done" >/dev/null 2>&1
  sleep 2
  if ! vm "nft list set inet linkguard abusers" | grep -qE '127\.0\.0\.1|192\.168\.'; then
    ok "40 conexões pela rede interna e ninguém de dentro foi contido"
  else bad "UMA ORIGEM INTERNA FOI CONTIDA: é tranca do admin com outro nome" "$(vm "nft list set inet linkguard abusers" | tr -d '\r' | tr '\n' ' ' | head -c 200)"; fi

  # S5 — o painel mostra quem está contido, com prazo. Bloqueio invisível é o
  # pior tipo de suporte.
  local n
  n=$(body GET /api/nftables/abusers "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin).get('contidos') or []
print(len([c for c in d if c.get('ip')=='198.18.0.2' and c.get('expira_em_seg',0)>0]))" 2>/dev/null)
  if [[ "${n:-0}" == "1" ]]; then ok "o painel mostra a origem contida com prazo restante"
  else bad "o painel não mostra a contenção" "$(body GET /api/nftables/abusers "$tok" | head -c 200)"; fi

  # S6 — e dá para liberar.
  status DELETE /api/nftables/abusers "$tok" '{"ip":"198.18.0.2"}' >/dev/null
  sleep 1
  if ! vm "nft list set inet linkguard abusers" | grep -q '198.18.0.2'; then
    ok "liberar tira a origem da contenção"
  else bad "a origem continuou contida depois de liberar"; fi

  # S7 — e DESLIGAR tira as regras da chain. Sem isto, a bateria deixaria a
  # contenção ligada para as baterias seguintes, que fazem exatamente o tipo de
  # chamada que dispara a contenção — que foi como esta suíte se trancou.
  status PUT /api/nftables/edge-containment "$tok" '{"enabled":false}' >/dev/null
  sleep 2
  if ! vm "nft list chain inet linkguard input 2>/dev/null" | grep -q 'add @abusers'; then
    ok "desligar tira a contenção da chain"
  else bad "a contenção continuou na chain depois de desligada"; fi

  local lid
  lid=$(body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l['interface']=='lg-abus': print(l['id'])" 2>/dev/null)
  [[ -n "$lid" ]] && status DELETE "/api/links/$lid" "$tok" >/dev/null 2>&1
  vm "ip netns del lgabus 2>/dev/null; ip link del lg-abus 2>/dev/null; true" >/dev/null 2>&1

  # Religa os links detectados: as baterias seguintes contam com eles. A
  # contenção já foi desligada acima, então religar não tranca ninguém.
  for id in $detectados; do
    local volta
    volta=$(body GET "/api/links/$id" "$tok")
    python3 -c "
import json,sys
d=json.loads(sys.argv[1]); d['enabled']=True
print(json.dumps(d))" "$volta" > /tmp/lgv_link.json 2>/dev/null
    status PUT "/api/links/$id" "$tok" "$(cat /tmp/lgv_link.json)" >/dev/null 2>&1
  done
}

# ─── T. Mapa endereço → nome (issue #116) ────────────────────────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. O produto sabia que alguém perguntou por
# um site e não sabia qual endereço foi devolvido — então todo destino em toda
# tela era número. Esta bateria prova o caminho inteiro numa máquina de verdade:
# o unbound entrega a RESPOSTA por dnstap, o coletor lê três formatos que o
# produto não conhecia (Frame Streams, protobuf e o fio do DNS), e o mapa passa
# a saber o nome daquele endereço.
#
# E prova o outro lado, que é o que torna a asserção honesta: DESLIGADO, o mapa
# fica vazio. Sem essa metade, "o mapa tem entradas" poderia significar qualquer
# coisa.
battery_mapa_dns() {
  head_ "T. Mapa endereço → nome"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria T não roda"; return; }

  # T0 — o unbound desta caixa tem dnstap? A issue exige medir, não supor.
  if vm "/usr/sbin/unbound -V 2>&1 | grep -q enable-dnstap"; then
    ok "o unbound desta máquina foi compilado com dnstap"
  else
    bad "o unbound não tem dnstap; o recurso não pode funcionar aqui" \
        "$(vm "/usr/sbin/unbound -V 2>&1 | head -3" | tr -d '\r' | tr '\n' ' ' | head -c 200)"
    return
  fi

  # T1 — DESLIGADO, o mapa está vazio e a tela diz isso.
  local resp
  resp=$(body GET /api/dns/mapa "$tok")
  local ligado
  ligado=$(python3 -c "
import json,sys
print(json.loads(sys.argv[1]).get('ligado'))" "$resp" 2>/dev/null)
  if [[ "$ligado" == "False" ]]; then ok "desligado por padrão, como a issue exige"
  else bad "o recurso veio ligado de fábrica ('$ligado')"; fi

  # T2 — ligar escreve o bloco no unbound.conf.
  local st
  st=$(status PUT /api/dns/config "$tok" '{"upstreams":[],"log_queries":false,"force_local_dns":false,"block_dot":false,"dns_except_ips":[],"dnstap_enabled":true}')
  if [[ "$st" != "200" ]]; then bad "não consegui ligar o recurso: $st"; return; fi
  sleep 6
  if vm "grep -q 'dnstap-enable: yes' /etc/unbound/unbound.conf.d/*.conf 2>/dev/null"; then
    ok "o bloco de dnstap foi escrito na configuração do unbound"
  else
    bad "o bloco não chegou no unbound.conf" \
        "$(vm "grep -c dnstap /etc/unbound/unbound.conf.d/*.conf 2>/dev/null" | tr -d '\r')"
  fi

  # T3 — o coletor está ouvindo, E o AppArmor autoriza o unbound a chegar lá.
  #
  # As duas asserções andam juntas porque separadas mentem: o socket pode estar
  # de pé e o unbound ser recusado pelo AppArmor sem que nada apareça no log de
  # nenhum dos dois. O perfil de fábrica permite exatamente três caminhos em
  # /run, e nenhum é de dnstap — nem o que o pacote compilou por padrão.
  if vm "ls -l /run/linkguard-fw/dnstap.sock 2>/dev/null | grep -q srw"; then
    ok "o coletor está ouvindo em /run/linkguard-fw/dnstap.sock"
  else
    bad "o socket do coletor não existe: o unbound não tem onde entregar" \
        "$(vm "journalctl -u linkguard-fw --since '5 min ago' --no-pager | grep -i dnstap | tail -1" | tr -d '\r' | head -c 200)"
  fi
  if vm "grep -q 'dnstap.sock' /etc/apparmor.d/local/usr.sbin.unbound 2>/dev/null"; then
    ok "o AppArmor do unbound foi autorizado no ponto de extensão local"
  else bad "sem a regra de AppArmor o unbound é recusado em silêncio pelo kernel"; fi

  # T4 — A ASSERÇÃO CENTRAL: uma consulta de verdade vira nome no mapa.
  # O domínio é resolvido pelo próprio unbound da caixa, e o nome perguntado tem
  # de aparecer no mapa associado a um endereço.
  # A CONSULTA VAI DIRETO AO UNBOUND, e não pelo resolvedor da caixa.
  #
  # A primeira versão usava `getent hosts`, que passa pelo /etc/resolv.conf — e
  # nesta VM ele aponta para 127.0.0.53, o systemd-resolved. A consulta NUNCA
  # chegava ao unbound, e a asserção falhava dizendo que o dnstap não entregou.
  # Medido: o unbound escuta em 127.0.0.1:53 e responde normalmente.
  #
  # Perguntar direto ao resolver do produto é o que um aparelho da LAN faz, e é
  # o único jeito de esta asserção medir o dnstap em vez de medir o resolvedor
  # do sistema operacional.
  #
  # E a consulta é MEDIDA, não suposta. O unbound recém-reiniciado gasta a
  # primeira consulta fazendo priming da raiz e validando o DNSSEC, e responde
  # só a partir da segunda. Sem separar "o unbound não respondeu" de "o dnstap
  # não entregou", uma VM sem saída para a internet reprova a bateria acusando
  # o coletor de um problema que é de rede.
  local respondeu
  respondeu=$(vm "cat > /tmp/lgq.py <<'PYEOF'
import socket
q = bytes.fromhex(\"abcd01000001000000000000036465620664656269616e036f72670000010001\")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(6)
n = 0
for _ in range(6):
    s.sendto(q, (\"127.0.0.1\", 53))
    try:
        r, _ = s.recvfrom(4096)
        n += 1
    except Exception:
        pass
print(n)
PYEOF
python3 /tmp/lgq.py; rm -f /tmp/lgq.py" | tr -d '\r' | tail -1)
  if [[ "${respondeu:-0}" -gt 0 ]]; then
    ok "o unbound da caixa respondeu a consulta ($respondeu de 6)"
  else
    bad "o unbound não respondeu; sem resposta não há CLIENT_RESPONSE para o dnstap entregar" \
        "$(vm "journalctl -u unbound --since '2 min ago' --no-pager | tail -3" | tr -d '\r' | head -c 300)"
  fi
  sleep 3
  if [[ "${respondeu:-0}" -gt 0 ]]; then
    local achou
    achou=$(body GET /api/dns/mapa "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(len([e for e in (d.get('amostra') or []) if 'debian' in (e.get('nome') or '')]))" 2>/dev/null)
    if [[ "${achou:-0}" -gt 0 ]]; then
      ok "uma consulta de verdade virou nome no mapa ($achou entrada(s))"
    else
      bad "a consulta não chegou ao mapa" \
          "estado: $(body GET /api/dns/mapa "$tok" | head -c 200)"
    fi
  fi

  # T5 — e desligar para de escrever o bloco.
  status PUT /api/dns/config "$tok" '{"upstreams":[],"log_queries":false,"force_local_dns":false,"block_dot":false,"dns_except_ips":[],"dnstap_enabled":false}' >/dev/null
  sleep 6
  if ! vm "grep -q 'dnstap-enable: yes' /etc/unbound/unbound.conf.d/*.conf 2>/dev/null"; then
    ok "desligar tira o bloco da configuração"
  else bad "o bloco continuou no unbound.conf depois de desligado"; fi
}

# ─── U. Métricas por aparelho para o coletor (issue #118) ────────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. A issue pedia publicar endereço físico e
# consumo por aparelho no /metrics — que é ABERTO e que esta própria suíte exige
# que responda pela WAN (bateria N: fechar a porta do painel é tranca). Isso
# seria um endpoint público de inventário da rede do cliente.
#
# A entrega é a intenção da issue sem o endereço errado: as séries existem, em
# rota própria e por token. Então a bateria prova as DUAS metades — que o
# inventário NÃO sai pelo aberto, e que sai pelo autenticado.
battery_metricas_host() {
  head_ "U. Métricas por aparelho"

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  [[ -n "$tok" ]] || { bad "sem sessão administrativa; a bateria U não roda"; return; }

  # U1 — A ASSERÇÃO DE SEGURANÇA: o /metrics aberto não tem identidade de
  # aparelho. Vale mesmo com a feature ligada, porque as séries vivem fora do
  # registro aberto — ausentes por construção, não filtradas na saída.
  local aberto
  aberto=$(curl -s --max-time 6 "$API/metrics" 2>/dev/null)
  if [[ -z "$aberto" ]]; then bad "o /metrics não respondeu; a bateria U não pode afirmar nada"; return; fi
  if ! grep -qE 'mac=|linkguard_host_' <<<"$aberto"; then
    ok "o /metrics aberto não publica identidade de aparelho"
  else
    bad "INVENTÁRIO DA REDE NO /metrics SEM AUTENTICAÇÃO" "$(grep -E 'mac=|linkguard_host_' <<<"$aberto" | head -2)"
  fi
  # E continua servindo o que sempre serviu: sem isto, "não tem identidade"
  # passaria também com o endpoint quebrado.
  if grep -q 'linkguard_' <<<"$aberto"; then ok "o /metrics aberto continua servindo as métricas agregadas"
  else bad "o /metrics não serve mais nada" "$(head -c 150 <<<"$aberto")"; fi

  # U2 — sem token configurado, a rota por aparelho NÃO EXISTE. 404, e não 403:
  # responder "não autorizado" confirmaria que há algo ali.
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$API/api/metrics/hosts" 2>/dev/null)
  if [[ "$code" == "404" ]]; then ok "sem token, a rota por aparelho não existe (404)"
  else bad "a rota respondeu $code sem token configurado"; fi

  # U3 — o token é configurado PELO PRODUTO, e não por dentro do banco.
  #
  # A primeira versão desta bateria escrevia direto no SQLite e pulava as
  # asserções quando não havia sqlite3 na VM — e foi assim que ela mostrou que
  # eu tinha entregado a #118 SEM NENHUMA ROTA para definir o token. Um recurso
  # opt-in sem caminho para o opt-in é um recurso desligado com trabalho extra.
  local st
  st=$(status PUT /api/metrics/hosts/token "$tok" '{"token":"curto"}')
  if [[ "$st" == "400" ]]; then ok "token curto é recusado (ele dá acesso à lista de aparelhos)"
  else bad "token de 5 caracteres aceito ($st)"; fi

  st=$(status PUT /api/metrics/hosts/token "$tok" '{"token":"tok-da-bateria-u-com-tamanho"}')
  if [[ "$st" == "200" ]]; then ok "o token é definido pela API do produto"
  else bad "não consegui definir o token: $st"; return; fi
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H "Authorization: Bearer errado" "$API/api/metrics/hosts" 2>/dev/null)
  if [[ "$code" == "401" ]]; then ok "token errado é recusado (401)"
  else bad "token errado respondeu $code"; fi

  local corpo
  corpo=$(curl -s --max-time 6 -H "Authorization: Bearer tok-da-bateria-u-com-tamanho" "$API/api/metrics/hosts" 2>/dev/null)
  if grep -q 'linkguard_host_rx_bytes_per_second' <<<"$corpo"; then
    ok "com o token certo, as séries por aparelho são servidas"
  else bad "a rota autenticada não serviu as séries" "$(head -c 200 <<<"$corpo")"; fi

  # U5 — e desligar é tão alcançável quanto ligar: token vazio apaga.
  status PUT /api/metrics/hosts/token "$tok" '{"token":""}' >/dev/null
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H "Authorization: Bearer tok-da-bateria-u-com-tamanho" "$API/api/metrics/hosts" 2>/dev/null)
  if [[ "$code" == "404" ]]; then ok "apagar o token desliga a rota (404)"
  else bad "a rota continuou respondendo depois de apagar o token ($code)"; fi
}

# ─── V. Alertas de comportamento por aparelho (issue #117) ───────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. Detector de desvio é fácil de escrever e
# fácil de entregar MUDO: ele só fala quando o histórico real da caixa tem a
# forma que ele espera, e o teste em Go semeia essa forma com a própria mão. Os
# testes da #117 escreviam amostras num passo escolhido por eles e conferiam que o
# detector alertou — provam a aritmética da mediana, não que exista aparelho no
# mundo capaz de disparar isto.
#
# Por isso a bateria abre com a pergunta que teste de unidade nenhum faz: o
# passo que o detector CONSULTA é um passo que o produto GRAVA sozinho? (V2.) Foi
# essa pergunta que achou o defeito: o detector pedia 300 segundos e o tsdb
# grava host.* em 10, 60, 900 e 3600 — o alerta nunca pôde sair. E
# ela não pergunta isso olhando o banco de qualquer jeito — gera tráfego que
# ATRAVESSA o firewall, do jeito que a bateria G gera, e pergunta quais passos
# apareceram PARA AQUELE APARELHO na última hora. Assim a resposta é do produto
# desta rodada, e não de restos de uma execução anterior nem da ordem em que as
# baterias rodaram.
#
# Depois vêm as asserções da issue, e as DUAS DE SILÊNCIO são o que torna as
# outras honestas:
#
#   V1 — aparelho que o produto nunca viu vira alerta. Esta metade não é
#        semeada: um aparelho de mentira aparece na vizinhança e o avistamento é
#        gravado pelo caminho do próprio produto (GET /api/hosts).
#   V3 — consumo acima do próprio normal daquela hora vira alerta.
#   V4 — O PISO CALA. Um aparelho que faz DEZ vezes o normal dele e mesmo assim
#        não chega a 2 MB/s não pode gerar nada. Só que "ficou calado" não prova
#        piso nenhum se o detector estiver morto — quando `consumo()` desiste
#        por falta de amostras, ELE CALA PARA TODO MUNDO. Por isso a V4 só é
#        cobrada quando a V3 disparou na mesma passada; sem isso, ela é PULADA.
#   V6 — A HISTERESE CALA. Segundo pico do mesmo aparelho dentro de 6 h não
#        vira segundo alerta. E para essa asserção não ser gratuita: o primeiro
#        alerta é RESOLVIDO antes (senão quem cala é o dedupe de alerta aberto,
#        não a histerese), uma testemunha é semeada para disparar NA MESMA
#        passada (silêncio sem testemunha só provaria que o detector parou) e o
#        PID do serviço é conferido no fim (a histerese vive na memória do
#        processo: um restart no meio a zera, e alertar de novo passa a ser o
#        comportamento CERTO — acusar o produto ali seria mentira).
#
# O passado não tem rota: nenhuma API do produto cria sete dias de histórico.
# Essa metade é semeada no banco da VM, e é a única coisa desta suíte escrita
# por baixo do produto — de propósito, e só o que é passado. Tudo o que é
# medição é lido por SQL também, e não pela lista de alertas do painel: a rota
# devolve as 100 mais recentes (handlers/alerts.go), e as três asserções de
# silêncio desta bateria são igualdades com uma linha de base — uma janela que
# empurra alertas para fora do fim transformaria "a histerese não segurou" em OK.
battery_comportamento() {
  head_ "V. Alertas de comportamento por aparelho"

  # Cada asserção tem um marcador. Quem sair pelo meio chama encerra_v, que
  # PULA por nome tudo o que não chegou a ser medido: uma bateria que aborta
  # calada deixa o resumo dizer "0 falhas" sobre asserção que nunca rodou.
  local M_V1=0 M_V2=0 M_V3=0 M_V4=0 M_V6=0
  local SCRIPT=/tmp/lgv117.py
  local BANCO="" mac_novo="" script_pronto=0
  local T_NOVO="host_novo_na_rede" T_ACIMA="host_acima_do_normal"

  # MACS SORTEADOS A CADA RODADA. A histerese do detector é um mapa em MEMÓRIA
  # do processo (6 h por aparelho) e não tem rota para ser limpa: com MACs
  # fixos, a segunda execução desta bateria na mesma caixa mediria o silêncio
  # que a primeira deixou e chamaria isso de defeito do produto. MAC novo por
  # rodada também tira do caminho o dedupe de alerta aberto e qualquer resto de
  # execução abortada.
  local suf; suf=$(printf '%02x:%02x' $((RANDOM % 256)) $((RANDOM % 256)))
  local ALTO="aa:bb:17:$suf:01" PISO="aa:bb:17:$suf:02" CTRL="aa:bb:17:$suf:03"

  # limpa_v desfaz o que a bateria montou. Ela é chamada de TODOS os caminhos de
  # saída, inclusive os que abortam cedo: o aparelho de mentira precisa sair do
  # inventário, senão a bateria seguinte enxerga um inventário que a rede não
  # tem. Cada pedaço é independente do outro — nada aqui pode depender de uma
  # etapa que talvez não tenha acontecido.
  limpa_v() {
    vm "ip netns del lgnovo 2>/dev/null; ip link del lg-novo 2>/dev/null; true" >/dev/null 2>&1
    [[ "$script_pronto" == 1 ]] || return 0
    # Os alertas desta bateria são fechados pelo caminho do painel, e em TODO
    # caminho de saída: alerta aberto sobre um MAC que não existe mais engorda a
    # contagem de abertos que outras baterias e o próprio painel leem.
    local tipo mac id lista
    if [[ -n "$tok" ]]; then
      for tipo in "$T_NOVO" "$T_ACIMA"; do
        for mac in "$ALTO" "$PISO" "$CTRL" ${mac_novo:+"$mac_novo"}; do
          lista=$(q1 abertos "$tipo" "$mac")
          [[ "$lista" == ABERTOS\ * && "$lista" != "ABERTOS -" ]] || continue
          for id in ${lista#ABERTOS }; do
            status PUT "/api/alerts/$id/resolve" "$tok" >/dev/null 2>&1
          done
        done
      done
    fi
    local sobra
    sobra=$(q1 limpa "$ALTO" "$PISO" "$CTRL" ${mac_novo:+"$mac_novo"})
    if [[ "$sobra" != "LIMPO 0" ]]; then
      bad "a limpeza da bateria V não terminou; a bateria seguinte pode ver aparelho que a rede não tem" "$sobra"
    fi
    vm "rm -f $SCRIPT" >/dev/null 2>&1
  }

  encerra_v() {
    local motivo="$1"
    [[ "$M_V1" == 1 ]] || pular "V1. Aparelho nunca visto vira alerta" "$motivo"
    [[ "$M_V2" == 1 ]] || pular "V2. O passo consultado é um passo que o produto grava" "$motivo"
    [[ "$M_V3" == 1 ]] || pular "V3. Consumo acima do próprio normal vira alerta" "$motivo"
    [[ "$M_V4" == 1 ]] || pular "V4. O piso absoluto cala o detector" "$motivo"
    [[ "$M_V6" == 1 ]] || pular "V6. A histerese cala o segundo pico" "$motivo"
    limpa_v
  }

  local initial tok
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  if [[ -z "$tok" ]]; then
    bad "sem sessão administrativa; a bateria V não roda"
    encerra_v "sem sessão administrativa"
    return
  fi

  # ── Portões de ambiente, ANTES de montar qualquer coisa ────────────────────
  #
  # O passado que o baseline exige não tem rota de API, e o único jeito de
  # escrevê-lo é o sqlite3 do python da VM. Perguntar isso depois de criar o
  # veth deixaria um aparelho fantasma no inventário sem nenhuma forma de
  # apagá-lo (não existe DELETE /api/hosts). E as duas ausências possíveis têm
  # consertos diferentes, então são diagnosticadas separadamente.
  local tem_py tem_sql
  tem_py=$(vm "command -v python3 >/dev/null 2>&1 && echo py" | tr -d '\r' | tail -1)
  if [[ "$tem_py" != "py" ]]; then
    bad "não há python3 na VM: o histórico por aparelho não tem como ser escrito nem lido"
    encerra_v "sem python3 na VM"
    return
  fi
  tem_sql=$(vm "python3 -c 'import sqlite3; print(\"sql\")' 2>/dev/null" | tr -d '\r' | tail -1)
  if [[ "$tem_sql" != "sql" ]]; then
    bad "o python3 da VM não tem o módulo sqlite3; o passado que o baseline exige não pode ser criado"
    encerra_v "python3 da VM sem o módulo sqlite3"
    return
  fi

  # O caminho do banco é o que o PRODUTO usa, e não um caminho cravado aqui: o
  # próprio arranjo desta suíte já edita config.json, então ele não é imutável.
  # Semear no banco errado imprimiria "o produto não alertou" sobre um banco que
  # o produto nunca leu.
  BANCO=$(vm "python3 -c \"import json;print(json.load(open('/etc/linkguard-fw/config.json')).get('db_path',''))\" 2>/dev/null" | tr -d '\r' | tail -1)
  [[ -n "$BANCO" ]] || BANCO="/var/lib/linkguard-fw/linkguard.db"

  # ── O ajudante que lê e semeia o banco da VM ───────────────────────────────
  #
  # Ele abre o banco com mode=rw: caminho errado ERRA, em vez de criar um .db
  # vazio e falhar depois com "no such table" dentro de um 2>/dev/null.
  # Toda saída é uma linha com prefixo conhecido — falha vira "ERRO ...", nunca
  # vira zero. Zero é justamente o valor que faz as asserções de silêncio
  # passarem, e uma leitura quebrada não pode virar uma asserção verde.
  vm "cat > $SCRIPT <<'PYEOF'
import sqlite3, sys, time

SERIE = 'host.rx_bps'
# PASSO tem de ser o mesmo de comportamento.PassoBaseline. Semear no passo
# errado faz o produto ficar calado COM RAZÃO e a bateria acusá-lo por isso —
# foi exatamente o defeito que a V2 pegou: o detector pedia 300, que o tsdb
# nunca grava. Do lado do Go, TestPassoBaselineExisteNoTSDB amarra a constante
# aos passos que o produtor da série realmente escreve.
PASSO = 900

def abre(caminho):
    db = sqlite3.connect('file:%s?mode=rw' % caminho, uri=True, timeout=20)
    db.execute('PRAGMA busy_timeout=20000')
    return db

def grava(db, mac, ts, v):
    ts = ts - ts % PASSO
    db.execute('INSERT OR REPLACE INTO metric_samples (series,label,step_seconds,ts_unix,v_min,v_avg,v_max)'
               ' VALUES (?,?,?,?,?,?,?)', (SERIE, mac, PASSO, ts, v, v, v))

def semeia(db, alto, piso, ctrl):
    agora = int(time.time())
    lt = time.localtime(agora)
    # O detector compara HORA LOCAL do processo (time.Time.Hour()). Alinhar
    # pelo topo da hora UTC só funcionaria por acidente de fuso.
    topo = agora - lt.tm_min * 60 - lt.tm_sec
    velho = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(agora - 30 * 86400))
    visto = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(agora))
    # first_seen de 30 dias com folga enorme de propósito: é o que sustenta a
    # asserção 'aparelho conhecido não é novidade' mesmo com o fuso errado.
    for mac, ip, alias in ((alto, '192.168.117.11', 'Alto da bateria V'),
                           (piso, '192.168.117.12', 'Quieto da bateria V'),
                           (ctrl, '192.168.117.13', 'Testemunha da bateria V')):
        db.execute('INSERT OR REPLACE INTO host_metadata (mac,ip,hostname,alias,blocked,first_seen,last_seen)'
                   ' VALUES (?,?,?,?,0,?,?)', (mac, ip, '', alias, velho, visto))
    db.commit()
    # TRÊS HORAS SEGUIDAS em cada um dos sete dias anteriores (12 baldes de 15
    # min), e não só a hora
    # corrente: o normal é a mediana da MESMA HORA DO DIA, e esta bateria leva
    # mais de dez minutos — uma passada que caia na hora seguinte não pode
    # reprovar o produto por causa do relógio.
    # Um commit por dia semeado: uma transação longa segura o writer
    # do tsdb, que grava a cada segundo, e fazem o produto PERDER amostra real.
    for mac, v in ((alto, 1048576.0), (piso, 102400.0), (ctrl, 1048576.0)):
        for d in range(1, 8):
            base = topo - d * 86400
            for j in range(12):
                grava(db, mac, base + j * PASSO, v)
            db.commit()
    grava(db, alto, agora, 8388608.0)   # 8x o normal e acima do piso
    grava(db, piso, agora, 1048576.0)   # 10x o normal e ABAIXO do piso
    db.commit()
    print('SEMEADO')

def pico2(db, alto, ctrl):
    agora = int(time.time())
    grava(db, alto, agora, 16777216.0)
    grava(db, ctrl, agora, 8388608.0)
    db.commit()
    n = db.execute('SELECT count(*) FROM metric_samples WHERE series=? AND step_seconds=?'
                   ' AND label IN (?,?) AND ts_unix >= ? AND v_avg >= ?',
                   (SERIE, PASSO, alto, ctrl, agora - agora % PASSO, 8388608.0)).fetchone()[0]
    print('PICO2 %d' % n)

def portas(db, mac):
    # As duas portas EXATAS de consumo(): 12 amostras na janela de 7 dias e 6 na
    # mesma hora do dia com mais de uma hora de idade. Contar linhas no total
    # aprovaria uma semeadura na hora errada, e aí o produto ficaria calado com
    # razão e a bateria gritaria que ele falhou.
    agora = int(time.time())
    linhas = db.execute('SELECT ts_unix, v_avg FROM metric_samples WHERE series=? AND label=?'
                        ' AND step_seconds=? AND ts_unix BETWEEN ? AND ? ORDER BY ts_unix ASC',
                        (SERIE, mac, PASSO, agora - 7 * 86400, agora)).fetchall()
    hora = time.localtime(agora).tm_hour
    mesma = [r for r in linhas if time.localtime(r[0]).tm_hour == hora and agora - r[0] > 3600]
    meta = db.execute('SELECT count(*) FROM host_metadata WHERE mac=? AND blocked=0', (mac,)).fetchone()[0]
    atual = linhas[-1][1] if linhas else -1.0
    print('PORTAS %d %d %d %d' % (len(linhas), len(mesma), meta, int(atual)))

def passos(db, mac):
    agora = int(time.time())
    l = db.execute('SELECT DISTINCT step_seconds FROM metric_samples WHERE series=? AND label=?'
                   ' AND ts_unix > ? ORDER BY 1', (SERIE, mac, agora - 3600)).fetchall()
    print('PASSOS ' + (','.join(str(x[0]) for x in l) if l else '-'))

def conta(db, tipo, mac):
    print('CONTA %d' % db.execute('SELECT count(*) FROM alerts WHERE type=? AND link_id=?',
                                  (tipo, mac)).fetchone()[0])

def msg(db, tipo, mac):
    r = db.execute('SELECT message FROM alerts WHERE type=? AND link_id=? ORDER BY rowid DESC LIMIT 1',
                   (tipo, mac)).fetchone()
    print('MSG ' + (r[0].replace('\n', ' ') if r else '-'))

def abertos(db, tipo, mac):
    r = db.execute('SELECT id FROM alerts WHERE type=? AND link_id=? AND resolved=0', (tipo, mac)).fetchall()
    print('ABERTOS ' + (' '.join(x[0] for x in r) if r else '-'))

def meta(db, mac):
    print('META %d' % db.execute('SELECT count(*) FROM host_metadata WHERE mac=?', (mac,)).fetchone()[0])

def limpa(db, macs):
    for mac in macs:
        db.execute('DELETE FROM metric_samples WHERE label=?', (mac,))
        db.execute('DELETE FROM host_metadata WHERE mac=?', (mac,))
    db.commit()
    n = 0
    for mac in macs:
        n += db.execute('SELECT count(*) FROM host_metadata WHERE mac=?', (mac,)).fetchone()[0]
    print('LIMPO %d' % n)

try:
    db = abre(sys.argv[1])
    cmd, arg = sys.argv[2], sys.argv[3:]
    if cmd == 'semeia':   semeia(db, arg[0], arg[1], arg[2])
    elif cmd == 'pico2':  pico2(db, arg[0], arg[1])
    elif cmd == 'portas': portas(db, arg[0])
    elif cmd == 'passos': passos(db, arg[0])
    elif cmd == 'conta':  conta(db, arg[0], arg[1])
    elif cmd == 'msg':    msg(db, arg[0], arg[1])
    elif cmd == 'abertos':abertos(db, arg[0], arg[1])
    elif cmd == 'meta':   meta(db, arg[0])
    elif cmd == 'limpa':  limpa(db, arg)
    else: print('ERRO subcomando desconhecido: %s' % cmd)
except Exception as e:
    print('ERRO %r' % (e,))
PYEOF
      echo escrito" >/dev/null 2>&1
  script_pronto=1

  q()  { vm "python3 $SCRIPT '$BANCO' $*" 2>/dev/null | tr -d '\r'; }
  q1() { q "$@" | tail -1; }

  # conta_alertas TIPO MAC → número, ou ERR. Nunca zero por falha de leitura: o
  # zero é o valor que faz as asserções de silêncio passarem, e um banco
  # ilegível não pode virar prova de que o detector se conteve.
  conta_alertas() {
    local r; r=$(q1 conta "$1" "$2")
    if [[ "$r" =~ ^CONTA\ ([0-9]+)$ ]]; then echo "${BASH_REMATCH[1]}"; else echo ERR; fi
  }
  mensagem_de() {
    local r; r=$(q1 msg "$1" "$2")
    [[ "$r" == MSG\ * ]] && printf '%s\n' "${r#MSG }"
  }

  # O ajudante tem de responder antes de qualquer asserção depender dele.
  local sanidade; sanidade=$(q1 conta "$T_NOVO" "00:00:00:00:00:00")
  if [[ "$sanidade" != "CONTA 0" ]]; then
    bad "não consigo ler a tabela de alertas do banco da VM; nada desta bateria pode ser afirmado" "$sanidade"
    encerra_v "o banco da VM não pôde ser lido ($BANCO)"
    return
  fi

  # Linha de base. Com MAC sorteado ela tem de ser zero; se não for, o sorteio
  # bateu num MAC de outra rodada e as igualdades desta bateria mediriam o
  # passado.
  local base_alto base_piso base_ctrl
  base_alto=$(conta_alertas "$T_ACIMA" "$ALTO")
  base_piso=$(conta_alertas "$T_ACIMA" "$PISO")
  base_ctrl=$(conta_alertas "$T_ACIMA" "$CTRL")
  if [[ "$base_alto" != "0" || "$base_piso" != "0" || "$base_ctrl" != "0" ]]; then
    bad "os MACs sorteados já têm alerta nesta caixa; as asserções de silêncio não valeriam" \
        "$ALTO=$base_alto $PISO=$base_piso $CTRL=$base_ctrl"
    encerra_v "colisão dos MACs sorteados com uma execução anterior"
    return
  fi

  # ── V2 — O PASSO QUE O DETECTOR PEDE TEM DE SER UM PASSO QUE O PRODUTO GRAVA
  #
  # ESTA É A ASSERÇÃO QUE JUSTIFICA A BATERIA EXISTIR NUMA MÁQUINA DE VERDADE.
  # O detector consulta a série `host.rx_bps` no passo 900 (15 min). Se o produto
  # não gravar esse passo sozinho, a consulta volta vazia, `consumo()` desiste
  # por falta de amostras e NENHUM aparelho do mundo dispara o alerta — recurso
  # entregue e mudo, com os testes em Go verdes porque eles mesmos inserem o
  # passo que o produto não grava — foi assim que o defeito do passo 300 passou.
  #
  # A pergunta é feita com tráfego DESTA rodada, atravessando o firewall, e
  # olhando só o aparelho que acabou de gerá-lo: assim a resposta não pode vir
  # de resto de execução anterior nem depender de a bateria G ter rodado antes.
  status PUT /api/nftables/policy "$tok" '{"policy":"accept"}' >/dev/null 2>&1
  status POST /api/links/auto-detect "$tok" >/dev/null 2>&1
  vm "ip netns del lgnovo 2>/dev/null; ip link del lg-novo 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add lgnovo && \
      ip link add lg-novo type veth peer name novo-far && \
      ip link set novo-far netns lgnovo && \
      ip addr add 192.168.117.1/24 dev lg-novo && ip link set lg-novo up && \
      ip netns exec lgnovo ip link set lo up && \
      ip netns exec lgnovo ip addr add 192.168.117.2/24 dev novo-far && \
      ip netns exec lgnovo ip link set novo-far up && \
      ip netns exec lgnovo ip route add default via 192.168.117.1" >/dev/null 2>&1
  # O endereço físico do veth é sorteado a cada criação: é genuinamente inédito
  # para o inventário desta caixa.
  mac_novo=$(vm "ip netns exec lgnovo cat /sys/class/net/novo-far/address 2>/dev/null" | tr -d '\r' | tr 'A-Z' 'a-z')
  # Um ping curto no próprio firewall coloca o aparelho na vizinhança (é dali
  # que sai tanto o inventário quanto o mapa IP→MAC do amostrador), e um ping
  # longo para fora gera o tráfego que ATRAVESSA e portanto é contabilizado.
  if [[ -z "$mac_novo" ]]; then
    bad "não consegui criar o aparelho de mentira na VM; nada desta bateria pode ser montado" \
        "$(vm "ip link show lg-novo 2>&1 | head -2" | tr -d '\r' | head -c 160)"
    encerra_v "a montagem do aparelho de teste (veth em netns) falhou"
    return
  fi
  vm "timeout 5 ip netns exec lgnovo ping -c 3 -i 0.3 192.168.117.1" >/dev/null 2>&1
  vm "nohup ip netns exec lgnovo ping -q -i 0.2 -s 1400 -w 120 10.0.2.2 >/dev/null 2>&1 &" >/dev/null 2>&1

  # A pergunta da V2 é feita LÁ NO FIM desta bateria, e não aqui. Um balde do
  # tsdb só é escrito quando a JANELA DELE FECHA, então o balde de 900s exige
  # quinze minutos de relógio — e três minutos de tráfego só conseguem fechar
  # baldes de 10s. Perguntando aqui, a bateria acusava o produto de não gravar
  # um passo que ele ainda não tinha tido tempo de gravar. Lá no fim as duas
  # passadas do detector já se passaram e o tempo existe de graça.
  printf '       (gerando tráfego contabilizado; o passo gravado é conferido no fim, quando o balde de 15 min já fechou)\n'
  local i
  # O INSTANTE EM QUE O TRÁFEGO COMEÇOU, porque a V2 depende de RELÓGIO e não de
  # quantas asserções correram antes dela. Ver o comentário da V2 lá embaixo.
  local t_traf; t_traf=$(vm "date +%s" | tr -d '\r' | tail -1)

  # ── Semeadura: o passado, que não tem rota ─────────────────────────────────
  local r_semeia; r_semeia=$(q1 semeia "$ALTO" "$PISO" "$CTRL")
  if [[ "$r_semeia" != "SEMEADO" ]]; then
    bad "não consegui semear o histórico por aparelho; as asserções de consumo não seriam medidas" "$r_semeia"
    encerra_v "a semeadura do baseline falhou"
    return
  fi

  # E a semeadura é conferida CONTRA AS PORTAS DO PRODUTO, não contra um número
  # de linhas: consumo() exige 12 amostras na janela de 7 dias, 6 na mesma hora
  # do dia com mais de uma hora de idade, e o aparelho no inventário e não
  # bloqueado. Uma contagem global aprovaria uma semeadura na hora errada — e aí
  # o produto ficaria calado com razão e esta bateria o acusaria.
  local m falhou_porta=0 detalhe_porta=""
  for m in "$ALTO" "$PISO" "$CTRL"; do
    local p; p=$(q1 portas "$m")
    if [[ "$p" =~ ^PORTAS\ ([0-9]+)\ ([0-9]+)\ ([0-9]+)\ (-?[0-9]+)$ ]]; then
      local nj="${BASH_REMATCH[1]}" nh="${BASH_REMATCH[2]}" nm="${BASH_REMATCH[3]}"
      if [[ "$nj" -lt 12 || "$nh" -lt 6 || "$nm" -ne 1 ]]; then
        falhou_porta=1; detalhe_porta="$detalhe_porta $m(janela=$nj mesma_hora=$nh inventário=$nm)"
      fi
    else
      falhou_porta=1; detalhe_porta="$detalhe_porta $m($p)"
    fi
  done
  if [[ "$falhou_porta" == 0 ]]; then
    ok "o histórico semeado satisfaz as portas que o detector exige (janela de 7 dias, mesma hora do dia e inventário)"
  else
    bad "o histórico semeado NÃO satisfaz as portas do detector; o silêncio dele seria certo e a bateria mediria a si mesma" \
        "$detalhe_porta"
    encerra_v "a semeadura não satisfez as portas de consumo()"
    return
  fi

  # ── V1, montagem: o avistamento, que é a última coisa a acontecer ──────────
  #
  # `IdadeDeHostNovo` é de 10 minutos contados do first_seen, o ticker é de 5 e
  # NÃO há passada no boot. Se o avistamento fosse gravado antes da semeadura, o
  # orçamento de 10 minutos seria gasto por SSH e SQL e o aparelho deixaria de
  # ser novo antes do primeiro tick — matando a V1 e, pior, podendo pegar uma
  # passada com metade do cenário montado e reprovar a V3 por isso. Semeado tudo,
  # o avistamento é a última coisa: uma única passada serve para os dois
  # detectores.
  local t_avist visto_meta quer_novo=0
  body GET /api/hosts "$tok" >/dev/null 2>&1
  sleep 2
  body GET /api/hosts "$tok" >/dev/null 2>&1
  t_avist=$(date +%s)
  # O que o detector lê é a LINHA DO BANCO, e o upsert do avistamento é
  # best-effort dentro do handler (o erro é descartado): o aparelho pode
  # aparecer na resposta HTTP sem ter entrado no inventário.
  visto_meta=$(q1 meta "$mac_novo")
  if [[ "$visto_meta" == "META 1" ]]; then
    ok "o aparelho de mentira entrou no inventário pelo caminho do produto ($mac_novo)"
    quer_novo=1
  else
    bad "o avistamento não chegou ao inventário; a asserção de aparelho novo não pode ser medida" \
        "mac '$mac_novo', leitura: $visto_meta, vizinhança: $(vm "ip neigh show 2>/dev/null | grep -i '$mac_novo'" | tr -d '\r' | head -c 120)"
    pular "V1. Aparelho nunca visto vira alerta" "o avistamento não foi gravado no inventário; sem ele o detector não teria o que ver"
    M_V1=1
  fi

  # O PID de agora. A histerese vive na memória do processo: se ele reiniciar no
  # meio, alertar de novo passa a ser o comportamento CERTO, e a V6 não pode
  # acusar ninguém.
  local pid1; pid1=$(vm "systemctl show -p MainPID --value linkguard-fw" | tr -d '\r' | tail -1)

  # ── A passada do detector ──────────────────────────────────────────────────
  #
  # Teto, e não sono cego: se os alertas saírem no primeiro minuto a bateria
  # segue no primeiro minuto. E a espera só termina quando OS DOIS sinais
  # chegam — os dois detectores rodam na mesma passada, e quebrar no primeiro
  # faria julgar o segundo com 15 segundos de espera para um ticker de 5 min.
  printf '       (aguardando a passada dos detectores — o ticker é de 5 minutos, sem passada no boot)\n'
  local n_novo=0 n_alto=0
  for i in $(seq 1 28); do
    sleep 15
    n_novo=$(conta_alertas "$T_NOVO" "$mac_novo")
    n_alto=$(conta_alertas "$T_ACIMA" "$ALTO")
    [[ "$n_alto" == ERR || "$n_novo" == ERR ]] && continue
    if [[ "$n_alto" -gt 0 ]] && { [[ "$quer_novo" == 0 ]] || [[ "$n_novo" -gt 0 ]]; }; then break; fi
  done
  # Os detectores rodam um depois do outro dentro da mesma passada; um instante
  # de folga evita julgar o segundo com o número lido enquanto o primeiro ainda
  # escrevia.
  sleep 5
  n_novo=$(conta_alertas "$T_NOVO" "$mac_novo")
  n_alto=$(conta_alertas "$T_ACIMA" "$ALTO")
  if [[ "$n_novo" == ERR || "$n_alto" == ERR ]]; then
    bad "a leitura dos alertas falhou depois da espera; a bateria V não mediu nada"
    encerra_v "a tabela de alertas ficou ilegível durante a bateria"
    return
  fi

  # Antes de acusar o detector de mudo, provar que a caixa está viva: serviço
  # morto e detector calado produzem o mesmo silêncio, e só um deles é defeito
  # do recurso.
  if [[ "$n_novo" -eq 0 && "$n_alto" -eq 0 ]]; then
    local vivo; vivo=$(vm "systemctl is-active linkguard-fw" | tr -d '\r' | tail -1)
    if [[ "$vivo" != "active" ]] || ! wait_api; then
      bad "o serviço não está no ar; o silêncio dos detectores não pode ser cobrado dele" "systemctl is-active: $vivo"
      encerra_v "o serviço caiu durante a bateria"
      return
    fi
  fi

  # ── V1 — APARELHO NOVO VIRA ALERTA ─────────────────────────────────────────
  if [[ "$quer_novo" == 1 ]]; then
    if [[ "$n_novo" -eq 1 ]]; then
      ok "o aparelho nunca visto virou alerta de aparelho novo"
    elif [[ "$n_novo" -gt 1 ]]; then
      bad "o mesmo aparelho novo gerou $n_novo alertas: a histerese não vale para este detector"
    elif [[ $(( $(date +%s) - t_avist )) -gt 600 ]]; then
      # A janela do cenário venceu antes de o ticker bater: isto não é veredicto
      # sobre o produto, e imprimir FALHA aqui seria acusar o relógio da bateria.
      pular "V1. Aparelho nunca visto vira alerta" \
            "a janela de 10 min de 'aparelho novo' venceu antes da passada de 5 min do detector; o cenário não deu tempo"
    else
      bad "o aparelho apareceu na rede e nenhum alerta de aparelho novo saiu ($mac_novo)"
    fi
    M_V1=1

    if [[ "$n_novo" -ge 1 ]]; then
      # O alerta tem de IDENTIFICAR o aparelho — é o que separa um aviso útil de
      # uma linha que manda o admin procurar em outra tela. Este aparelho não tem
      # apelido nem nome anunciado, então o que se cobra é o endereço físico.
      local msg_novo; msg_novo=$(mensagem_de "$T_NOVO" "$mac_novo")
      if [[ -n "$msg_novo" && "$msg_novo" != "-" ]] && grep -qiF -- "$mac_novo" <<<"$msg_novo"; then
        ok "o alerta de aparelho novo traz o endereço físico do aparelho"
      else
        bad "o alerta de aparelho novo não identifica o aparelho" "$(head -c 150 <<<"$msg_novo")"
      fi

      # A OUTRA METADE: aparelho conhecido há trinta dias NÃO é novidade. Só vale
      # perguntar isso porque o alerta do aparelho de mentira prova que o detector
      # RODOU e varreu o inventário inteiro na mesma passada; sem esse gate, um
      # detector morto imprimiria este OK de graça.
      local n_novo_velho; n_novo_velho=$(conta_alertas "$T_NOVO" "$ALTO")
      if [[ "$n_novo_velho" == "0" ]]; then
        ok "aparelho visto pela primeira vez há 30 dias não vira alerta de aparelho novo"
      elif [[ "$n_novo_velho" == ERR ]]; then
        bad "não consegui contar os alertas do aparelho conhecido; a asserção não foi medida"
      else
        bad "um aparelho conhecido há 30 dias foi anunciado como novo na rede ($n_novo_velho alerta(s))"
      fi
    else
      pular "V1b. Aparelho conhecido há 30 dias não é novidade" \
            "sem o alerta do aparelho de mentira não há prova de que o detector varreu o inventário nesta passada"
    fi
  fi

  # ── V3 — CONSUMO ACIMA DO PRÓPRIO NORMAL VIRA ALERTA ───────────────────────
  # 8 MB/s contra 1 MB/s de mediana naquela hora: oito vezes o normal e acima do
  # piso de 2 MB/s.
  if [[ "$n_alto" -eq 1 ]]; then
    ok "consumo de 8x o normal daquela hora virou alerta"
  elif [[ "$n_alto" -eq 0 ]]; then
    bad "o aparelho com 8x o próprio normal não gerou alerta de consumo" \
        "$(vm "journalctl -u linkguard-fw --since '15 min ago' --no-pager | grep -iE 'comportamento|panic|alert created' | tail -2" | tr -d '\r' | head -c 200)"
  else
    bad "o mesmo aparelho gerou $n_alto alertas de consumo numa passada só"
  fi
  M_V3=1

  if [[ "$n_alto" -ge 1 ]]; then
    # A mensagem tem de trazer os DOIS números na ORDEM CERTA. Dois greps
    # independentes passariam igual se o produto trocasse os argumentos —
    # "consumindo 1.0 MB/s, contra 8.0 MB/s que é o normal" — que é exatamente o
    # defeito que esta asserção existe para pegar.
    local msg_alto; msg_alto=$(mensagem_de "$T_ACIMA" "$ALTO")
    if [[ -n "$msg_alto" && "$msg_alto" != "-" ]] &&
       grep -qE "Alto da bateria V \($ALTO\) está consumindo 8\.0 MB/s, contra 1\.0 MB/s" <<<"$msg_alto"; then
      ok "a mensagem nomeia o aparelho e compara o consumo de agora com o normal dele, nessa ordem"
    else
      bad "a mensagem não compara o consumo com o normal na ordem esperada" "$(head -c 200 <<<"$msg_alto")"
    fi
  fi

  # Os alertas também têm de CHEGAR À TELA. Tudo o que esta bateria decide é
  # lido por SQL (a rota devolve só as 100 mais recentes, o que estragaria as
  # igualdades), mas se a rota não os mostrasse, o recurso estaria entregue
  # invisível.
  if [[ "$quer_novo" == 1 && "$n_novo" -ge 1 && "$n_alto" -ge 1 ]]; then
    local no_painel
    no_painel=$(body GET "/api/alerts?unresolved=true" "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
if not isinstance(d,list): raise SystemExit(1)
alvo={(sys.argv[1],sys.argv[3].lower()),(sys.argv[2],sys.argv[4].lower())}
print(len({(a.get('type'),(a.get('link_id') or '').lower()) for a in d} & alvo))" \
      "$T_NOVO" "$T_ACIMA" "$mac_novo" "$ALTO" 2>/dev/null)
    if [[ "$no_painel" == "2" ]]; then
      ok "os dois alertas aparecem na lista do painel (GET /api/alerts)"
    else
      bad "os alertas de comportamento não apareceram na lista do painel" "encontrados: ${no_painel:-leitura falhou}"
    fi
  fi

  # ── V4 — O PISO CALA O DETECTOR ────────────────────────────────────────────
  #
  # O aparelho quieto foi semeado com a MESMA FORMA do outro — mesmos baldes,
  # mesma hora, mesma janela — e faz DEZ vezes o próprio normal, mais que os três
  # exigidos. A única diferença é a grandeza: 1 MB/s não chega aos 2 MB/s do
  # piso. Só que "ficou calado" só significa piso se ALGUÉM tiver falado na mesma
  # passada: quando consumo() desiste por falta de amostras, ele desiste para
  # todos. Sem a V3 verde, esta asserção é PULADA em vez de virar um OK grátis.
  local n_piso; n_piso=$(conta_alertas "$T_ACIMA" "$PISO")
  if [[ "$n_alto" -ne 1 ]]; then
    pular "V4. O piso absoluto cala o detector" \
          "o aparelho de controle não disparou nesta passada; o silêncio do quieto não distingue piso de detector parado"
  elif [[ "$n_piso" == "0" ]]; then
    ok "aparelho com 10x o próprio normal mas abaixo de 2 MB/s ficou calado — o piso segura o ruído"
  elif [[ "$n_piso" == ERR ]]; then
    bad "não consegui contar os alertas do aparelho quieto; o piso não foi medido"
  else
    bad "O PISO NÃO SEGUROU: alerta de consumo para quem faz 1 MB/s" \
        "$(head -c 200 <<<"$(mensagem_de "$T_ACIMA" "$PISO")")"
  fi
  M_V4=1

  # ── V5/V6 — A HISTERESE ────────────────────────────────────────────────────
  #
  # V5 é a montagem que torna V6 honesta. O serviço suprime alerta novo enquanto
  # houver um ABERTO do mesmo tipo para o mesmo aparelho — se o primeiro ficasse
  # aberto, o silêncio do segundo pico provaria o dedupe e não a histerese, que é
  # outra coisa e mora na memória do processo.
  if [[ "$n_alto" -lt 1 ]]; then
    encerra_v "não houve primeiro alerta de consumo; sem ele não existe segundo pico para calar"
    return
  fi
  local lista_abertos; lista_abertos=$(q1 abertos "$T_ACIMA" "$ALTO")
  if [[ "$lista_abertos" != ABERTOS\ * || "$lista_abertos" == "ABERTOS -" ]]; then
    bad "não achei alerta aberto para resolver; a histerese não poderia ser medida separada do dedupe" "$lista_abertos"
    encerra_v "não foi possível tirar o dedupe de alerta aberto do caminho"
    return
  fi
  local id st_res falha_res=0
  for id in ${lista_abertos#ABERTOS }; do
    st_res=$(status PUT "/api/alerts/$id/resolve" "$tok")
    [[ "$st_res" == "204" || "$st_res" == "200" ]] || falha_res=1
  done
  # 204 não prova resolução: o handler responde 204 mesmo para id inexistente e o
  # UPDATE descarta o RowsAffected. Quem decide é o estado depois.
  local sobrou; sobrou=$(q1 abertos "$T_ACIMA" "$ALTO")
  if [[ "$sobrou" == "ABERTOS -" ]]; then
    ok "não há mais alerta aberto para o aparelho de teste (o dedupe está fora do caminho)"
  else
    bad "sobrou alerta aberto para o aparelho de teste; o silêncio seguinte seria do dedupe, não da histerese" \
        "resolve devolveu falha=$falha_res, ainda abertos: $sobrou"
    encerra_v "o dedupe de alerta aberto não pôde ser tirado do caminho"
    return
  fi

  # Segundo pico do MESMO aparelho, maior ainda — e uma TESTEMUNHA, outro
  # aparelho semeado para disparar na mesma passada. Sem a testemunha, "não
  # alertou de novo" é o que se veria também com o detector morto. E a semeadura
  # da testemunha é conferida: se ela não for gravada, a bateria acusaria o
  # produto por uma escrita que nunca aconteceu.
  local r_pico2; r_pico2=$(q1 pico2 "$ALTO" "$CTRL")
  if [[ "$r_pico2" != "PICO2 2" ]]; then
    bad "não consegui semear o segundo pico e a testemunha; a histerese não será medida" "$r_pico2"
    encerra_v "a semeadura do segundo pico e da testemunha falhou"
    return
  fi

  printf '       (aguardando a passada seguinte — a testemunha é quem prova que ela aconteceu)\n'
  local n_ctrl=0
  for i in $(seq 1 28); do
    sleep 15
    n_ctrl=$(conta_alertas "$T_ACIMA" "$CTRL")
    [[ "$n_ctrl" =~ ^[0-9]+$ && "$n_ctrl" -gt 0 ]] && break
  done

  if [[ ! "$n_ctrl" =~ ^[0-9]+$ || "$n_ctrl" -eq 0 ]]; then
    bad "a testemunha não alertou em 7 minutos; não dá para afirmar que a histerese calou coisa alguma" \
        "alertas da testemunha: $n_ctrl"
    encerra_v "sem testemunha, o silêncio do segundo pico não distingue histerese de detector parado"
    return
  fi

  # A ordem em que o detector percorre o inventário não é definida (a consulta
  # não tem ORDER BY), então ver a testemunha não garante que o aparelho de teste
  # já foi avaliado nesta passada. A leitura só é aceita quando estabiliza: duas
  # leituras seguidas iguais, com folga entre elas.
  local n_alto2="" n_alto3=""
  for i in $(seq 1 6); do
    sleep 10
    n_alto2=$(conta_alertas "$T_ACIMA" "$ALTO")
    sleep 10
    n_alto3=$(conta_alertas "$T_ACIMA" "$ALTO")
    [[ "$n_alto2" == "$n_alto3" && "$n_alto2" =~ ^[0-9]+$ ]] && break
  done

  local pid2; pid2=$(vm "systemctl show -p MainPID --value linkguard-fw" | tr -d '\r' | tail -1)
  if [[ ! "$n_alto2" =~ ^[0-9]+$ || "$n_alto2" != "$n_alto3" ]]; then
    pular "V6. A histerese cala o segundo pico" \
          "não consegui uma leitura estável dos alertas depois da passada da testemunha (leituras: '$n_alto2' e '$n_alto3')"
  elif [[ -z "$pid2" || "$pid2" != "$pid1" ]]; then
    # Histerese é estado de processo: depois de um restart, alertar de novo é o
    # comportamento CERTO. Acusar aqui seria inventar um defeito.
    pular "V6. A histerese cala o segundo pico" \
          "o serviço reiniciou entre as duas passadas (PID $pid1 → $pid2); a histerese é estado de memória e foi zerada"
  elif [[ "$n_alto2" -eq 1 ]]; then
    ok "houve passada (a testemunha alertou) e o segundo pico do mesmo aparelho NÃO virou segundo alerta"
  else
    bad "SEGUNDO ALERTA DO MESMO APARELHO DENTRO DE 6H: a histerese não segurou" \
        "alertas para $ALTO: $n_alto2 (o primeiro foi resolvido antes do segundo pico)"
  fi
  M_V6=1

  # ── V2 — O PASSO QUE O DETECTOR PEDE TEM DE SER UM PASSO QUE O PRODUTO GRAVA
  #
  # ESTA É A ASSERÇÃO QUE JUSTIFICA A BATERIA EXISTIR NUMA MÁQUINA DE VERDADE, e
  # ela vem no fim por uma razão de relógio, não de importância: o tsdb só grava
  # um balde quando a janela dele fecha, e a janela de 900s leva quinze minutos.
  # As duas passadas do detector que as asserções acima esperaram já pagaram
  # esse tempo.
  #
  # O tráfego parou lá atrás, e não faz diferença: o tick fecha o balde no prazo
  # mesmo sem amostra nova chegando. O que se mede é se o passo que o detector
  # CONSULTA aparece sozinho, para um aparelho que só existe nesta rodada.
  # A ESPERA É CALCULADA, E NÃO CHUTADA. Um balde do tsdb fecha em MÚLTIPLO do
  # passo, contado do epoch: o balde de 900s que contém o começo do tráfego só é
  # escrito quando o relógio cruza a fronteira seguinte. Esperar "oito vezes 30
  # segundos" faz a asserção medir QUANTO TEMPO A SUÍTE LEVOU até aqui — e ela
  # mediu: a mesma versão do produto passou numa rodada com a bateria de upgrade
  # (mais longa) e reprovou numa sem ela, acusando o produto de não gravar um
  # passo que ele grava.
  #
  # Aqui a espera vai até a fronteira do balde mais uma folga, e o teto é dito em
  # segundos de relógio, não em número de tentativas.
  local passos="" alvo agora restante
  if [[ "$t_traf" =~ ^[0-9]+$ ]]; then
    alvo=$(( t_traf - t_traf % 900 + 900 + 60 ))
  else
    alvo=0
  fi
  while :; do
    passos=$(q1 passos "$mac_novo")
    [[ "$passos" == PASSOS\ * && "$passos" != "PASSOS -" ]] && grep -qE '(^|,)900(,|$)' <<<"${passos#PASSOS }" && break
    agora=$(vm "date +%s" | tr -d '\r' | tail -1)
    [[ "$agora" =~ ^[0-9]+$ ]] || break
    restante=$(( alvo - agora ))
    if [[ "$restante" -le 0 ]]; then break; fi
    printf '       (faltam %ds para o balde de 15 min fechar)\n' "$restante"
    sleep $(( restante > 60 ? 60 : restante ))
  done
  if [[ "$alvo" == 0 ]]; then
    pular "V2. O passo consultado é um passo que o produto grava" \
          "não consegui ler o relógio da VM para saber quando o balde de 15 min fecharia"
  elif [[ "$passos" != PASSOS\ * ]]; then
    bad "não consegui ler os passos gravados para o aparelho de teste; a asserção do passo não foi medida" "$passos"
  else
    passos="${passos#PASSOS }"
    if [[ "$passos" == "-" ]]; then
      # Sem amostra nenhuma o buraco pode ser do cenário (tráfego que não
      # atravessou, contabilidade sem WAN detectada) e não do produto. Acusar o
      # detector aqui seria trocar a culpa.
      pular "V2. O passo consultado é um passo que o produto grava" \
            "o produto não gravou amostra alguma para o aparelho de teste; sem série real não dá para dizer em que passo ela é escrita"
    elif grep -qE '(^|,)900(,|$)' <<<"$passos"; then
      ok "o passo que o detector consulta (900s) é um dos que o produto grava sozinho ($passos)"
    elif [[ "$(vm "date +%s" | tr -d '\r' | tail -1)" -lt "$alvo" ]] 2>/dev/null; then
      # A fronteira não chegou: o produto não teve como gravar ainda, e dizer
      # que ele não grava seria acusá-lo do relógio da bateria.
      pular "V2. O passo consultado é um passo que o produto grava" \
            "o balde de 15 min ainda não fechou desde o tráfego desta rodada (passos até agora: $passos)"
    else
      bad "O DETECTOR CONSULTA UM PASSO QUE NINGUÉM GRAVA: sem 900s, o alerta de consumo nunca sai numa caixa real" \
          "passos que o produto gravou para $mac_novo depois da fronteira do balde: $passos"
    fi
  fi
  M_V2=1

  # Limpeza: os alertas desta bateria são fechados pelo caminho do painel, o
  # histórico semeado sai do banco e o aparelho de mentira sai da rede e do
  # inventário — senão a bateria seguinte enxerga um inventário que a rede não
  # tem.
  limpa_v
}

# ─── X. WAN em VLAN entra no balanceamento (issue #188) ──────────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. O iproute2 acrescenta "@mãe" ao nome de
# toda interface que tem interface-mãe — VLAN, veth, macvlan, ipvlan — e só a
# física sai com o nome limpo. O produto lia esse campo inteiro como nome, a
# consulta era pelo nome do link, e nunca casavam: a WAN era tratada como CAÍDA
# e jogada fora do balanceamento, sem uma linha de log, aparecendo no painel
# como excluída POR ESTAR FORA DO AR enquanto estava no ar e funcionando.
#
# PPPoE sobre VLAN e VLAN de operadora são o arranjo mais comum em firewall de
# borda. O cliente contrata dois links e o produto usa um.
#
# O CONTROLE ESTÁ DENTRO DA BATERIA, e é o que a torna honesta: são DUAS VLANs,
# uma no ar e uma derrubada. Se só houvesse a de cima, "entrou no plano"
# passaria igual num produto que simplesmente parou de excluir qualquer coisa —
# e aí um link de verdade fora do ar continuaria carregando tráfego, que é pior
# do que o defeito consertado. A única diferença entre as duas é o estado do
# link, que é precisamente o que o filtro existe para medir.
battery_vlan_no_balanceamento() {
  head_ "X. WAN em VLAN entra no balanceamento"

  local M_X1=0 M_X2=0 tok=""

  limpa_x() {
    local id
    if [[ -n "$tok" ]]; then
      for id in $(body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l.get('interface') in ('lgv0.100','lgv0.200'): print(l['id'])" 2>/dev/null); do
        status DELETE "/api/links/$id" "$tok" >/dev/null 2>&1
      done
    fi
    vm "ip link del lgv0.100 2>/dev/null; ip link del lgv0.200 2>/dev/null; ip link del lgv0 2>/dev/null; true" >/dev/null 2>&1
    local sobra
    sobra=$(vm "ip -br link show 2>/dev/null | grep -c lgv0" | tr -d '\r' | head -1)
    if [[ "${sobra:-0}" != "0" ]]; then
      bad "as interfaces de teste da bateria X não saíram; as baterias seguintes veriam WAN que não existe" "sobraram: $sobra"
    fi
  }

  encerra_x() {
    [[ "$M_X1" == 1 ]] || pular "X1. A VLAN no ar entra no balanceamento" "$1"
    [[ "$M_X2" == 1 ]] || pular "X2. A VLAN derrubada continua fora" "$1"
    limpa_x
  }

  local initial
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  if [[ -z "$tok" ]]; then
    bad "sem sessão administrativa; a bateria X não roda"
    encerra_x "sem sessão administrativa"
    return
  fi

  # Uma interface-mãe de mentira (dummy, que não precisa de par) e duas VLANs em
  # cima dela. A dummy é usada em vez da WAN real da VM para que derrubar uma
  # das VLANs não mexa no enlace por onde esta própria suíte fala.
  vm "ip link del lgv0 2>/dev/null
      ip link add lgv0 type dummy && ip link set lgv0 up && \
      ip link add link lgv0 name lgv0.100 type vlan id 100 && \
      ip link add link lgv0 name lgv0.200 type vlan id 200 && \
      ip addr add 10.58.100.1/24 dev lgv0.100 && ip link set lgv0.100 up && \
      ip addr add 10.58.200.1/24 dev lgv0.200 && ip link set lgv0.200 down" >/dev/null 2>&1

  # O CENÁRIO É CONFERIDO ANTES DE SER USADO. Se o kernel desta caixa não
  # imprimisse o "@mãe", a bateria estaria medindo um defeito que não existe
  # aqui e passaria por acidente — verde sem significado nenhum.
  local nome_no_kernel estado_100 estado_200
  nome_no_kernel=$(vm "ip -br link show lgv0.100 2>/dev/null | awk '{print \$1}'" | tr -d '\r' | head -1)
  estado_100=$(vm "ip -br link show lgv0.100 2>/dev/null | awk '{print \$2}'" | tr -d '\r' | head -1)
  estado_200=$(vm "ip -br link show lgv0.200 2>/dev/null | awk '{print \$2}'" | tr -d '\r' | head -1)
  if [[ "$nome_no_kernel" != *"@"* ]]; then
    bad "o kernel desta caixa não imprime o sufixo '@mãe'; a bateria mediria um defeito que não existe aqui" \
        "nome lido: '${nome_no_kernel:-vazio}'"
    encerra_x "o cenário do defeito não pôde ser montado"
    return
  fi
  if [[ "$estado_100" != "UP" || "$estado_200" == "UP" ]]; then
    bad "as duas VLANs de teste não ficaram nos estados que a bateria compara" \
        "lgv0.100='$estado_100' (queria UP), lgv0.200='$estado_200' (queria não-UP)"
    encerra_x "o par de comparação não pôde ser montado"
    return
  fi
  ok "duas VLANs montadas, uma no ar e uma derrubada (o kernel as nomeia '$nome_no_kernel')"

  local st_a st_b
  st_a=$(status POST /api/links "$tok" '{"name":"VLAN no ar","interface":"lgv0.100","gateway":"10.58.100.2","ip_address":"10.58.100.1","weight":1,"enabled":true,"monitor_hosts":"10.58.100.2","dns_test":"10.58.100.2"}')
  st_b=$(status POST /api/links "$tok" '{"name":"VLAN derrubada","interface":"lgv0.200","gateway":"10.58.200.2","ip_address":"10.58.200.1","weight":1,"enabled":true,"monitor_hosts":"10.58.200.2","dns_test":"10.58.200.2"}')
  # 200 OU 201: o handler devolve Created, e é o que todas as outras baterias
  # desta suíte já aceitam. Comparar só com 200 reprovava um cadastro que tinha
  # dado certo — e a bateria acusava o painel de recusar o que ele acabara de
  # aceitar.
  if [[ ("$st_a" != "200" && "$st_a" != "201") || ("$st_b" != "200" && "$st_b" != "201") ]]; then
    bad "o painel não aceitou cadastrar as WANs em VLAN ($st_a / $st_b)"
    encerra_x "as WANs de teste não entraram"
    return
  fi
  sleep 3

  # excluidos_x IFACE → "sim" se o balanceador a jogou fora, "nao" se não, e
  # "erro" quando a interface não aparece em lado nenhum do plano: nesse caso a
  # leitura falhou, e "nao" seria um verde comprado com uma leitura quebrada.
  excluidos_x() {
    body GET /api/routing/balance "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin); p=d.get('plan') or {}
ex={n.get('interface') for n in (p.get('excluded') or [])}
todos={n.get('interface') for n in (p.get('nexthops') or [])} | ex
alvo=sys.argv[1]
print('erro' if alvo not in todos else ('sim' if alvo in ex else 'nao'))" "$1" 2>/dev/null
  }

  # X1 — O CONSERTO: a VLAN no ar deixa de ser tratada como caída.
  local fora_100; fora_100=$(excluidos_x lgv0.100)
  if [[ "$fora_100" == "nao" ]]; then
    ok "a WAN em VLAN no ar deixou de ser tratada como fora do ar"
  elif [[ "$fora_100" == "sim" ]]; then
    bad "A WAN EM VLAN CONTINUA SENDO EXCLUÍDA: o cliente contrata dois links e o produto usa um" \
        "$(body GET /api/routing/balance "$tok" | head -c 220)"
  else
    bad "não consegui ler o plano do balanceador para a VLAN no ar; o conserto não foi medido" "$fora_100"
  fi
  M_X1=1

  # X2 — A METADE DE SILÊNCIO: a VLAN derrubada CONTINUA fora.
  #
  # Sem esta, a X1 passaria igual num produto que parou de excluir qualquer
  # coisa — e aí um link de verdade fora do ar seguiria carregando tráfego, que
  # é pior do que o defeito consertado. As duas são VLAN, montadas na mesma
  # interface-mãe: a única diferença entre elas é o estado do link.
  local fora_200; fora_200=$(excluidos_x lgv0.200)
  if [[ "$fora_200" == "sim" ]]; then
    ok "a VLAN derrubada continua fora do balanceamento — o filtro não parou de filtrar"
  elif [[ "$fora_200" == "nao" ]]; then
    bad "O FILTRO PAROU DE FILTRAR: uma interface fora do ar entrou no balanceamento" \
        "$(body GET /api/routing/balance "$tok" | head -c 220)"
  else
    bad "não consegui ler o plano do balanceador para a VLAN derrubada; a metade de silêncio não foi medida" "$fora_200"
  fi
  M_X2=1

  limpa_x
}

# ─── W. Fixação de conexão de saída na WAN (issue #120, a outra ponta) ───────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. Em modo balanceado a rota padrão é
# multipath e o kernel escolhe o caminho por hash. Quando a rota é REESCRITA —
# um peso muda, um link cai e volta, o DHCP do provedor renova o gateway — o
# hash muda de resposta e as conexões ABERTAS pulam de link. Pular de link não
# degrada: mata. O conntrack já guardou a tradução de origem para o endereço da
# WAN antiga, o pacote sai pela nova levando o endereço da outra, e o provedor
# descarta por uRPF. Download reabre e parece só "travar um instante"; chamada
# de vídeo e jogo online morrem calados.
#
# A METADE DE SILÊNCIO, E ELA TEM NOME. Numa revisão adversarial descobriu-se
# que uma versão anterior desta mudança mandava a RESPOSTA DA INTERNET de volta
# para o provedor: a restauração de ENTRADA continuou lendo `ct mark != 0` com
# o significado antigo ("a conexão entrou por uma WAN") depois de a memória de
# saída passar a dar marca também a quem nasceu na LAN. Resultado: a LAN
# inteira sem internet, no instante da reconciliação e persistido para o
# próximo boot — enquanto a PRÓPRIA CAIXA continuava navegando, porque o
# tráfego dela nasce no hook output e não atravessa o forward. É um apagão que
# um handshake TCP de dois segundos pega, e é por isso que aqui quem fala é um
# host da LAN atrás do firewall; a caixa é medida em SEPARADO, e só para dizer
# no log que ela navegar não prova nada.
#
# O CENÁRIO NÃO EXISTE DE GRAÇA, E A PRIMEIRA VERSÃO DESTA BATERIA NÃO RODOU
# POR ISSO. O modo PADRÃO é o failover (balancer/service.go), e em failover
# ninguém escreve a default da `main`: o failover mexe só em `table <id>`. Uma
# bateria que cadastra duas WANs e espera `ip route show default` adotá-las
# espera para sempre — bate o teto, imprime uma falha que é do arnês e pula as
# seis asserções. Aqui o balanceamento é LIGADO PELO PAINEL
# (`PUT /api/routing/balance`), e a janela armada que essa troca abre é
# CONFIRMADA na hora: sem o confirm, os 90 segundos de auto-reversão desfazem a
# rota no meio da bateria e o sintoma seria "a conexão morreu na reescrita",
# acusando o produto por um relógio do arnês.
#
# COMO SE MONTA ISSO SEM DUAS OPERADORAS. Duas WANs de mentira (veth + netns),
# cada uma com a MESMA "internet" atrás dela (172.31.99.9 no lo) e cada
# servidor devolvendo a própria etiqueta. A etiqueta que volta diz por qual WAN
# a conexão saiu — e é assim que se prova que ela CONTINUOU saindo pela mesma
# depois de a rota ser reescrita, em vez de se acreditar na ausência de erro.
#
# A REESCRITA E O CONTROLE, que é o que separa medir de torcer. O gatilho é uma
# mudança de PESO pelo painel seguida de `POST /api/routing/balance/apply` — o
# produto recalculando e reinstalando a própria rota, com quase todo o espaço
# de hash jogado para a OUTRA WAN. Derrubar o link em uso seria mais dramático
# e mediria outra coisa: link desabilitado sai da lista de WANs, e aí a
# restauração de ENTRADA deixa de reconhecer a interface por onde a resposta
# volta — a conexão morreria por um efeito de borda, não por falta de fixação.
#
# E o controle é uma conexão NOVA, aberta depois da reescrita, do mesmo host
# para o mesmo destino: com o hash multipath fixado em L3 (o arnês fixa e
# devolve o sysctl), ela responde exatamente a pergunta "para onde este par de
# endereços vai agora?". Se a conexão nova mudou de WAN e a conexão ABERTA não
# mudou, a diferença entre as duas é a marca — não é sorte. Se a conexão nova
# NÃO mudou de WAN, a reescrita não moveu esta tupla e a asserção é dita NÃO
# MEDIDA, em vez de verde.
#
# E a bateria termina pelo encaminhamento de porta, que é a metade da #120 que
# uma versão errada desta mudança quebra: quem fixa a saída sem o guarda de
# interface re-marca a resposta que vem de fora. O cliente dele fala de um
# endereço FORA da sub-rede do enlace, senão a resposta acerta a WAN pela rota
# conectada da `main` e a asserção passa com a marcação desligada.
battery_fixacao_saida() {
  head_ "W. Fixação de conexão de saída na WAN"

  # Cada asserção tem um marcador. Quem sair pelo meio chama encerra_w, que
  # PULA por nome tudo o que não chegou a ser medido — bateria que aborta
  # calada deixa o resumo dizer "0 falhas" sobre asserção que nunca rodou. E
  # asserção que já FALHOU marca o próprio marcador antes de sair: PULADA quer
  # dizer "não medi", e dizer as duas coisas sobre a mesma linha é mentira nos
  # dois sentidos.
  local M_W1=0 M_W2=0 M_W3=0 M_W4=0 M_W4B=0 M_W5=0 M_W6=0
  local desligados="" id_a="" id_b="" tab_a="" tab_b="" pf_criado=0
  local usada="" outra="" if_usada="" if_outra="" marca="" sport=""
  local tok="" modo_trocado=0 rota_original="" gw_orig="" dev_orig=""
  local rpf_orig="" hash_orig="" etiqueta="" lan_ok=0 LINHA_CT=""

  # limpa_w desfaz o que a bateria montou, e é chamada de TODO caminho de
  # saída. Três pedaços dela não são arrumação, são a condição de existência
  # das baterias seguintes — e por isso têm ASSERÇÃO, não `>/dev/null`:
  # religar os links detectados, devolver o modo de roteamento ao failover e
  # terminar com uma rota padrão que sai desta caixa. A lição da S é que sem
  # WAN o produto nem emite as regras, e a bateria seguinte falharia dizendo
  # que a feature não existe. Cada pedaço é independente do outro — nada aqui
  # pode depender de uma etapa que talvez não tenha acontecido.
  limpa_w() {
    if [[ -n "$tok" ]]; then
      # O DELETE do encaminhamento lê o id da QUERY STRING (handlers/
      # portforward.go: `r.URL.Query().Get("id")`); com o id só no corpo o
      # produto devolve 400 e o encaminhamento SOBREVIVE à bateria, apontando
      # para um host da LAN que deixou de existir — e persistido no snapshot.
      if [[ "$pf_criado" == 1 ]]; then
        local pfid st_pf
        pfid=$(body GET /api/portforward "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ls=d if isinstance(d,list) else d.get('forwards',[])
for f in ls:
    if f.get('dest_ip')=='192.168.121.2': print(f.get('id',''))" 2>/dev/null)
        if [[ -n "$pfid" ]]; then
          st_pf=$(status DELETE "/api/portforward?id=$pfid" "$tok")
          if [[ "$st_pf" == "200" ]]; then ok "o encaminhamento de teste foi removido pelo painel"
          else bad "não consegui remover o encaminhamento de teste ($st_pf): ele fica na chain de DNAT apontando para um host que não existe mais" "id=$pfid"; fi
        else
          bad "não achei o id do encaminhamento de teste para removê-lo" "$(body GET /api/portforward "$tok" | head -c 200)"
        fi
      fi
      local id
      for id in $id_a $id_b; do
        status DELETE "/api/links/$id" "$tok" >/dev/null 2>&1
      done
      # OS LINKS DETECTADOS VOLTAM, E ISSO É COBRADO. muda_link devolve pista
      # quando falha; um PUT com corpo vazio (o GET que não veio, o python que
      # morreu) deixaria a caixa sem WAN nenhuma em silêncio, e o custo seria a
      # suíte inteira depois desta bateria.
      local falhou="" pista
      for id in $desligados; do
        pista=$(muda_link "$id" enabled true) || falhou="$falhou $id($pista)"
      done
      if [[ -n "$desligados" ]]; then
        if [[ -z "$falhou" ]]; then
          local ainda
          ainda=$(body GET /api/links "$tok" | python3 -c "
import json,sys
alvos=set(sys.argv[1].split())
for l in json.load(sys.stdin):
    if l.get('id') in alvos and not l.get('enabled'): print(l.get('interface',l['id']))" "$desligados" 2>/dev/null | tr '\n' ' ')
          if [[ -z "$ainda" ]]; then ok "os links detectados voltaram ligados (as baterias seguintes têm WAN)"
          else bad "link(s) continuam desligados depois da limpeza: as baterias seguintes rodam sem WAN" "$ainda"; fi
        else
          bad "não consegui religar link(s) detectado(s): as baterias seguintes rodam sem WAN" "$falhou"
        fi
      fi
      # O modo volta ao failover, que é o padrão do produto. Sair daqui em
      # modo balanceado deixaria o balanceador dono da rota padrão para as
      # baterias seguintes, que não pediram isso.
      if [[ "$modo_trocado" == 1 ]]; then
        status POST "/api/routing/balance/apply?arm=false" "$tok" >/dev/null 2>&1
        status PUT /api/routing/balance "$tok" '{"mode":"failover","table":"main","arm_seconds":90,"schedules":[]}' >/dev/null 2>&1
      fi
    fi

    vm "pkill -f lgw_serv >/dev/null 2>&1; pkill -f lgw_fixa >/dev/null 2>&1
        ip netns del wana 2>/dev/null; ip netns del wanb 2>/dev/null; ip netns del lanw 2>/dev/null
        ip link del lg-wana 2>/dev/null; ip link del lg-wanb 2>/dev/null; ip link del lg-lanw 2>/dev/null
        rm -f /tmp/lgw_serv.py /tmp/lgw_fala.py /tmp/lgw_fixa.py /tmp/lgw_fixa.out /tmp/lgw_go; true" >/dev/null 2>&1
    [[ -n "$rpf_orig"  ]] && vm "sysctl -w net.ipv4.conf.all.rp_filter=$rpf_orig" >/dev/null 2>&1
    [[ -n "$hash_orig" ]] && vm "sysctl -w net.ipv4.fib_multipath_hash_policy=$hash_orig" >/dev/null 2>&1
    rm -f /tmp/lgw_link.json

    # A ÚLTIMA COISA QUE ESTA BATERIA DEVE À SUÍTE: uma rota padrão que não
    # aponta para uma interface que ela mesma acabou de apagar.
    if [[ "$modo_trocado" == 1 || -n "$desligados" ]]; then
      local rota_fim i
      for i in $(seq 1 10); do
        rota_fim=$(vm "ip route show default" | tr -d '\r' | tr '\n' ' ')
        # Sem gateway de origem anotado não há o que esperar: espera com teto
        # vira espera cega, e trinta segundos por bateria é o que ninguém vê.
        [[ -z "$gw_orig" ]] && break
        grep -qF "via $gw_orig" <<<"$rota_fim" && break
        sleep 3
      done
      if [[ -n "$gw_orig" ]] && grep -qF "via $gw_orig" <<<"$rota_fim"; then
        ok "a caixa termina a bateria com a rota padrão de antes (via $gw_orig)"
      else
        # Rede de segurança do arnês, e ela é FALHA mesmo funcionando: se o
        # produto não devolveu a rota, quem devolveu foi este script.
        [[ -n "$gw_orig" && -n "$dev_orig" ]] && vm "ip route replace default via $gw_orig dev $dev_orig" >/dev/null 2>&1
        bad "a rota padrão não voltou ao que era; o arnês a restaurou à força para não derrubar as baterias seguintes" \
            "antes: ${rota_original:-vazia} | depois: ${rota_fim:-vazia}"
      fi
    fi
  }

  encerra_w() {
    local motivo="$1"
    [[ "$M_W1"  == 1 ]] || pular "W1. As três chains e os caminhos por marca, lidos do kernel" "$motivo"
    [[ "$M_W2"  == 1 ]] || pular "W2. Um host da LAN atravessa o firewall" "$motivo"
    [[ "$M_W3"  == 1 ]] || pular "W3. A conexão de saída guarda a marca da WAN por onde saiu" "$motivo"
    [[ "$M_W4"  == 1 ]] || pular "W4. A conexão aberta sobrevive à reescrita da rota" "$motivo"
    [[ "$M_W4B" == 1 ]] || pular "W4b. A rota marcada, perguntada ao kernel" "$motivo"
    [[ "$M_W5"  == 1 ]] || pular "W5. O encaminhamento de porta continua respondendo" "$motivo"
    [[ "$M_W6"  == 1 ]] || pular "W6. A caixa navegar não conta como prova" "$motivo"
    limpa_w
  }

  # ── Ajudantes de medição ───────────────────────────────────────────────────

  # fala NETNS HOST PORTA [ORIGEM] → a etiqueta que o outro lado devolveu, ou
  # "erro:X". NETNS vazio mede a PRÓPRIA CAIXA, que é uma medida diferente de
  # propósito (ver W6). ORIGEM liga o cliente a um endereço específico, que é o
  # que tira o encaminhamento de porta de cima da rota conectada do enlace.
  # O cliente é um arquivo na VM e não um -c gigante: a versão com aspas dentro
  # de aspas dentro do ssh já quebrou uma vez e a falha parecia do produto. E o
  # `timeout` do shell é MAIOR que o pior caso do próprio cliente (4s+4s):
  # menor, ele mataria o cliente antes do diagnóstico e "não conectou" chegaria
  # igual a "conectou e não respondeu".
  fala() {
    local pre=""
    [[ -n "$1" ]] && pre="ip netns exec $1 "
    vm "${pre}timeout 12 python3 /tmp/lgw_fala.py $2 $3 ${4:-} 2>/dev/null" | tr -d '\r' | tail -1
  }

  # ler_link INTERFACE CAMPO → o campo daquele link, pelo painel.
  ler_link() {
    body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l.get('interface')==sys.argv[1]: print(l.get(sys.argv[2],''))" "$1" "$2" 2>/dev/null
  }

  # muda_link ID CAMPO VALOR → "ok", ou uma pista e código de saída != 0.
  # Muda PELO PAINEL, com o objeto inteiro de volta: `ip link set down` não
  # passa por reconciliação nenhuma e provaria outra coisa.
  #
  # Os três sumidouros que esta versão fecha, e que a bateria S ainda tem: o
  # GET que não é JSON (o `>` já truncou o arquivo e o 2>/dev/null comeu o
  # traceback), o corpo vazio (que o api() DESCARTA, mandando um PUT sem
  # payload) e o status do PUT indo para /dev/null. Os três davam no-op mudo —
  # e o no-op mudo desta função é a caixa sem WAN.
  muda_link() {
    local atual st
    atual=$(body GET "/api/links/$1" "$tok")
    python3 -c "
import json,sys
d=json.loads(sys.argv[1])
v=sys.argv[3]
d[sys.argv[2]] = (v=='true') if v in ('true','false') else int(v)
print(json.dumps(d))" "$atual" "$2" "$3" > /tmp/lgw_link.json 2>/dev/null
    if [[ ! -s /tmp/lgw_link.json ]]; then echo "sem-json:$(head -c 60 <<<"$atual")"; return 1; fi
    st=$(status PUT "/api/links/$1" "$tok" "$(cat /tmp/lgw_link.json)")
    [[ "$st" == "200" || "$st" == "204" ]] || { echo "http:$st"; return 1; }
    echo ok
  }

  # plano_ifaces → as interfaces que o BALANCEADOR diz que vão carregar
  # tráfego. É a resposta do próprio produto para "esta rota é multipath?", e
  # por isso é ela que o portão espera — não um sleep.
  plano_ifaces() {
    body GET /api/routing/balance "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
nh=(d.get('plan') or {}).get('nexthops') or []
print(' '.join(sorted(n.get('interface','') for n in nh)))" 2>/dev/null
  }

  rota_default() { vm "ip route show default" | tr -d '\r' | tr '\n' ' '; }

  # marca_do_fluxo SPORT → a marca que o conntrack guardou PARA ESTA CONEXÃO,
  # em decimal, ou vazio.
  #
  # A porta de origem não é preciosismo: quando o W3 roda já existem outros
  # fluxos de 192.168.121.2 para a mesma internet de mentira (o handshake do W2
  # ainda em TIME_WAIT), e um `head -1` sobre a ordem de hash do conntrack
  # podia ler o fluxo errado — acusando o produto de guardar "a marca de outro
  # caminho" por uma leitura do arnês. A porta de destino também é exclusiva da
  # conexão longa (18097), que é cinto e suspensório de propósito.
  #
  # Duas fontes, porque a ausência da ferramenta não pode virar "a marca está
  # errada": se nenhuma responder, a asserção é dita NÃO MEDIDA, e não verde.
  # E o `mark=` é ANCORADO — sem a âncora ele casa dentro de `secmark=0`, que é
  # a mesma família do "22," casando dentro de "2222," que esta suíte já pagou.
  marca_do_fluxo() {
    local linha
    linha=$(vm "conntrack -L -p tcp --sport $1 --dport 18097 2>/dev/null | head -1" | tr -d '\r' | head -1)
    [[ -n "$linha" ]] || linha=$(vm "grep -E 'sport=$1 dport=18097' /proc/net/nf_conntrack 2>/dev/null | head -1" | tr -d '\r' | head -1)
    # Segunda tentativa só pela porta de origem: a porta é sorteada e não se
    # repete nesta janela, então ela sozinha identifica o fluxo deste cliente.
    [[ -n "$linha" ]] || linha=$(vm "grep -E 'sport=$1 ' /proc/net/nf_conntrack 2>/dev/null | head -1" | tr -d '\r' | head -1)
    LINHA_CT="$linha"
    [[ -n "$linha" ]] || { echo ""; return 0; }
    grep -oE '(^| )mark=[0-9]+' <<<"$linha" | head -1 | cut -d= -f2
  }

  # ── Sessão ─────────────────────────────────────────────────────────────────
  local initial
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  if [[ -z "$tok" ]]; then
    bad "sem sessão administrativa; a bateria W não roda"
    encerra_w "sem sessão administrativa"
    return
  fi

  # A postura do que ATRAVESSA precisa ser accept, mas trocá-la por trocar abre
  # uma janela de confirmação de 90 segundos que recusa toda mutação guardada
  # enquanto durar. Lê-se antes; e se a troca acontecer, ela é CONFIRMADA na
  # hora, como a bateria N aprendeu a fazer.
  local postura
  postura=$(body GET /api/nftables/policy "$tok" | jqk forward)
  if [[ "$postura" != "accept" ]]; then
    status PUT /api/nftables/policy "$tok" '{"policy":"accept","chain":"forward"}' >/dev/null
    local janela
    janela=$(body GET /api/nftables/pending "$tok" | jqk pending.id)
    [[ -n "$janela" ]] && status POST /api/nftables/pending/confirm "$tok" "{\"id\":\"$janela\"}" >/dev/null
  fi

  rota_original=$(rota_default)
  gw_orig=$(grep -oE 'via [0-9]+(\.[0-9]+){3}' <<<"$rota_original" | head -1 | cut -d' ' -f2)
  dev_orig=$(grep -oE 'dev [A-Za-z0-9@._-]+' <<<"$rota_original" | head -1 | cut -d' ' -f2)

  # ── Montagem: duas WANs de mentira e um host de LAN, cada um na sua netns ──
  #
  # As duas netns de WAN têm o MESMO endereço de "internet" (172.31.99.9 no lo)
  # e etiquetas diferentes: a etiqueta que volta é o único jeito honesto de
  # saber por onde a conexão saiu, e é ela que responde a pergunta da bateria.
  # Cada uma tem também um endereço FORA da sub-rede do enlace (203.0.113.9 e
  # .19), que é de onde o cliente do encaminhamento de porta vai falar.
  vm "pkill -f lgw_serv >/dev/null 2>&1; pkill -f lgw_fixa >/dev/null 2>&1
      ip netns del wana 2>/dev/null; ip netns del wanb 2>/dev/null; ip netns del lanw 2>/dev/null
      ip link del lg-wana 2>/dev/null; ip link del lg-wanb 2>/dev/null; ip link del lg-lanw 2>/dev/null
      rm -f /tmp/lgw_fixa.out /tmp/lgw_go; true" >/dev/null 2>&1
  vm "ip netns add wana && ip netns add wanb && ip netns add lanw && \
      ip link add lg-wana type veth peer name wana-far && \
      ip link add lg-wanb type veth peer name wanb-far && \
      ip link add lg-lanw type veth peer name lanw-far && \
      ip link set wana-far netns wana && ip link set wanb-far netns wanb && ip link set lanw-far netns lanw && \
      ip addr add 172.31.10.1/24 dev lg-wana && ip link set lg-wana up && \
      ip addr add 172.31.20.1/24 dev lg-wanb && ip link set lg-wanb up && \
      ip addr add 192.168.121.1/24 dev lg-lanw && ip link set lg-lanw up && \
      ip netns exec wana sh -c 'ip link set lo up; ip addr add 172.31.10.2/24 dev wana-far; ip addr add 172.31.99.9/32 dev lo; ip addr add 203.0.113.9/32 dev lo; ip link set wana-far up; ip route add 172.31.10.1 dev wana-far; ip route add default via 172.31.10.1' && \
      ip netns exec wanb sh -c 'ip link set lo up; ip addr add 172.31.20.2/24 dev wanb-far; ip addr add 172.31.99.9/32 dev lo; ip addr add 203.0.113.19/32 dev lo; ip link set wanb-far up; ip route add 172.31.20.1 dev wanb-far; ip route add default via 172.31.20.1' && \
      ip netns exec lanw sh -c 'ip link set lo up; ip addr add 192.168.121.2/24 dev lanw-far; ip link set lanw-far up; ip route add default via 192.168.121.1'" >/dev/null 2>&1

  # DOIS SYSCTLS DO ARNÊS, os dois lidos antes e devolvidos na limpeza.
  #
  # rp_filter: o cliente do encaminhamento fala de 203.0.113.9, cujo caminho de
  # volta é a rota padrão — que estará pendendo para a OUTRA WAN. Com filtro
  # estrito o kernel descarta esse pacote e a falha seria creditada ao produto.
  #
  # fib_multipath_hash_policy: fixado em L3 para que o CONTROLE do W4 (uma
  # conexão nova, do mesmo par de endereços) responda pela mesma tupla de hash
  # que a conexão medida. Com hash L4 as duas tuplas são diferentes e o
  # controle deixaria de falar pelo fluxo que ele controla.
  rpf_orig=$(vm "cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null" | tr -d '\r' | head -1)
  hash_orig=$(vm "cat /proc/sys/net/ipv4/fib_multipath_hash_policy 2>/dev/null" | tr -d '\r' | head -1)
  vm "sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1
      sysctl -w net.ipv4.conf.lg-wana.rp_filter=0 >/dev/null 2>&1
      sysctl -w net.ipv4.conf.lg-wanb.rp_filter=0 >/dev/null 2>&1
      sysctl -w net.ipv4.conf.lg-lanw.rp_filter=0 >/dev/null 2>&1
      sysctl -w net.ipv4.fib_multipath_hash_policy=0 >/dev/null 2>&1; true" >/dev/null 2>&1

  vm "cat > /tmp/lgw_serv.py <<'PYEOF'
import socket, sys, threading
etiqueta = sys.argv[1].encode()
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((sys.argv[2], int(sys.argv[3])))
srv.listen(16)
def atende(c):
    try:
        while True:
            if not c.recv(64): return
            c.sendall(etiqueta + b'\n')
    except Exception:
        return
    finally:
        c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=atende, args=(c,), daemon=True).start()
PYEOF
      cat > /tmp/lgw_fala.py <<'PYEOF'
import socket, sys
try:
    origem = sys.argv[3] if len(sys.argv) > 3 else ''
    s = socket.socket()
    if origem:
        s.bind((origem, 0))
    s.settimeout(4)
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.sendall(b'oi\n')
    print(s.recv(64).decode(errors='replace').strip())
    s.close()
except Exception as e:
    print('erro:' + type(e).__name__)
PYEOF
      cat > /tmp/lgw_fixa.py <<'PYEOF'
import os, socket, sys, time
saida = open('/tmp/lgw_fixa.out', 'w', buffering=1)
try:
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), 6)
    s.settimeout(10)
    # A porta de origem vai para o arquivo ANTES da primeira troca: é por ela
    # que o arnês acha ESTA conexão no conntrack, e não outra do mesmo host.
    saida.write('sport=%d\n' % s.getsockname()[1])
    s.sendall(b'1\n')
    saida.write('r1=' + s.recv(64).decode(errors='replace').strip() + '\n')
    # A conexão fica ABERTA e parada enquanto o arnês reescreve a rota. O
    # gatilho é um arquivo e não um sleep: assim a segunda metade acontece
    # DEPOIS da reescrita, e não perto dela.
    t0 = time.time()
    while not os.path.exists('/tmp/lgw_go') and time.time() - t0 < 240:
        time.sleep(0.5)
    s.settimeout(20)
    s.sendall(b'2\n')
    saida.write('r2=' + s.recv(64).decode(errors='replace').strip() + '\n')
except Exception as e:
    saida.write('erro=' + type(e).__name__ + '\n')
saida.write('fim\n')
PYEOF
      ip netns exec wana setsid python3 /tmp/lgw_serv.py saude 172.31.10.2 443 >/dev/null 2>&1 < /dev/null &
      ip netns exec wanb setsid python3 /tmp/lgw_serv.py saude 172.31.20.2 443 >/dev/null 2>&1 < /dev/null &
      ip netns exec wana setsid python3 /tmp/lgw_serv.py wana 172.31.99.9 18099 >/dev/null 2>&1 < /dev/null &
      ip netns exec wana setsid python3 /tmp/lgw_serv.py wana 172.31.99.9 18097 >/dev/null 2>&1 < /dev/null &
      ip netns exec wanb setsid python3 /tmp/lgw_serv.py wanb 172.31.99.9 18099 >/dev/null 2>&1 < /dev/null &
      ip netns exec wanb setsid python3 /tmp/lgw_serv.py wanb 172.31.99.9 18097 >/dev/null 2>&1 < /dev/null &
      ip netns exec lanw setsid python3 /tmp/lgw_serv.py lan 192.168.121.2 18098 >/dev/null 2>&1 < /dev/null &
      sleep 1" >/dev/null 2>&1

  # PORTÃO: os servidores de mentira estão de pé DENTRO da própria netns? Esta
  # medida não atravessa firewall nenhum. Sem ela, um servidor que não subiu
  # faria a bateria inteira acusar o produto de um apagão que é do arnês.
  local eco_a eco_b eco_l
  eco_a=$(fala wana 172.31.99.9 18099)
  eco_b=$(fala wanb 172.31.99.9 18099)
  eco_l=$(fala lanw 192.168.121.2 18098)
  if [[ "$eco_a" == "wana" && "$eco_b" == "wanb" && "$eco_l" == "lan" ]]; then
    ok "as internets de mentira e o host da LAN respondem dentro da própria netns (rp_filter era '${rpf_orig:-?}', hash multipath era '${hash_orig:-?}'; o arnês devolve os dois na limpeza)"
  else
    bad "o cenário não subiu: os servidores de teste não respondem nem localmente (A='${eco_a:-nada}', B='${eco_b:-nada}', LAN='${eco_l:-nada}')" \
        "$(vm "ip netns list 2>&1; ip -br addr show lg-wana lg-wanb lg-lanw 2>&1" | tr -d '\r' | tr '\n' ' ' | head -c 220)"
    encerra_w "veth/netns não subiram nesta máquina"
    return
  fi

  # As WANs entram PELO PAINEL, que é o que dispara a reconciliação — e é a
  # única forma de a marcação de conexão e a tabela de rota existirem.
  local st
  st=$(status POST /api/links "$tok" '{"name":"WAN W-A","interface":"lg-wana","gateway":"172.31.10.2","ip_address":"172.31.10.1","weight":1,"enabled":true,"monitor_hosts":"172.31.10.2","dns_test":"172.31.10.2"}')
  if [[ "$st" != "200" && "$st" != "201" ]]; then
    bad "não consegui cadastrar a WAN de teste A: $st"
    encerra_w "a WAN de teste A não foi aceita pelo painel"
    return
  fi
  st=$(status POST /api/links "$tok" '{"name":"WAN W-B","interface":"lg-wanb","gateway":"172.31.20.2","ip_address":"172.31.20.1","weight":1,"enabled":true,"monitor_hosts":"172.31.20.2","dns_test":"172.31.20.2"}')
  if [[ "$st" != "200" && "$st" != "201" ]]; then
    bad "não consegui cadastrar a WAN de teste B: $st"
    encerra_w "a WAN de teste B não foi aceita pelo painel"
    return
  fi
  ok "as duas WANs de teste entraram pelo painel"
  sleep 2

  id_a=$(ler_link lg-wana id);        id_b=$(ler_link lg-wanb id)
  tab_a=$(ler_link lg-wana table_id); tab_b=$(ler_link lg-wanb table_id)
  # `table_id` é INTEGER NOT NULL DEFAULT 0 no banco, e um zero aqui envenena
  # tudo o que vem depois: a marca esperada viraria 0, e um fluxo SEM MARCA
  # NENHUMA lê 0 no conntrack — o W3 imprimiria verde para a feature desligada.
  if [[ -z "$id_a" || -z "$id_b" ]] || ! [[ "$tab_a" =~ ^[1-9][0-9]*$ && "$tab_b" =~ ^[1-9][0-9]*$ ]]; then
    bad "as WANs de teste não receberam identidade e tabela de rota utilizável" \
        "id_a='$id_a' id_b='$id_b' tabela_a='$tab_a' tabela_b='$tab_b'"
    encerra_w "sem tabela de rota, não há fixação para medir"
    return
  fi

  # ISOLAMENTO DEPOIS DE AS WANS DE TESTE EXISTIREM, e a ordem é a lição da
  # bateria S: desligar os links detectados ANTES deixa a caixa sem WAN
  # nenhuma, e sem WAN a marcação de conexão nem sequer é emitida — as
  # asserções seguintes falhariam dizendo que a feature não existe.
  desligados=$(body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l.get('enabled') and l.get('interface') not in ('lg-wana','lg-wanb'): print(l['id'])" 2>/dev/null)
  local id pista falhou=""
  for id in $desligados; do
    pista=$(muda_link "$id" enabled false) || falhou="$falhou $id($pista)"
  done
  local n_desl; n_desl=$(wc -w <<<"$desligados")
  if [[ "$n_desl" -gt 0 && -z "$falhou" ]]; then
    ok "$n_desl link(s) detectado(s) saíram do caminho para o isolamento"
  else
    bad "o isolamento não desligou os links detectados: a WAN real divide a rota padrão com as de teste e o tráfego da LAN pode sair por ela" \
        "desligados=$n_desl falhas=${falhou:-nenhuma} | $(body GET /api/links "$tok" | head -c 200)"
    encerra_w "os links reais continuaram no caminho"
    return
  fi

  # AS DUAS WANS DE TESTE PRECISAM FICAR ONLINE, e isto não é capricho de
  # cenário bonito: o failover reage a link offline APAGANDO o default da
  # tabela daquele link (failover/service.go, handleLinkDown). Sem esse default,
  # a `ip rule fwmark` cai numa tabela vazia, escorrega para a main e a fixação
  # deixa de existir — a bateria mediria o produto sem a metade de roteamento e
  # chamaria isso de defeito da marcação. Por isso cada netns de WAN atende
  # também na porta que o monitor do produto disca (443 no endereço do
  # gateway): a saúde é medida pelo caminho do produto, não fingida no banco.
  local estados="" i
  for i in $(seq 1 18); do
    estados=$(body GET /api/links "$tok" | python3 -c "
import json,sys
d={l.get('interface'):l.get('status') for l in json.load(sys.stdin)}
print('%s/%s' % (d.get('lg-wana',''), d.get('lg-wanb','')))" 2>/dev/null)
    [[ "$estados" == "online/online" ]] && break
    sleep 5
  done
  if [[ "$estados" == "online/online" ]]; then
    ok "as duas WANs de teste estão online pelo monitor do produto"
  else
    bad "as WANs de teste não ficaram online em 90s ('${estados:-nada}'): o failover apagaria o default da tabela do link e não haveria fixação para medir" \
        "$(vm "ss -lnt 2>/dev/null | head -6" | tr -d '\r' | tr '\n' ' ' | head -c 200)"
    encerra_w "as WANs de teste não ficaram online"
    return
  fi

  # O BALANCEAMENTO É LIGADO PELO PAINEL, e a janela armada é confirmada na
  # hora. Sem o modo balanceado NÃO EXISTE rota multipath nesta caixa: o modo
  # padrão é failover, e nele o produto só escreve `table <id>` — a premissa
  # inteira desta bateria ("o kernel escolhe o caminho por hash") seria falsa e
  # todas as asserções abaixo mediriam outra coisa.
  st=$(status PUT /api/routing/balance "$tok" '{"mode":"balance","table":"main","arm_seconds":90,"evict_on_degrade":false,"schedules":[]}')
  if [[ "$st" != "200" ]]; then
    bad "o painel recusou ligar o balanceamento: $st"
    encerra_w "sem modo balanceado não há rota multipath para reescrever"
    return
  fi
  modo_trocado=1
  status POST /api/routing/balance/confirm "$tok" >/dev/null 2>&1

  # O portão espera o PRODUTO dizer que as duas WANs de teste carregam
  # tráfego — e só elas. Esperar com sleep aqui daria o mesmo verde para uma
  # rota de caminho único.
  local plano=""
  for i in $(seq 1 14); do
    plano=$(plano_ifaces)
    [[ "$plano" == "lg-wana lg-wanb" ]] && break
    sleep 5
  done
  if [[ "$plano" != "lg-wana lg-wanb" ]]; then
    bad "o balanceador não colocou as duas WANs de teste no plano em 70s: sem dois caminhos não há hash para mudar" "plano='${plano:-vazio}'"
    encerra_w "o plano do balanceador não ficou multipath"
    return
  fi
  st=$(status POST "/api/routing/balance/apply?arm=false" "$tok")
  if [[ "$st" != "200" ]]; then
    bad "o painel recusou aplicar a rota balanceada: $st"
    encerra_w "a rota balanceada não foi aplicada"
    return
  fi

  # A ROTA VIVIDA É PERGUNTADA AO KERNEL, E NÃO CASADA POR TEXTO NA TABELA.
  #
  # A primeira versão exigia que a default fosse EXCLUSIVAMENTE as duas WANs de
  # teste, e reprovava assim:
  #
  #   default  nexthop via 172.31.10.2 dev lg-wana weight 256 onlink
  #            nexthop via 172.31.20.2 dev lg-wanb weight 256 onlink
  #   default via 10.0.2.2 dev enp0s2 proto dhcp src 10.0.2.15 metric 100
  #
  # As duas coexistem porque o dhclient da VM instala a dela e o produto não a
  # remove — e não pode: é por esse enlace que esta própria suíte fala com a
  # caixa. Mas a multipath tem métrica 0 e a do DHCP métrica 100, então quem
  # decide já é a multipath. A asserção reprovava um cenário que estava certo.
  #
  # `ip route get`, com a origem e a interface de entrada do tráfego que a
  # bateria vai medir, é a pergunta exata: por onde ESTE pacote sairia? Ela
  # atravessa métrica, multipath e política de uma vez, em vez de reconstruir
  # essa lógica com grep.
  local rota="" saida=""
  for i in $(seq 1 10); do
    saida=$(vm "ip route get 172.31.99.9 from 192.168.121.2 iif lg-lanw 2>&1" | tr -d '\r' | tr '\n' ' ')
    grep -qE 'dev (lg-wana|lg-wanb)' <<<"$saida" && break
    sleep 3
  done
  rota=$(rota_default)
  if grep -qE 'dev (lg-wana|lg-wanb)' <<<"$saida"; then
    ok "o kernel manda o tráfego da LAN por uma das WANs de teste ($(grep -oE 'dev (lg-wana|lg-wanb)' <<<"$saida" | head -1))"
  else
    bad "o kernel não manda o tráfego da LAN pelas WANs de teste; o que for medido a seguir sai pelo caminho errado" \
        "ip route get: ${saida:-vazio} | default: ${rota:-vazia}"
    encerra_w "o kernel não roteia o tráfego da LAN pelas WANs de teste"
    return
  fi

  # ── W1 — AS TRÊS CHAINS E OS CAMINHOS POR MARCA, LIDOS DO KERNEL ───────────
  # O código Go não é fonte aqui: o que vale é o que o nft e o iproute2
  # imprimem na máquina.
  local pre fora saida_ch
  pre=$(vm "nft list chain inet linkguard conn_mark 2>/dev/null" | tr -d '\r')
  fora=$(vm "nft list chain inet linkguard conn_mark_out 2>/dev/null" | tr -d '\r')
  saida_ch=$(vm "nft list chain inet linkguard output_mark 2>/dev/null" | tr -d '\r')

  if grep -q 'hook prerouting priority mangle + 10' <<<"$pre"; then
    ok "a memória de entrada está no prerouting, depois da mark_hosts (mangle + 10)"
  else bad "a chain conn_mark não está no prerouting em mangle + 10 (ou não existe)" "$(tr '\n' ' ' <<<"${pre:-ausente}" | head -c 200)"; fi
  # output_mark é a chain cujo defeito é invisível: com `type filter` a marca é
  # escrita e ignorada — parece configurada e não faz nada. A H1 já cobra isso;
  # a bateria que se anuncia como a das TRÊS chains não pode cobrar menos.
  if grep -q 'type route hook output' <<<"$saida_ch"; then
    ok "a chain de saída da própria caixa é type route (o kernel refaz a rota)"
  else bad "a chain output_mark não é type route: a marca seria escrita e ignorada" "$(tr '\n' ' ' <<<"${saida_ch:-ausente}" | head -c 200)"; fi
  if grep -q 'type filter hook forward priority mangle' <<<"$fora"; then
    ok "a memória de saída está no forward, onde a interface de saída já está decidida"
  else bad "a chain conn_mark_out não está no forward (ou não existe)" "$(tr '\n' ' ' <<<"${fora:-ausente}" | head -c 200)"; fi

  # A memória de ENTRADA, uma regra por WAN, com `ct state new` — a condição
  # que o próprio código diz não ser economia: sem ela um pacote que chega pela
  # WAN errada no meio da conversa reescreve a marca e muda o caminho de volta
  # no meio do caminho.
  local hex_a hex_b faltando=""
  hex_a=$(printf '%x' "$tab_a"); hex_b=$(printf '%x' "$tab_b")
  # A marca de SAÍDA é o table_id com o bit 0x10000. O valor tem de ser
  # calculado inteiro: colar "1" na frente do hex do table_id dá 0x166 quando
  # o certo é 0x10066, e a asserção reprova uma regra que está correta.
  local saida_a saida_b
  saida_a=$(printf '%x' $(( tab_a + 65536 ))); saida_b=$(printf '%x' $(( tab_b + 65536 )))
  grep -qE "iifname \"lg-wana\" ct state new .*ct mark set 0x0*$hex_a( |\$)" <<<"$pre" || faltando="$faltando lg-wana"
  grep -qE "iifname \"lg-wanb\" ct state new .*ct mark set 0x0*$hex_b( |\$)" <<<"$pre" || faltando="$faltando lg-wanb"
  if [[ -z "$faltando" ]]; then
    ok "cada WAN grava, em conexão nova que entra por ela, a marca da tabela dela ($tab_a e $tab_b)"
  else bad "falta a regra de memória de entrada (com ct state new e a marca da tabela) para:$faltando" "$(tr '\n' ' ' <<<"$pre" | head -c 240)"; fi

  # AS DUAS RESTAURAÇÕES DO PREROUTING, CONFERIDAS UMA A UMA. Contar duas
  # linhas e procurar o nome das WANs não distingue nada: os nomes aparecem
  # DENTRO do conjunto negado das duas, então o grep estaria lendo o guarda, e
  # duas cópias da regra de resposta passariam pelo mesmo teste.
  local rest_reply rest_orig
  rest_reply=$(grep 'meta mark set ct mark' <<<"$pre" | grep 'ct direction reply' | head -1)
  rest_orig=$(grep 'meta mark set ct mark' <<<"$pre" | grep 'ct direction original' | head -1)
  # É AQUI QUE MORA O APAGÃO: sem `iifname != { WANs }` na regra VELHA (a de
  # resposta), a resposta da internet para um host da LAN é marcada com a WAN e
  # mandada para a tabela do link, que só tem o default do provedor.
  if [[ -n "$rest_reply" ]] && grep -q 'iifname != {' <<<"$rest_reply" &&
     grep -q '"lg-wana"' <<<"$rest_reply" && grep -q '"lg-wanb"' <<<"$rest_reply" &&
     ! grep -qE 'meta mark (== )?0x0+ ' <<<"$rest_reply"; then
    ok "a restauração de resposta restaura só o que NÃO entrou por uma WAN, e sem exigir marca zerada (a memória da conexão vence o @host_wan)"
  else
    bad "a restauração de resposta está fora de forma: sem o guarda de interface, a resposta da internet sai de volta para o provedor e a LAN fica sem internet" \
        "${rest_reply:-linha ausente} | conn_mark: $(tr '\n' ' ' <<<"$pre" | head -c 200)"
  fi
  if [[ -n "$rest_orig" ]] && grep -q 'iifname != {' <<<"$rest_orig" &&
     grep -qE 'meta mark (== )?0x0+ ' <<<"$rest_orig"; then
    ok "a restauração de saída casa a direção original, só o que veio da LAN, e cede a vez ao direcionamento por host"
  else
    bad "a restauração de saída perdeu uma das condições (direção original, guarda de interface, marca de pacote ainda zerada)" \
        "${rest_orig:-linha ausente}"
  fi

  # A GRAVAÇÃO DE SAÍDA, uma por WAN — a asserção que não pode olhar só a
  # primeira: se a regra da segunda WAN sumir, metade das conexões deixa de ter
  # dono e ninguém percebe.
  local grava_a grava_b
  grava_a=$(grep 'oifname "lg-wana"' <<<"$fora" | head -1)
  grava_b=$(grep 'oifname "lg-wanb"' <<<"$fora" | head -1)
  # A marca de saída carrega o bit 0x10000, que separa "saiu por esta WAN" de
  # "entrou por esta WAN". Sem ele, regra escrita para uma metade age sobre a
  # outra — já derrubou a LAN uma vez e o RST do DoT outra.
  local ok_grava=1
  grep -q 'ct direction original'  <<<"$grava_a" || ok_grava=0
  grep -qE 'ct mark (== )?0x0+ '   <<<"$grava_a" || ok_grava=0
  grep -qE "ct mark set 0x0*$saida_a( |\$)" <<<"$grava_a" || ok_grava=0
  grep -q 'ct direction original'  <<<"$grava_b" || ok_grava=0
  grep -qE 'ct mark (== )?0x0+ '   <<<"$grava_b" || ok_grava=0
  grep -qE "ct mark set 0x0*$saida_b( |\$)" <<<"$grava_b" || ok_grava=0
  if [[ "$ok_grava" == 1 ]]; then
    ok "cada WAN de saída grava a marca da tabela dela, só na direção original e só com a marca ainda zerada"
  else
    bad "a gravação de saída perdeu uma das condições ou uma das WANs" \
        "A='${grava_a:-ausente}' B='${grava_b:-ausente}'"
  fi

  # E A METADE DE ROTEAMENTO, que é o que dá significado à marca. Sem a `ip
  # rule` e sem o default na tabela do link, a consulta marcada do W4b cairia
  # na main — e o que ela mediria seria o hash, não a fixação.
  local regras
  regras=$(vm "ip rule show" | tr -d '\r')
  if grep -q "lookup $tab_a" <<<"$regras" && grep -q "lookup $tab_b" <<<"$regras"; then
    ok "as duas WANs de teste têm ip rule por marca ($tab_a e $tab_b)"
  else bad "falta ip rule por marca: a marca não muda rota nenhuma" "$(tr '\n' ' ' <<<"$regras" | head -c 240)"; fi
  if vm "ip route show table $tab_a" | grep -q 'default via 172.31.10.2' &&
     vm "ip route show table $tab_b" | grep -q 'default via 172.31.20.2'; then
    ok "cada tabela de link tem o default do link dela"
  else
    bad "tabela de link sem o default do link: a marca apontaria para uma tabela vazia" \
        "$tab_a: $(vm "ip route show table $tab_a" | tr -d '\r' | tr '\n' ' ' | head -c 100) | $tab_b: $(vm "ip route show table $tab_b" | tr -d '\r' | tr '\n' ' ' | head -c 100)"
  fi
  M_W1=1

  # ── W2 — A ASSERÇÃO QUE TERIA PEGO O APAGÃO ───────────────────────────────
  # Ela custa dois segundos: um host da LAN completa um handshake TCP ATRAVÉS
  # do firewall, com as chains já aplicadas. Não é prova de que a fixação
  # funciona — é o detector do apagão, e é a asserção mais barata desta bateria
  # em relação ao que ela pega: a LAN inteira sem internet.
  etiqueta=$(fala lanw 172.31.99.9 18099)
  if [[ "$etiqueta" == "wana" || "$etiqueta" == "wanb" ]]; then
    lan_ok=1
    ok "um host da LAN atravessa o firewall e é respondido (saiu pela $etiqueta)"
  else
    # A MENSAGEM NÃO CONCLUI, e isso é a cicatriz da N6: masquerade ausente,
    # postura do forward, rota da netns e a marcação errada dão o mesmo
    # sintoma. A causa vai na EVIDÊNCIA, para quem lê decidir.
    bad "O HOST DA LAN NÃO ATRAVESSA O FIREWALL" \
        "resposta='${etiqueta:-nada}' | rota: $(rota_default | head -c 120) | masq: $(vm "nft list chain inet linkguard postrouting 2>&1" | tr -d '\r' | tr '\n' ' ' | head -c 140) | conn_mark: $(tr '\n' ' ' <<<"$pre" | head -c 200)"
  fi
  M_W2=1

  # ── W6 — A CAIXA NAVEGAR NÃO CONTA COMO PROVA ─────────────────────────────
  # Esta asserção existe para dizer isso NO LOG, onde alguém vai ler. O tráfego
  # da própria máquina nasce no hook output e nunca atravessa o forward: no
  # apagão de que esta bateria trata, a caixa continuava navegando com a LAN
  # inteira parada. As duas medidas são separadas de propósito, e o desfecho
  # tem três braços — nenhum deles nomeia uma chain como culpada, porque para
  # tráfego nascido na caixa a marca nem chega a existir e o suspeito seria
  # outro.
  local caixa caixa_ok=0
  caixa=$(fala "" 172.31.99.9 18099)
  [[ "$caixa" == "wana" || "$caixa" == "wanb" ]] && caixa_ok=1
  if [[ "$lan_ok" == 1 && "$caixa_ok" == 1 ]]; then
    ok "a caixa e a LAN alcançam a internet de teste; as duas medidas foram feitas em separado"
  elif [[ "$lan_ok" != 1 && "$caixa_ok" == 1 ]]; then
    bad "A CAIXA NAVEGA E A LAN NÃO: é exatamente o apagão desta bateria, e o firewall navegar NÃO é prova de nada" \
        "caixa='$caixa' lan='${etiqueta:-nada}'"
  elif [[ "$lan_ok" == 1 && "$caixa_ok" != 1 ]]; then
    bad "a LAN atravessa e a PRÓPRIA CAIXA não alcança a internet de teste" \
        "caixa='${caixa:-nada}' | rota da caixa para 172.31.99.9: $(vm "ip route get 172.31.99.9 2>&1" | tr -d '\r' | tr '\n' ' ' | head -c 160)"
  else
    bad "nem a caixa nem a LAN alcançam a internet de teste; o cenário não estava de pé e o apagão não foi medido" \
        "caixa='${caixa:-nada}' lan='${etiqueta:-nada}' rota: $(rota_default | head -c 160)"
  fi
  M_W6=1

  if [[ "$lan_ok" != 1 ]]; then
    encerra_w "o host da LAN não atravessa o firewall"
    return
  fi

  # ── W3 — A CONEXÃO DE SAÍDA GANHA A MARCA DA WAN POR ONDE SAIU ────────────
  # Lida do conntrack para ESTE fluxo, e não em geral. Abre-se aqui a conexão
  # longa que o W4 vai atravessar: ela fica parada esperando o arnês reescrever
  # a rota. `Mark == TableID` é a derivação única do produto
  # (links/wanpath.go), e nenhuma outra chain grava `ct mark` em tráfego que
  # entra pela LAN — então o número lido aqui só pode ter vindo do conn_mark_out.
  vm "rm -f /tmp/lgw_fixa.out /tmp/lgw_go
      ip netns exec lanw setsid python3 /tmp/lgw_fixa.py 172.31.99.9 18097 >/dev/null 2>&1 < /dev/null &
      true" >/dev/null 2>&1
  local cliente=""
  for i in $(seq 1 20); do
    cliente=$(vm "cat /tmp/lgw_fixa.out 2>/dev/null" | tr -d '\r')
    grep -q '^r1=' <<<"$cliente" && break
    sleep 1
  done
  usada=$(grep '^r1=' <<<"$cliente" | head -1 | cut -d= -f2)
  sport=$(grep '^sport=' <<<"$cliente" | head -1 | cut -d= -f2)
  if [[ "$usada" != "wana" && "$usada" != "wanb" || -z "$sport" ]]; then
    bad "a conexão longa não chegou a ser estabelecida; a fixação não tem o que fixar" "${cliente:-sem saída do cliente}"
    M_W3=1
    encerra_w "a conexão longa não foi estabelecida"
    return
  fi
  if [[ "$usada" == "wana" ]]; then outra="wanb"; if_usada="lg-wana"; if_outra="lg-wanb"
  else outra="wana"; if_usada="lg-wanb"; if_outra="lg-wana"; fi
  # A marca guardada é o table_id COM o bit de saída (0x10000 = 65536).
  local esperada=$(( tab_a + 65536 )); [[ "$usada" == "wanb" ]] && esperada=$(( tab_b + 65536 ))

  marca=$(marca_do_fluxo "$sport")
  if [[ -z "$marca" ]]; then
    # NÃO ACHAR O FLUXO É FALHA DE MEDIÇÃO, NÃO DO PRODUTO, e a diferença
    # importa. Esta asserção lê o MECANISMO (a marca guardada); a W4 mede o
    # RESULTADO (por qual WAN a conexão continua saindo depois de a rota ser
    # reescrita). Conexão não fica fixada sem marca, então com a W4 verde o
    # mecanismo está funcionando mesmo que esta leitura falhe — chamar isto de
    # FALHA acusaria o produto de um defeito que a linha de baixo desmente.
    pular "W3. A conexão de saída guarda a marca da WAN por onde saiu" \
          "não achei o fluxo no conntrack (porta $sport); a W4 mede o mesmo mecanismo pelo resultado"
    printf '       (diagnóstico: %s)\n' "$(vm "echo -n 'com dport=18097: '; grep -c 'dport=18097' /proc/net/nf_conntrack 2>/dev/null; echo -n 'com sport=$sport: '; grep -c 'sport=$sport' /proc/net/nf_conntrack 2>/dev/null; echo -n 'fluxos no total: '; grep -c . /proc/net/nf_conntrack 2>/dev/null" | tr -d '\r' | tr '\n' ' ')"
  elif [[ "$marca" == "0" ]]; then
    bad "a conexão de saída ficou SEM MARCA (0): a memória de saída não gravou, e nada vai fixá-la quando a rota mudar" \
        "fluxo: $(head -c 200 <<<"$LINHA_CT") | conn_mark_out: $(tr '\n' ' ' <<<"$fora" | head -c 200)"
  elif [[ "$marca" == "$esperada" ]]; then
    ok "a conexão de saída guardou a marca da WAN por onde saiu ($usada, marca $marca)"
  else
    bad "a conexão saiu pela $usada e guardou a marca $marca, que é de outro caminho (esperada $esperada)" \
        "fluxo: $(head -c 200 <<<"$LINHA_CT")"
  fi
  M_W3=1

  # ── W4 — A ASSERÇÃO CENTRAL: a rota é REESCRITA e a conexão ABERTA continua
  # saindo pela mesma WAN ──────────────────────────────────────────────────
  #
  # A reescrita é do PRODUTO: o peso da outra WAN vai a 200 (que o balanceador
  # normaliza para 256 contra 1) e o painel reinstala a rota. Quase todo o
  # espaço de hash passa a apontar para a outra WAN — é a mesma coisa que um
  # link caindo e voltando faz com o hash, sem tirar interface nenhuma do ar.
  local id_outro="$id_b"; [[ "$usada" == "wanb" ]] && id_outro="$id_a"
  local pista_peso
  if ! pista_peso=$(muda_link "$id_outro" weight 200); then
    bad "não consegui mudar o peso do outro link pelo painel; sem reescrita não há o que a conexão aberta sobreviver" "$pista_peso"
    M_W4=1; M_W4B=1
    encerra_w "a reescrita de rota não pôde ser disparada"
    return
  fi
  st=$(status POST "/api/routing/balance/apply?arm=false" "$tok")
  local rota_antes="$rota" rota_depois=""
  for i in $(seq 1 10); do
    rota_depois=$(rota_default)
    grep -qE "dev $if_outra weight (25[0-6]|2[0-4][0-9])" <<<"$rota_depois" && break
    sleep 3
  done
  if [[ "$st" == "200" ]] && grep -qE "dev $if_outra weight (25[0-6]|2[0-4][0-9])" <<<"$rota_depois" &&
     grep -qE "dev $if_usada weight [1-9]?[0-9]( |\$)" <<<"$rota_depois"; then
    ok "o produto reescreveu a rota padrão, jogando o hash para a $outra"
  else
    bad "a rota padrão NÃO foi reescrita (apply=$st): sem reescrita não há nada para a conexão aberta sobreviver" \
        "antes: $rota_antes | depois: ${rota_depois:-vazia}"
    M_W4=1; M_W4B=1
    encerra_w "a rota padrão não foi reescrita"
    return
  fi

  # O CONTROLE, e é ele que transforma "continuou funcionando" em prova: uma
  # conexão NOVA, do mesmo host para o mesmo destino, tem de sair agora pela
  # OUTRA WAN. Se ela sair, o par de endereços mudou de caminho e qualquer
  # coisa que ainda saia pela WAN antiga só pode estar sendo decidida pela
  # marca. Se ela NÃO sair, a reescrita não moveu esta tupla e não há o que
  # medir — e aí a asserção é dita NÃO MEDIDA, em vez de verde.
  local controle
  controle=$(fala lanw 172.31.99.9 18099)
  if [[ "$controle" == "$usada" ]]; then
    pular "W4. A conexão aberta sobrevive à reescrita da rota" \
          "a reescrita não moveu esta tupla de hash (conexão nova ainda sai pela $usada): sobreviver não distinguiria fixação de inércia"
    pular "W4b. A rota marcada, perguntada ao kernel" \
          "sem o controle mostrar mudança de caminho, a consulta marcada não separaria a marca do hash"
    M_W4=1; M_W4B=1
  elif [[ "$controle" != "$outra" ]]; then
    bad "depois da reescrita o host da LAN parou de atravessar o firewall" \
        "controle='${controle:-nada}' | rota: ${rota_depois:-vazia}"
    M_W4=1; M_W4B=1
    encerra_w "a LAN parou de atravessar depois da reescrita"
    return
  else
    ok "depois da reescrita, uma conexão NOVA do mesmo host passa a sair pela $outra (o caminho deste par de endereços mudou)"

    # W4b — A MESMA PERGUNTA, FEITA AO KERNEL, sem depender do desfecho do TCP:
    # com a marca da conexão o caminho ainda é a WAN de origem; sem ela, é a
    # nova. É um A/B de uma linha só, e é o núcleo aproveitável da bateria.
    # A MARCA DA CONSULTA É A DO PACOTE, NÃO A DA CONEXÃO. O conntrack guarda o
    # table_id COM o bit de saída (0x10066), e a restauração devolve ao pacote
    # apenas o table_id (`meta mark set ct mark and 0xffff`), porque é isso que a
    # `ip rule fwmark 0x66 lookup 102` casa. Perguntar com 0x10066 é perguntar
    # com um valor que pacote nenhum carrega — o kernel responde pelo hash, com
    # razão, e a asserção acusaria o produto do erro da pergunta.
    local com_marca sem_marca marca_do_pacote
    marca_do_pacote=$(( marca & 65535 ))
    com_marca=$(vm "ip route get 172.31.99.9 from 192.168.121.2 iif lg-lanw mark $marca_do_pacote 2>&1" | tr -d '\r' | tr '\n' ' ')
    sem_marca=$(vm "ip route get 172.31.99.9 from 192.168.121.2 iif lg-lanw 2>&1" | tr -d '\r' | tr '\n' ' ')
    if [[ -z "$marca" || "$marca" == "0" ]]; then
      pular "W4b. A rota marcada, perguntada ao kernel" \
            "sem marca lida do conntrack (W3) não existe consulta marcada para fazer"
    elif ! grep -q ' dev ' <<<"$com_marca" || ! grep -q ' dev ' <<<"$sem_marca"; then
      pular "W4b. A rota marcada, perguntada ao kernel" \
            "o ip route get desta caixa não respondeu uma rota: com marca='$com_marca' sem marca='$sem_marca'"
    elif grep -qE " dev $if_usada( |\$)" <<<"$com_marca" && grep -qE " dev $if_outra( |\$)" <<<"$sem_marca"; then
      ok "o kernel resolve o pacote MARCADO pela WAN de origem ($if_usada) e o não marcado pela nova ($if_outra) — a marca é que decide"
    else
      bad "a consulta de rota não separou marca de hash: o pacote marcado devia sair por $if_usada e o não marcado por $if_outra" \
          "com marca: $com_marca | sem marca: $sem_marca"
    fi
    M_W4B=1

    # E o desfecho que quem opera sente: a MESMA conexão, ainda aberta, é
    # respondida pela MESMA ponta. O gatilho é conferido — um `touch` que não
    # aconteceu (ssh piscando, /tmp cheio) faria o cliente esperar 240s e a
    # bateria acusar o produto de "a conexão morreu", que é o sintoma exato que
    # ela procura.
    if [[ "$(vm "touch /tmp/lgw_go && test -f /tmp/lgw_go && echo criado" | tr -d '\r' | tail -1)" != "criado" ]]; then
      pular "W4. A conexão aberta sobrevive à reescrita da rota" \
            "o gatilho /tmp/lgw_go não foi criado na VM; o desfecho da conexão aberta não foi medido"
    else
      cliente=""
      for i in $(seq 1 40); do
        cliente=$(vm "cat /tmp/lgw_fixa.out 2>/dev/null" | tr -d '\r')
        grep -q '^fim$' <<<"$cliente" && break
        sleep 1
      done
      local depois
      depois=$(grep '^r2=' <<<"$cliente" | head -1 | cut -d= -f2)
      if [[ "$depois" == "$usada" ]]; then
        ok "a conexão aberta atravessou a reescrita de rota e continua saindo pela $usada, enquanto a conexão nova já sai pela $outra"
      elif [[ "$depois" == "$outra" ]]; then
        bad "a conexão aberta PULOU DE LINK: saiu pela $usada e agora responde a $outra — é a queda de fluxo longo que a mudança existe para impedir" \
            "cliente: $(tr '\n' ' ' <<<"$cliente" | head -c 160)"
      else
        bad "a conexão aberta MORREU na reescrita de rota (nenhuma resposta depois dela)" \
            "cliente: ${cliente:-sem saída} | marca agora: $(marca_do_fluxo "$sport") | fluxo lido no W3: $(head -c 140 <<<"$LINHA_CT") | estado dos links: $(body GET /api/links "$tok" | python3 -c "import json,sys; print(' '.join('%s=%s' % (l.get('interface'), l.get('status')) for l in json.load(sys.stdin)))" 2>/dev/null)"
      fi
    fi
    M_W4=1
  fi

  # ── W5 — SILÊNCIO, E É A METADE DA #120 ───────────────────────────────────
  # Fixar a saída não pode quebrar quem chega de fora. E esta asserção roda
  # DEPOIS da reescrita de peso de propósito: com a rota padrão pendendo para a
  # outra WAN, a resposta do host da LAN só chega ao cliente se a marca da
  # conexão de ENTRADA a devolver pela WAN por onde ela entrou. O cliente fala
  # de 203.0.113.x, FORA da sub-rede do enlace — dentro dela a rota conectada
  # da `main` acertaria a WAN sozinha e a asserção passaria com a marcação
  # desligada, que é a lacuna que a bateria P ainda tem.
  local origem_pf="203.0.113.9" ip_pf="172.31.10.1"
  [[ "$usada" == "wanb" ]] && { origem_pf="203.0.113.19"; ip_pf="172.31.20.1"; }
  local antes_pf
  antes_pf=$(fala "$usada" "$ip_pf" 18098 "$origem_pf")
  if [[ "$antes_pf" == erro:* ]] && ! vm "nft list chain inet linkguard prerouting_dnat 2>/dev/null" | grep -q '192.168.121.2'; then
    ok "sem encaminhamento, a porta não responde de fora e a chain de DNAT não conhece o host da LAN ('$antes_pf')"
  else
    bad "a linha de base do encaminhamento não vale: ou a porta já respondia, ou a tradução já estava lá" \
        "resposta='${antes_pf:-nada}' | dnat: $(vm "nft list chain inet linkguard prerouting_dnat 2>&1" | tr -d '\r' | tr '\n' ' ' | head -c 200)"
  fi
  st=$(status POST /api/portforward "$tok" "{\"name\":\"servidor interno W\",\"enabled\":true,\"proto\":\"tcp\",\"interface\":\"$if_usada\",\"ext_port\":18098,\"dest_ip\":\"192.168.121.2\",\"dest_port\":18098}")
  if [[ "$st" == "200" || "$st" == "201" ]]; then
    pf_criado=1
    sleep 2
    # Três tentativas, e todas têm de entregar: uma só poderia acertar a WAN
    # por sorte de hash caso a marcação de entrada tivesse sumido.
    local acertos=0 ultima=""
    for i in 1 2 3; do
      ultima=$(fala "$usada" "$ip_pf" 18098 "$origem_pf")
      [[ "$ultima" == "lan" ]] && acertos=$((acertos+1))
    done
    if [[ "$acertos" == "3" ]]; then
      ok "o encaminhamento de porta continua entregando ao host da LAN e a resposta volta pela WAN por onde entrou (3/3)"
    else
      # Sem hipótese no primeiro argumento (cicatriz da N6): re-marcação da
      # resposta, DNAT ausente, rota da netns e liberação do forward dão o
      # mesmo sintoma. A evidência é que decide.
      bad "O ENCAMINHAMENTO DE PORTA NÃO ENTREGA MAIS AO HOST DA LAN ($acertos/3) — é a metade de entrada da #120" \
          "última resposta='${ultima:-nada}' | dnat: $(vm "nft list chain inet linkguard prerouting_dnat 2>&1" | tr -d '\r' | tr '\n' ' ' | head -c 200) | conn_mark: $(vm "nft list chain inet linkguard conn_mark 2>/dev/null" | tr -d '\r' | tr '\n' ' ' | head -c 200)"
    fi
  else
    bad "não consegui criar o encaminhamento de porta ($st); a metade de entrada não foi medida"
  fi
  M_W5=1

  # Limpeza: o encaminhamento sai pelo caminho que o produto aceita, as WANs de
  # teste saem, o modo volta ao failover e — o que mais importa para a bateria
  # seguinte — os links detectados voltam a ficar ligados, com asserção.
  limpa_w
}

# ─── Z. Registro de conversa por host (issue #115) ───────────────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. Esta feature põe uma base chain no hook
# forward — por onde passa TODO o tráfego da LAN — e guarda, num set do kernel,
# com quem cada aparelho da rede falou. Duas coisas que teste em Go não alcança
# decidem se ela pode existir nesta forma:
#
#   1. ONDE O DADO MORA. O Persist do produto grava o dump de `inet linkguard`
#      em /etc/nftables.conf, e o dump inclui os ELEMENTOS dos sets dinâmicos —
#      a #198 mediu isso na caixa de produção: 86 elementos de contabilidade
#      carimbados no arquivo de boot, que o systemd replaya ANTES de o LinkGuard
#      subir. Se a conversa morasse na tabela do firewall, o arquivo de boot
#      cresceria com o tráfego da rede e ressuscitaria, a cada boot, a afirmação
#      de que um aparelho falou com um destino. O desenho evita isso com uma
#      TABELA IRMÃ (`inet linkguard_flows`) que o Persist não enxerga — e "não
#      enxerga" é uma afirmação sobre um arquivo numa máquina de verdade, não
#      sobre uma função. Z4 é essa asserção, e a Z4c mede o CONTRASTE que lhe dá
#      peso em vez de afirmá-lo em prosa: o mesmo arquivo tem de estar guardando
#      elemento de contabilidade, senão a premissa mudou e ninguém saberia.
#
#   2. SE A MEDIÇÃO MEDE. Um set alimentado por duas regras de nftables só prova
#      alguma coisa com pacote que ATRAVESSA a caixa, gerado de um netns, do
#      jeito que as baterias G, V e W geram. A própria caixa falando nasce no
#      hook output e nunca passa pelo forward: mediria outra coisa.
#
# E METADE DA BATERIA É SILÊNCIO, porque sem ela "apareceu" não significa nada:
#
#   Z1 — DESLIGADO NÃO MEDE. O mesmo tráfego que depois vira conversa é gerado
#        com o recurso desligado, e a tabela não pode existir. Sem esta metade,
#        a Z3 passaria igual numa versão que registra a rede inteira desde o
#        boot, sem ninguém ter pedido — que é o que o padrão desligado existe
#        para impedir.
#   Z6 — A IDENTIDADE NÃO SAI PELO ABERTO, dito com a precisão que a entrega
#        merece, e não com a frase larga que a primeira versão desta bateria
#        usava. O /metrics NUNCA publicou fluxo: `git diff main..` em
#        internal/metrics/ é vazio, nenhum coletor ganhou série de conversa.
#        A asserção do /metrics é GUARDA DE REGRESSÃO, e está escrita como tal.
#        Onde o dado de fato vazava é outro lugar, e está no corpo do commit da
#        feature: Ruleset e Save eram `nft list ruleset` — o kernel inteiro,
#        tabela de conversa junto — e isso saía por GET /api/nftables/ruleset
#        atrás de firewall.read (papel de Operador E de Visualizador, sem
#        auditoria) e por POST /api/nftables/backup, que CONGELAVA a janela numa
#        linha de banco. O conserto foi um só (`nft list table inet linkguard`)
#        e vale para os dois; a bateria cobra os DOIS, porque o segundo é o pior
#        — o que era retenção configurável em memória vira linha permanente em
#        disco.
#   Z8 — DESLIGAR APAGA. Não basta parar de mostrar: a base chain some do hook
#        forward e o dado some com ela.
#
# E a Z5 é a asserção que impede a tela de mentir sobre o que ela mostra: o
# contador do set NÃO obedece à janela. Uma conversa que nunca fica quieta
# renova o próprio prazo a cada pacote e acumula desde o primeiro — então o
# número da coluna de volume pode ser de muito antes dos minutos anunciados no
# topo da tela. Isso é MEDIDO no kernel aqui (o prazo volta ao topo e o contador
# não zera), e depois é cobrado no texto que o produto de fato entrega ao
# navegador — e cobrado de um jeito que distingue "a frase existe no dicionário"
# de "a tela mostra a frase" (Z5b).
#
# Esta bateria NÃO precisa de conntrack (a W descobriu que a caixa pode não
# ter): a medição é por pacote, no forward, e não pelo fim do fluxo.
battery_registro_de_fluxo() {
  head_ "Z. Registro de conversa por host"

  # Cada asserção tem um marcador, INCLUSIVE as de sufixo. Quem sair pelo meio
  # chama encerra_z, que PULA por nome tudo o que não chegou a ser medido — a
  # lição desta suíte é que bateria que aborta calada deixa o resumo dizer "0
  # falhas" sobre asserção que nunca rodou. E o marcador só é ligado depois de a
  # asserção ter sido FEITA (ok ou bad): ligá-lo ao sair por falha de arnês
  # transformaria "não medi" em "medi", que é a mentira oposta.
  local M_Z1=0 M_Z2=0 M_Z3=0 M_Z3B=0 M_Z3C=0 M_Z4=0 M_Z4B=0 M_Z4C=0
  local M_Z5=0 M_Z5B=0 M_Z6=0 M_Z6B=0 M_Z6C=0 M_Z6D=0 M_Z7=0 M_Z8=0
  local tok="" salvou=0 limpou=0 postura_trocada=0 postura_ini=""
  local JAN_INI=60 TETO_INI=32768
  local LAN_IP="192.168.115.2" DEST_IP="172.31.115.2" PORTA=18115

  # tabela_z → "existe", "ausente" ou VAZIO. O terceiro valor é o ponto: o idiom
  # `nft list table ... && echo existe || echo ausente` devolve vazio quando o
  # ssh morre, e um vazio lido como "existe" faz esta bateria imprimir as três
  # FALHAS mais graves que ela tem (a tabela existe desligada / desligar não
  # apagou / o produto não desligou) por causa de um soluço de rede. Perguntar
  # ao nft se ELE está de pé separa "não existe" de "não consegui perguntar".
  tabela_z() {
    vm "if nft list table inet linkguard_flows >/dev/null 2>&1; then echo existe
        elif nft list tables >/dev/null 2>&1; then echo ausente; fi" 2>/dev/null \
      | tr -d '\r' | grep -E '^(existe|ausente)$' | head -1
  }

  # espera_z ESTADO TENTATIVAS → espera com teto pelo estado, devolve o último
  # lido (que pode ser vazio: ver acima).
  espera_z() {
    local alvo="$1" n="$2" i estado=""
    for i in $(seq 1 "$n"); do
      estado=$(tabela_z)
      [[ "$estado" == "$alvo" ]] && break
      sleep 1
    done
    echo "$estado"
  }

  # limpa_z desfaz o que a bateria montou, e roda em TODO caminho de saída —
  # inclusive num Ctrl-C, via trap: Z é a primeira bateria da suíte a montar uma
  # base chain no hook forward, e interromper aqui custa mais do que em qualquer
  # outra.
  #
  # O guarda NÃO é "eu liguei?", é "há o que desligar?". A diferença é a que
  # deixava a chain de pé nos dois caminhos em que ela mais importa: o 409 do
  # ErrSemWAN GRAVA `ligado:true` no banco antes de recusar o kernel (o handler
  # diz isso com todas as letras), e o Z8 que descobre "desligar não apagou" é
  # justamente o caso em que a rede de segurança precisa correr. Por isso a
  # limpeza olha a intenção (salvou) E o kernel (tabela viva), e por isso o
  # BANCO é conferido no fim: é o setting que faz qualquer mudança de link
  # remontar a chain sozinha, no auto-detect da bateria seguinte ou no boot.
  limpa_z() {
    [[ "$limpou" == 1 ]] && return
    limpou=1
    local estado
    estado=$(tabela_z)
    if [[ -n "$tok" && ( "$salvou" == 1 || "$estado" == "existe" ) ]]; then
      # A janela e o teto voltam aos que a caixa TINHA, não aos desta bateria:
      # sair daqui com teto 1024 gravado deixaria a próxima instalação medindo
      # com o mínimo sem ninguém ter escolhido isso.
      status PUT /api/hosts/traffic/flows/config "$tok" \
        "{\"ligado\":false,\"janela_minutos\":$JAN_INI,\"teto\":$TETO_INI}" >/dev/null 2>&1
      estado=$(espera_z ausente 10)
      case "$estado" in
        ausente)
          ok "a limpeza desligou o registro pelo painel e a tabela saiu do kernel" ;;
        existe)
          # Rede de segurança do arnês, e ela é FALHA mesmo funcionando: se o
          # produto não derrubou a tabela, quem derrubou foi este script — e as
          # baterias seguintes rodariam com uma chain a mais no forward.
          vm "nft delete table inet linkguard_flows" >/dev/null 2>&1
          bad "o registro não foi desligado pelo painel; o arnês derrubou a tabela à força para não deixar a medição de pé nas baterias seguintes" \
              "$(vm "nft list table inet linkguard_flows 2>&1 | head -4" | tr -d '\r' | tr '\n' ' ' | head -c 200)" ;;
        *)
          bad "não consegui perguntar ao kernel se a tabela de conversa saiu; a bateria pode estar deixando uma base chain no hook forward para as seguintes" \
              "a consulta por ssh não respondeu" ;;
      esac
      local cfg_fim lig_fim
      cfg_fim=$(body GET /api/hosts/traffic/flows/config "$tok")
      lig_fim=$(jqk config.ligado <<<"$cfg_fim")
      if [[ "$lig_fim" == "False" ]]; then
        ok "e o registro ficou DESLIGADO no banco (é o setting que remonta a chain sozinho a cada mudança de link e a cada boot)"
      else
        bad "o registro continua LIGADO no banco depois da limpeza ('$lig_fim'): a próxima mudança de link — o auto-detect de qualquer bateria — remonta a base chain no forward sem ninguém ter pedido" \
            "$(head -c 200 <<<"$cfg_fim")"
      fi
    fi
    # A POSTURA VOLTA AO QUE ESTAVA. Deixar a forward em accept é decidir pelas
    # baterias seguintes uma coisa que elas não pediram.
    if [[ "$postura_trocada" == 1 && -n "$tok" ]]; then
      status PUT /api/nftables/policy "$tok" "{\"policy\":\"$postura_ini\",\"chain\":\"forward\"}" >/dev/null 2>&1
      local jan agora
      jan=$(body GET /api/nftables/pending "$tok" | jqk pending.id)
      [[ -n "$jan" ]] && status POST /api/nftables/pending/confirm "$tok" "{\"id\":\"$jan\"}" >/dev/null 2>&1
      agora=$(body GET /api/nftables/policy "$tok" | jqk forward)
      if [[ "$agora" == "$postura_ini" ]]; then
        ok "a postura do que atravessa voltou ao que esta bateria encontrou ($postura_ini)"
      else
        bad "a postura do que atravessa ficou em '${agora:-nada}' e não no '$postura_ini' que esta bateria encontrou: as baterias seguintes herdam uma decisão que ninguém tomou"
      fi
    fi
    vm "pkill -f lgz_serv >/dev/null 2>&1
        ip netns del lanz 2>/dev/null; ip netns del intz 2>/dev/null
        ip link del lg-flan 2>/dev/null; ip link del lg-fint 2>/dev/null
        nft delete table inet lgz_probe 2>/dev/null
        rm -f /tmp/lgz_serv.py /tmp/lgz_fala.py /tmp/lgz_enche.py /tmp/lgz_probe.nft; true" >/dev/null 2>&1
    trap - INT TERM
  }

  encerra_z() {
    local motivo="$1"
    [[ "$M_Z1"  == 1 ]] || pular "Z1. Desligado, a medição não existe e a tela diz isso" "$motivo"
    [[ "$M_Z2"  == 1 ]] || pular "Z2. A medição monta, com as duas regras, depois da filtragem" "$motivo"
    [[ "$M_Z3"  == 1 ]] || pular "Z3. A conversa de um aparelho da LAN aparece, com destino e porta" "$motivo"
    [[ "$M_Z3B" == 1 ]] || pular "Z3b. O volume da conversa sobe com o tráfego" "$motivo"
    [[ "$M_Z3C" == 1 ]] || pular "Z3c. A ocupação que o produto devolve é a do kernel" "$motivo"
    [[ "$M_Z4"  == 1 ]] || pular "Z4. A tabela é separada da do firewall no kernel" "$motivo"
    [[ "$M_Z4B" == 1 ]] || pular "Z4b. O arquivo de boot não ganha conversa" "$motivo"
    [[ "$M_Z4C" == 1 ]] || pular "Z4c. O arquivo de boot guarda elemento de contabilidade (o perigo da #198 é real)" "$motivo"
    [[ "$M_Z5"  == 1 ]] || pular "Z5. O contador não obedece à janela" "$motivo"
    [[ "$M_Z5B" == 1 ]] || pular "Z5b. A tela entregue ao navegador não mente sobre o volume" "$motivo"
    [[ "$M_Z6"  == 1 ]] || pular "Z6. A identidade não sai pelo /metrics aberto" "$motivo"
    [[ "$M_Z6B" == 1 ]] || pular "Z6b. O dump de ruleset e o backup são escopados à tabela do firewall" "$motivo"
    [[ "$M_Z6C" == 1 ]] || pular "Z6c. A permissão de ver conversa nasce fora dos papéis de fábrica" "$motivo"
    [[ "$M_Z6D" == 1 ]] || pular "Z6d. A consulta de conversa fica no log de auditoria, com o alvo" "$motivo"
    [[ "$M_Z7"  == 1 ]] || pular "Z7. O teto aparece na leitura, em vez de sumir" "$motivo"
    [[ "$M_Z8"  == 1 ]] || pular "Z8. Desligar apaga a medição do kernel" "$motivo"
    limpa_z
  }

  # ── Ajudantes de medição ───────────────────────────────────────────────────
  #
  # Nenhum deles crava endereço: mudar a constante lá em cima e ver a Z5 virar
  # PULADA permanente ("não consegui ler o prazo nesta caixa") é falha do arnês
  # disfarçada de limitação da máquina.

  # fala_z KB → "ok:KB" quando o host da LAN atravessou o firewall e o outro
  # lado respondeu, ou "erro:X". O cliente é um arquivo na VM e não um -c
  # gigante: a versão com aspas dentro de aspas dentro do ssh já quebrou uma vez
  # nesta suíte e a falha parecia do produto.
  fala_z() {
    vm "ip netns exec lanz timeout 20 python3 /tmp/lgz_fala.py $DEST_IP $PORTA $1 2>/dev/null" \
      | tr -d '\r' | tail -1
  }

  # tupla_z → "pacotes bytes prazo_em_segundos" da conversa desta bateria, lidos
  # DO KERNEL, ou vazio. É a leitura crua que a Z5 usa.
  tupla_z() {
    vm "nft list set inet linkguard_flows flows 2>/dev/null" | tr -d '\r' | python3 -c "
import re,sys
lan,dest,porta=sys.argv[1],sys.argv[2],sys.argv[3]
t=sys.stdin.read()
alvo=(re.escape(lan)+r'\s*\.\s*'+re.escape(dest)+r'\s*\.\s*'+re.escape(porta)
      +r' counter packets (\d+) bytes (\d+)([^,}]*)')
m=re.search(alvo,t)
if not m:
    print('')
    raise SystemExit
e=re.search(r'expires (?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m(?!s))?(?:(\d+)s)?', m.group(3))
seg=0
if e:
    for v,mult in zip(e.groups(), (86400,3600,60,1)):
        if v:
            seg += int(v)*mult
print(m.group(1), m.group(2), seg)
" "$LAN_IP" "$DEST_IP" "$PORTA" 2>/dev/null
  }

  # elemento_cru → o elemento como o nft imprime, para o diagnóstico não ser uma
  # adivinhação quando a leitura acima não casar.
  elemento_cru() {
    vm "nft list set inet linkguard_flows flows 2>/dev/null | grep -o '$LAN_IP[^,}]*' | head -1" \
      | tr -d '\r' | head -1
  }

  # ocupa_z → quantas tuplas o set tem AGORA, contadas no kernel. É `grep -o` e
  # não `grep -c` de propósito: o nft imprime vários elementos por linha.
  ocupa_z() {
    vm "nft list set inet linkguard_flows flows 2>/dev/null | grep -o 'counter packets' | wc -l" \
      | tr -d '\r' | head -1
  }

  # campo_z CORPO CAMPO → um campo da resposta do produto.
  campo_z() {
    python3 -c "
import json,sys
d=json.loads(sys.argv[1])
v=d.get(sys.argv[2])
print('' if v is None else v)" "$1" "$2" 2>/dev/null
  }

  # conta_z CORPO → quantas conversas o produto devolveu.
  conta_z() {
    python3 -c "
import json,sys
print(len(json.loads(sys.argv[1]).get('conversas') or []))" "$1" 2>/dev/null
  }

  # linha_z CORPO → "origem destino porta bytes" da conversa de teste, como o
  # PRODUTO a devolve. A ORIGEM entra na conferência: a rota já filtra por ?ip=,
  # mas o tráfego de volta desta montagem entra por uma interface que não é WAN,
  # casa a regra de SUBIDA e cria a tupla espelhada `destino . origem . porta
  # efêmera` — um filtro de host quebrado no produto passaria despercebido se a
  # asserção olhasse só o destino.
  linha_z() {
    python3 -c "
import json,sys
d=json.loads(sys.argv[1])
lan,dest,porta=sys.argv[2],sys.argv[3],int(sys.argv[4])
for c in (d.get('conversas') or []):
    if c.get('origem')==lan and c.get('destino')==dest and int(c.get('porta') or 0)==porta:
        print(c.get('origem'), c.get('destino'), c.get('porta'), c.get('bytes'))
        break" "$1" "$LAN_IP" "$DEST_IP" "$PORTA" 2>/dev/null
  }

  # ── Sessão ─────────────────────────────────────────────────────────────────
  local initial
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial")
  [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  if [[ -z "$tok" ]]; then
    bad "sem sessão administrativa; a bateria Z não roda"
    encerra_z "sem sessão administrativa"
    return
  fi

  trap 'limpa_z; exit 130' INT TERM

  # NENHUMA JANELA DE CONFIRMAÇÃO ABERTA. Enquanto ela existe, toda mutação
  # guardada é recusada com 409 — e o 409 do PUT de configuração é o MESMO
  # código do ErrSemWAN. Ler o 409 errado faria a Z2 pular acusando falta de
  # WAN numa caixa que tem WAN. Aqui a bateria não confirma a mudança de outra
  # bateria: ela se recusa a rodar e diz por quê.
  local pend
  pend=$(body GET /api/nftables/pending "$tok" | jqk pending.id)
  if [[ -n "$pend" ]]; then
    encerra_z "há uma mudança de firewall aguardando confirmação ($pend): enquanto a janela de 90 s durar, toda mutação guardada é recusada com 409 e a bateria mediria a janela, não a feature"
    return
  fi

  # A postura do que ATRAVESSA precisa ser accept — sem tráfego passando não há
  # o que medir, e a falha apareceria como se fosse do registro. A troca é
  # CONFIRMADA na hora (senão a janela de 90 s recusa o PUT que monta a medição
  # e bloqueia o Persist de que a Z4 depende), e o valor original é guardado
  # para a limpeza devolver.
  postura_ini=$(body GET /api/nftables/policy "$tok" | jqk forward)
  if [[ -z "$postura_ini" ]]; then
    bad "não consegui ler a postura do que atravessa; sem saber se o tráfego passa, tudo o que esta bateria medisse seria ambíguo"
    encerra_z "não consegui ler a postura do forward"
    return
  fi
  if [[ "$postura_ini" == "accept" ]]; then
    ok "a postura do que atravessa já é accept: o tráfego da montagem passa e o que a bateria medir é do registro"
  else
    local st_pol janela_pol agora_pol
    st_pol=$(status PUT /api/nftables/policy "$tok" '{"policy":"accept","chain":"forward"}')
    janela_pol=$(body GET /api/nftables/pending "$tok" | jqk pending.id)
    [[ -n "$janela_pol" ]] && status POST /api/nftables/pending/confirm "$tok" "{\"id\":\"$janela_pol\"}" >/dev/null
    agora_pol=$(body GET /api/nftables/policy "$tok" | jqk forward)
    if [[ "$agora_pol" == "accept" ]]; then
      postura_trocada=1
      ok "a postura do que atravessa foi liberada e a troca foi confirmada na hora (era '$postura_ini'; a limpeza devolve)"
    else
      bad "não consegui liberar a postura do que atravessa (PUT=$st_pol, janela='${janela_pol:-nenhuma}', postura='${agora_pol:-nada}'); sem tráfego passando, a bateria acusaria o registro por uma falha do arnês"
      encerra_z "não consegui liberar a postura do forward"
      return
    fi
  fi

  # A medição só monta sabendo o que é WAN (ErrSemWAN), e a lista sai dos links
  # HABILITADOS no banco. O auto-detect é o caminho do próprio produto; sem
  # nenhum link habilitado a bateria mediria a recusa, não a feature. O
  # auto-detect é uma MUTAÇÃO (cria link habilitado) e por isso tem asserção:
  # se ele falhar, o sintoma reapareceria lá na frente como "a medição não
  # montou", com o nome errado.
  local st_ad
  st_ad=$(status POST /api/links/auto-detect "$tok")
  local wans
  wans=$(body GET /api/links "$tok" | python3 -c "
import json,sys
print(' '.join(l.get('interface','') for l in json.load(sys.stdin) if l.get('enabled')))" 2>/dev/null)
  if [[ -z "${wans// /}" ]]; then
    encerra_z "nenhum link WAN habilitado nesta caixa (auto-detect=$st_ad): a medição se recusa a montar (ErrSemWAN) e a bateria mediria a recusa, não a feature"
    return
  fi
  ok "há link WAN habilitado para escopar a medição ($wans)"

  # ── PORTÃO: o nft desta caixa aceita a forma que o produto emite? ──────────
  # Chave de três dimensões, set dinâmico com timeout e contador, e os DOIS
  # `update` — o da subida e o da descida — dentro de uma base chain no forward,
  # com a lista de WANs de verdade desta caixa. Se o nft recusar qualquer
  # pedaço, o cenário não existe nesta máquina, e isso é PULAR dizendo por quê.
  #
  # O QUE ESTE PORTÃO NÃO COBRE, dito para quem vier depois: ele reproduz a
  # forma à mão. Se flowsSetSpec/flowsChainRules ganharem um atributo novo
  # (gc-interval, um size derivado), o portão continua PROBE_OK e a recusa
  # aparece na Z2 como se fosse defeito do produto — por isso a Z2 traz o
  # journal na evidência quando a montagem falha.
  local wanset="" w
  for w in $wans; do wanset="$wanset\"$w\", "; done
  wanset="{ ${wanset%, } }"
  local probe
  probe=$(vm "cat > /tmp/lgz_probe.nft <<'NFTEOF'
table inet lgz_probe {
  set p { type ipv4_addr . ipv4_addr . inet_service; size 32768; flags dynamic,timeout; timeout 5m; counter; }
  chain c {
    type filter hook forward priority filter + 15; policy accept;
    iifname != $wanset meta l4proto { tcp, udp } update @p { ip saddr . ip daddr . th dport }
    iifname $wanset meta l4proto { tcp, udp } update @p { ip daddr . ip saddr . th sport }
  }
}
NFTEOF
nft -f /tmp/lgz_probe.nft 2>&1 && echo PROBE_OK
nft delete table inet lgz_probe >/dev/null 2>&1; rm -f /tmp/lgz_probe.nft" | tr -d '\r')
  if grep -q 'PROBE_OK' <<<"$probe"; then
    ok "o nft desta caixa aceita a forma que a medição emite (chave de três dimensões, set dinâmico com contador, os dois update no forward)"
  else
    encerra_z "o nft desta caixa recusou a forma da medição: $(tr '\n' ' ' <<<"$probe" | head -c 200)"
    return
  fi

  # ── Montagem: um aparelho de LAN e uma internet de mentira, cada um na sua
  # netns. O tráfego medido ATRAVESSA a caixa — é a única medida que vale, e é
  # por isso que nada aqui fala a partir da própria caixa. ────────────────────
  #
  # A internet de mentira NÃO é cadastrada como WAN, de propósito: cadastrá-la
  # traria junto o monitor de saúde, o failover e a rota padrão (a bateria W
  # paga esse preço porque precisa dele), e a pergunta desta bateria não depende
  # disso. O custo, dito por inteiro: (a) só a metade de SUBIDA da conversa é
  # exercitada com pacote — a regra de DESCIDA, o par que soma o volume de volta
  # na mesma tupla, é cobrada no kernel, na Z2; e (b) como o retorno entra por
  # uma interface que não é WAN, ele casa a regra de SUBIDA e cria uma tupla
  # ESPELHADA por porta efêmera. Isso não invalida nada — a linha_z confere a
  # origem —, mas conta para a ocupação do set, e é por isso que a Z7 enche o
  # set com uma folga em vez de contar exatamente.
  vm "pkill -f lgz_serv >/dev/null 2>&1
      ip netns del lanz 2>/dev/null; ip netns del intz 2>/dev/null
      ip link del lg-flan 2>/dev/null; ip link del lg-fint 2>/dev/null; true" >/dev/null 2>&1
  vm "ip netns add lanz && ip netns add intz && \
      ip link add lg-flan type veth peer name flan-far && \
      ip link add lg-fint type veth peer name fint-far && \
      ip link set flan-far netns lanz && ip link set fint-far netns intz && \
      ip addr add 192.168.115.1/24 dev lg-flan && ip link set lg-flan up && \
      ip addr add 172.31.115.1/24 dev lg-fint && ip link set lg-fint up && \
      ip netns exec lanz sh -c 'ip link set lo up; ip addr add $LAN_IP/24 dev flan-far; ip link set flan-far up; ip route add default via 192.168.115.1' && \
      ip netns exec intz sh -c 'ip link set lo up; ip addr add $DEST_IP/24 dev fint-far; ip link set fint-far up; ip route add default via 172.31.115.1'" >/dev/null 2>&1

  vm "cat > /tmp/lgz_serv.py <<'PYEOF'
import socket, sys, threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((sys.argv[1], int(sys.argv[2])))
srv.listen(16)
def atende(c):
    try:
        while True:
            d = c.recv(65536)
            if not d:
                return
            if d.endswith(b'FIM'):
                c.sendall(b'ok\n')
                return
    except Exception:
        return
    finally:
        c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=atende, args=(c,), daemon=True).start()
PYEOF
      cat > /tmp/lgz_fala.py <<'PYEOF'
import socket, sys
try:
    kb = int(sys.argv[3])
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), 6)
    s.settimeout(10)
    bloco = b'z' * 1024
    for _ in range(kb):
        s.sendall(bloco)
    s.sendall(b'FIM')
    s.recv(64)
    s.close()
    print('ok:' + str(kb))
except Exception as e:
    print('erro:' + type(e).__name__)
PYEOF
      cat > /tmp/lgz_enche.py <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
alvo = sys.argv[1]
inicio = int(sys.argv[2])
quantas = int(sys.argv[3])
enviados = 0
for p in range(inicio, inicio + quantas):
    try:
        s.sendto(b'z', (alvo, p))
        enviados += 1
    except Exception:
        pass
print(enviados)
PYEOF
      ip netns exec intz setsid python3 /tmp/lgz_serv.py $DEST_IP $PORTA >/dev/null 2>&1 < /dev/null &
      sleep 1" >/dev/null 2>&1

  # PORTÃO: o servidor de mentira está de pé DENTRO da própria netns? Esta
  # medida não atravessa firewall nenhum. Sem ela, um servidor que não subiu
  # faria a bateria acusar o produto de uma medição vazia que é do arnês.
  local eco
  eco=$(vm "ip netns exec intz timeout 10 python3 /tmp/lgz_fala.py $DEST_IP $PORTA 1 2>/dev/null" | tr -d '\r' | tail -1)
  if [[ "$eco" == ok:* ]]; then
    ok "a internet de mentira responde dentro da própria netns"
  else
    bad "o cenário não subiu: o servidor de teste não responde nem localmente ('${eco:-nada}')" \
        "$(vm "ip netns list 2>&1; ip -br addr show lg-flan lg-fint 2>&1" | tr -d '\r' | tr '\n' ' ' | head -c 220)"
    encerra_z "veth/netns não subiram nesta máquina"
    return
  fi

  # ── Z1 — SILÊNCIO: DESLIGADO NÃO MEDE ─────────────────────────────────────
  # O padrão de fábrica é desligado, o kernel não tem a tabela, e o MESMO
  # tráfego que depois vira conversa passa sem deixar rastro. A última é a que
  # torna a Z3 honesta — sem ela, "apareceu" poderia ser uma medição que já
  # estava lá.
  local cfg_ini lig_ini j_ini t_ini
  cfg_ini=$(body GET /api/hosts/traffic/flows/config "$tok")
  lig_ini=$(jqk config.ligado <<<"$cfg_ini")
  j_ini=$(jqk config.janela_minutos <<<"$cfg_ini")
  t_ini=$(jqk config.teto <<<"$cfg_ini")
  # O que a caixa tinha é o que a limpeza devolve.
  [[ -n "$j_ini" ]] && JAN_INI="$j_ini"
  [[ -n "$t_ini" ]] && TETO_INI="$t_ini"
  if [[ "$lig_ini" == "False" ]]; then
    ok "o registro nasce DESLIGADO: ligar uma medição de quem-falou-com-quem é decisão do admin, não padrão de fábrica"
  else
    bad "o registro de conversa veio ligado ('$lig_ini'): a rede passa a ser registrada sem ninguém ter pedido" \
        "$(head -c 200 <<<"$cfg_ini")"
    # E a bateria devolve a caixa ao estado desligado PELO PRODUTO antes de
    # medir o resto — senão a asserção seguinte mediria uma tabela herdada, e a
    # bateria inteira rodaria (e terminaria) com uma medição que não montou.
    salvou=1
    status PUT /api/hosts/traffic/flows/config "$tok" \
      "{\"ligado\":false,\"janela_minutos\":$JAN_INI,\"teto\":$TETO_INI}" >/dev/null 2>&1
    espera_z ausente 10 >/dev/null
  fi

  local atravessou
  atravessou=$(fala_z 200)
  if [[ "$atravessou" != ok:* ]]; then
    # A mensagem NÃO CONCLUI: postura do forward, rota da netns e ip_forward dão
    # o mesmo sintoma. A causa vai na EVIDÊNCIA, para quem lê decidir. E o
    # marcador do Z1 NÃO é ligado: nada do que o Z1 afirma foi medido, e o que
    # falhou é o arnês.
    bad "O HOST DA LAN NÃO ATRAVESSA O FIREWALL; nada do que esta bateria mede existiria" \
        "resposta='${atravessou:-nada}' | forward: $(body GET /api/nftables/policy "$tok" | head -c 80) | ip_forward: $(vm "cat /proc/sys/net/ipv4/ip_forward" | tr -d '\r') | rota: $(vm "ip route get $DEST_IP from $LAN_IP iif lg-flan 2>&1" | tr -d '\r' | tr '\n' ' ' | head -c 140)"
    encerra_z "o host da LAN não atravessa o firewall"
    return
  fi

  local tabela_off corpo_off lig_off mont_off jan_off
  tabela_off=$(tabela_z)
  case "$tabela_off" in
    ausente)
      ok "com o registro desligado, 200 KB atravessaram a caixa e a tabela de conversa não existe no kernel" ;;
    existe)
      bad "A TABELA DE CONVERSA EXISTE COM O RECURSO DESLIGADO: a rede está sendo registrada sem ninguém ter ligado" \
          "$(vm "nft list table inet linkguard_flows 2>&1 | head -8" | tr -d '\r' | tr '\n' ' ' | head -c 240)" ;;
    *)
      pular "Z1b. Com o registro desligado, o kernel não tem a tabela" \
            "não consegui perguntar ao kernel se a tabela existe (ssh/nft não responderam); afirmar ausência sem ter lido seria verde sem medida" ;;
  esac
  # E A TELA. Esta linha é uma conferência de CONTRATO, não uma medição
  # independente, e está escrita sabendo disso: com o registro desligado o
  # produto devolve um literal só (Ligado:false, lista vazia, montada falsa,
  # janela zero — hostflows/servico.go), então os campos não se confirmam entre
  # si. O que ela pega é a versão que responde "ninguém falou" no lugar de "não
  # estou olhando". A medição de verdade do desligado é a do kernel, acima.
  corpo_off=$(body GET "/api/hosts/traffic/flows?ip=$LAN_IP" "$tok")
  lig_off=$(campo_z "$corpo_off" ligado)
  mont_off=$(campo_z "$corpo_off" montada)
  jan_off=$(campo_z "$corpo_off" janela_minutos)
  if [[ "$lig_off" == "False" && "$mont_off" == "False" && "${jan_off:-x}" == "0" ]]; then
    ok "e a tela diz DESLIGADO e NÃO MONTADA, sem anunciar janela nenhuma — que é diferente de 'ninguém falou'"
  else
    bad "a tela não distinguiu 'desligado' de 'ninguém falou' (ligado='$lig_off', montada='$mont_off', janela='$jan_off')" \
        "$(head -c 200 <<<"$corpo_off")"
  fi
  M_Z1=1

  # ── Z2 — A MEDIÇÃO MONTA, COM AS DUAS REGRAS, DEPOIS DA FILTRAGEM ─────────
  # A janela vai no MÍNIMO (5 min) de propósito: é o que torna o prazo do
  # elemento observável dentro de uma bateria, e é o que a Z5 usa.
  #
  # A INTENÇÃO É MARCADA ANTES DO PUT, e não depois do 200. SalvarConfig grava
  # no banco ANTES de tocar no kernel: tanto o 409 do ErrSemWAN quanto um 500 no
  # meio da montagem deixam `ligado:true` gravado, e uma limpeza que só roda
  # depois de um 200 sairia daqui deixando a caixa configurada para remontar a
  # chain sozinha na próxima mudança de link.
  salvou=1
  local resp_cfg st_cfg corpo_cfg
  resp_cfg=$(api PUT /api/hosts/traffic/flows/config "$tok" '{"ligado":true,"janela_minutos":5,"teto":32768}')
  st_cfg=$(head -1 <<<"$resp_cfg"); corpo_cfg=$(tail -n +2 <<<"$resp_cfg")
  if [[ "$st_cfg" == "409" ]]; then
    # O MESMO 409 tem duas causas, e nomear a errada é pior do que não nomear:
    # falta de WAN é a recusa documentada da feature; janela de confirmação
    # aberta é estado do firewall que nada tem a ver com ela.
    if grep -q 'aguardando confirmação' <<<"$corpo_cfg"; then
      encerra_z "uma janela de confirmação de firewall abriu no meio da bateria e recusou a montagem (409); o que a bateria mediria é a janela, não a feature"
    else
      encerra_z "o produto recusou montar por não haver WAN habilitada (409, ErrSemWAN) — é a recusa documentada, não um defeito: $(head -c 140 <<<"$corpo_cfg")"
    fi
    return
  fi
  if [[ "$st_cfg" != "200" ]]; then
    bad "o painel recusou ligar o registro de conversa ($st_cfg)" "$(head -c 200 <<<"$corpo_cfg")"
    M_Z2=1
    encerra_z "não consegui ligar o registro pelo painel"
    return
  fi

  local chain="" i
  for i in $(seq 1 10); do
    chain=$(vm "nft list chain inet linkguard_flows flows 2>/dev/null" | tr -d '\r')
    [[ -n "$chain" ]] && break
    sleep 1
  done
  if [[ -z "$chain" ]]; then
    bad "ligar respondeu 200 e a chain não existe no kernel: a tela diria LIGADO sobre uma medição que não está lá" \
        "$(vm "nft list tables 2>&1; journalctl -u linkguard-fw --since '2 min ago' --no-pager | grep -i -e conversa -e flows | tail -3" | tr -d '\r' | tr '\n' ' ' | head -c 260)"
    M_Z2=1
    encerra_z "a medição não montou no kernel"
    return
  fi

  # DEPOIS DA FILTRAGEM. Prioridade errada aqui registra como conversa um
  # destino que uma regra de firewall bloqueou — a tela afirmaria que o aparelho
  # falou com quem ele não falou.
  #
  # A ASSERÇÃO CASA A SAÍDA RENDERIZADA, NÃO A SINTAXE DA DECLARAÇÃO. O produto
  # escreve `priority filter + 15` e o nft imprime `priority 15`, porque
  # `filter` vale zero. Cobrar o texto da declaração reprovava uma chain que
  # está exatamente onde deveria — o mesmo erro que a bateria W cometeu ao
  # perguntar ao kernel por uma marca que pacote nenhum carrega.
  if grep -qE 'hook forward priority (filter \+ )?15;' <<<"$chain" && grep -q 'policy accept' <<<"$chain"; then
    ok "a chain de conversa está no forward DEPOIS da filtragem (filter + 15) e com policy accept"
  else
    bad "a chain de conversa não está no forward em filter + 15, ou não é accept: ela contaria destino bloqueado como conversa" \
        "$(tr '\n' ' ' <<<"$chain" | head -c 240)"
  fi

  # AS DUAS REGRAS, uma a uma. A de descida é a que a primeira entrega desta
  # feature esqueceu: sem ela o volume seria só o que o aparelho ENVIOU, e um
  # host baixando 4 GB apareceria com dezenas de MB de ACK. E elas têm de ser
  # MUTUAMENTE EXCLUSIVAS (`!=` a lista, e depois a lista): com `oifname !=` na
  # segunda, todo pacote LAN→LAN casaria as duas e seria contado em dobro, em
  # duas tuplas espelhadas.
  #
  # O `iifname (\{|")` da descida não é frouxidão: esta VM tem UMA NIC (é a
  # premissa do battery_fechar_gerencia), a lista de WANs sai com um elemento só
  # e o nft normaliza set anônimo unitário para a forma crua `iifname "enp0s3"`.
  # Exigir chave aqui reprovaria o produto por causa da caixa — a G2 evita a
  # mesma armadilha do mesmo jeito. O que separa a forma certa da errada são as
  # DUAS NEGATIVAS: nem `iifname !=`, nem `oifname`.
  local sobe desce
  sobe=$(grep -F 'ip saddr . ip daddr . th dport' <<<"$chain" | head -1)
  desce=$(grep -F 'ip daddr . ip saddr . th sport' <<<"$chain" | head -1)
  if [[ -n "$sobe" ]] && grep -q 'iifname !=' <<<"$sobe" && grep -F -q 'update @flows' <<<"$sobe"; then
    ok "a regra de subida casa o que NÃO entra por uma WAN e chaveia origem . destino . porta"
  else
    bad "a regra de subida está fora de forma: sem o escopo por interface, cada endereço da internet que responde vira uma tupla e o set enche em minutos" \
        "${sobe:-linha ausente}"
  fi
  if [[ -n "$desce" ]] && grep -qE 'iifname (\{|")' <<<"$desce" && ! grep -q 'iifname !=' <<<"$desce" &&
     ! grep -q 'oifname' <<<"$desce" && grep -F -q 'update @flows' <<<"$desce"; then
    ok "a regra de descida casa o que ENTRA pela WAN e inverte a chave — a resposta soma na mesma tupla da ida, sem contar ninguém duas vezes"
  else
    bad "a regra de descida está ausente ou fora de forma: faltando, o volume é só o que o aparelho enviou; com 'oifname !=' no lugar de 'iifname', o tráfego LAN→LAN é contado em dobro" \
        "${desce:-linha ausente} | chain: $(tr '\n' ' ' <<<"$chain" | head -c 200)"
  fi

  # A JANELA E O TETO QUE O KERNEL APLICA. As duas leituras são ancoradas em
  # linha inteira, como as regexes do próprio produto (reFlowSize/reFlowTimeout
  # são `^\s*... \s*$` exatamente porque a palavra timeout também aparece na
  # lista de flags): um `grep -q '5m'` frouxo daria OK para `timeout 15m`,
  # `45m` ou `1h5m`, e a bateria estaria mais frouxa que o código que audita.
  local decl_jan decl_size
  decl_jan=$(vm "nft list set inet linkguard_flows flows 2>/dev/null | grep -E '^[[:space:]]*timeout [^[:space:]]+[[:space:]]*$'" | tr -d '\r' | head -1)
  decl_size=$(vm "nft list set inet linkguard_flows flows 2>/dev/null | grep -E '^[[:space:]]*size [0-9]+[[:space:]]*$'" | tr -d '\r' | head -1)
  if [[ "${decl_jan//[[:space:]]/}" == "timeout5m" ]]; then
    ok "o set no kernel guarda EXATAMENTE a janela escolhida (${decl_jan//[[:space:]]/})"
  else
    bad "o kernel não ficou com a janela de 5 min que foi salva: a tela anunciaria uma retenção que o set não tem" \
        "declaração: ${decl_jan:-ausente}"
  fi
  if [[ "${decl_size//[[:space:]]/}" == "size32768" ]]; then
    ok "e guarda o teto escolhido (${decl_size//[[:space:]]/}): a metade do contrato que cobra memória de kernel também chegou lá"
  else
    bad "o kernel não ficou com o teto de 32768 que foi salvo: a tela prometeria uma capacidade que o set não tem" \
        "declaração: ${decl_size:-ausente}"
  fi
  M_Z2=1

  # ── Z3 — A CONVERSA APARECE, COM O DESTINO CERTO E O VOLUME SUBINDO ───────
  # A leitura é a do PRODUTO (a mesma rota que a tela chama); o kernel entra só
  # como testemunha quando ela falha.
  local enviou1
  enviou1=$(fala_z 200)
  if [[ "$enviou1" != ok:* ]]; then
    bad "o host da LAN parou de atravessar o firewall depois de a medição montar" \
        "resposta='${enviou1:-nada}' | chain: $(tr '\n' ' ' <<<"$chain" | head -c 200)"
    encerra_z "a LAN parou de atravessar com a medição montada"
    return
  fi

  # Espera com teto, não sleep cego: a leitura do produto tem cache de 10 s
  # (hostflows.ValidadeDoCache), então a conversa pode existir no kernel e ainda
  # não estar na resposta.
  local corpo1="" linha1="" bytes1=0
  for i in $(seq 1 15); do
    corpo1=$(body GET "/api/hosts/traffic/flows?ip=$LAN_IP" "$tok")
    linha1=$(linha_z "$corpo1")
    [[ -n "$linha1" ]] && break
    sleep 2
  done
  if [[ -n "$linha1" ]]; then
    bytes1=$(awk '{print $4}' <<<"$linha1")
    ok "o produto devolve a conversa do aparelho da LAN com a origem, o destino e a porta certos ($linha1)"
  else
    bad "A CONVERSA NÃO APARECEU na leitura do produto — é a pergunta da issue sem resposta" \
        "kernel: $(elemento_cru | head -c 160) | resposta: $(head -c 240 <<<"$corpo1")"
  fi

  # Montada, e a janela lida do KERNEL. "Ligado no banco" e "existe no kernel"
  # são estados diferentes, e a tela tem nome para cada um.
  local montada janela_api
  montada=$(campo_z "$corpo1" montada)
  janela_api=$(campo_z "$corpo1" janela_minutos)
  if [[ "$montada" == "True" && "$janela_api" == "5" ]]; then
    ok "a resposta diz MONTADA e anuncia a janela que o kernel aplica (5 min)"
  else
    bad "a resposta não afirma o estado real da medição (montada='$montada', janela='$janela_api')" \
        "$(head -c 240 <<<"$corpo1")"
  fi
  M_Z3=1

  # O VOLUME SOBE. Um número parado é indistinguível de um número inventado no
  # boot: a segunda rajada é o que prova que a coluna mede tráfego.
  local enviou2 bytes2=0 corpo2="" linha2=""
  if [[ -z "$linha1" ]]; then
    pular "Z3b. O volume da conversa sobe com o tráfego" \
          "a conversa não chegou a aparecer; não há linha para ver subir"
  else
    enviou2=$(fala_z 300)
    if [[ "$enviou2" != ok:* ]]; then
      bad "a segunda rajada não atravessou o firewall ('$enviou2'); a subida do volume não foi medida"
      M_Z3B=1
    else
      for i in $(seq 1 15); do
        corpo2=$(body GET "/api/hosts/traffic/flows?ip=$LAN_IP" "$tok")
        linha2=$(linha_z "$corpo2")
        bytes2=$(awk '{print $4}' <<<"${linha2:-0 0 0 0}")
        [[ -n "$linha2" && "${bytes2:-0}" -gt "${bytes1:-0}" ]] && break
        sleep 2
      done
      if [[ "${bytes2:-0}" -gt "${bytes1:-0}" ]]; then
        ok "mais tráfego, mais volume na mesma conversa (${bytes1} → ${bytes2} bytes)"
      else
        bad "o volume da conversa não subiu depois de mais 300 KB atravessarem (${bytes1} → ${bytes2:-nada})" \
            "kernel: $(elemento_cru | head -c 160)"
      fi
      M_Z3B=1
    fi
  fi

  # ── Z3c — A OCUPAÇÃO QUE O PRODUTO DEVOLVE É A DO KERNEL ──────────────────
  # Medida AQUI, com o set LONGE do teto, e não lá na Z7: com o set preso em
  # `size 1024` e os dois lados esperando por "≥ 1024", uma igualdade só poderia
  # passar. Aqui a ocupação é um número qualquer, e a asserção é que ele está
  # entre as duas leituras de kernel que cercam a chamada — o intervalo existe
  # porque a resposta pode vir do cache de 10 s.
  local ok_ocup=0 k1 k2 ocup_api menor maior teto_api
  for i in $(seq 1 8); do
    k1=$(ocupa_z)
    corpo2=$(body GET "/api/hosts/traffic/flows?ip=$LAN_IP" "$tok")
    ocup_api=$(campo_z "$corpo2" ocupacao)
    teto_api=$(campo_z "$corpo2" teto)
    k2=$(ocupa_z)
    if [[ -n "$k1" && -n "$k2" && -n "$ocup_api" ]]; then
      menor="$k1"; maior="$k2"
      [[ "$k2" -lt "$k1" ]] && { menor="$k2"; maior="$k1"; }
      if [[ "$ocup_api" -ge "$menor" && "$ocup_api" -le "$maior" && "$ocup_api" -gt 0 ]]; then
        ok_ocup=1
        break
      fi
    fi
    sleep 3
  done
  if [[ "$ok_ocup" == 1 && "$teto_api" == "32768" ]]; then
    ok "a ocupação que o produto devolve é a que o kernel tem ($ocup_api tuplas, de um teto de $teto_api) — lida do set, não inventada"
  else
    bad "a ocupação do produto não bate com a do kernel (produto='${ocup_api:-nada}', kernel entre '${k1:-?}' e '${k2:-?}', teto='${teto_api:-nada}')" \
        "$(head -c 240 <<<"$corpo2")"
  fi
  M_Z3C=1

  # ── Z4 — A TABELA É SEPARADA DA DO FIREWALL ──────────────────────────────
  # A metade de kernel primeiro: duas tabelas irmãs, e o set de conversa FORA da
  # tabela que o Persist despeja.
  #
  # A ausência só é afirmada depois de um CONTROLE POSITIVO. `nft list table`
  # com 2>/dev/null e duas negativas transforma string vazia — nft recusando,
  # tabela ausente, ssh caindo — em OK, e o OK afirmaria sobre um texto que
  # ninguém leu.
  local tabelas tabela_fw
  tabelas=$(vm "nft list tables 2>/dev/null" | tr -d '\r')
  tabela_fw=$(vm "nft list table inet linkguard 2>/dev/null" | tr -d '\r')
  if grep -q 'table inet linkguard_flows' <<<"$tabelas" && grep -q 'table inet linkguard$' <<<"$tabelas"; then
    ok "a conversa mora numa tabela IRMÃ (inet linkguard_flows), ao lado da do firewall e não dentro dela"
  else
    bad "não achei as duas tabelas separadas no kernel" "$(tr '\n' ' ' <<<"$tabelas" | head -c 200)"
  fi
  if ! grep -q 'chain forward' <<<"$tabela_fw"; then
    pular "Z4. A tabela é separada da do firewall no kernel" \
          "não consegui ler a tabela do firewall (nem a chain forward apareceu); dizer que o set de conversa não está nela seria afirmar sobre um texto vazio"
  elif ! grep -qE '^[[:space:]]*(set|chain) flows \{' <<<"$tabela_fw" &&
       ! grep -F -q "$LAN_IP . $DEST_IP" <<<"$tabela_fw"; then
    ok "a tabela do firewall foi lida inteira e não tem o set de conversa nem tupla nenhuma dentro dela"
    M_Z4=1
  else
    bad "O SET DE CONVERSA ESTÁ DENTRO DA TABELA DO FIREWALL: é o defeito da #198 acontecendo de novo, e todo boot passaria a ressuscitar conversa velha" \
        "$(grep -nE '(set|chain) flows \{' <<<"$tabela_fw" | head -2 | tr '\n' ' ' | head -c 200)"
    M_Z4=1
  fi

  # E a metade que só uma máquina de verdade prova: o ARQUIVO DE BOOT. Um
  # Persist de verdade é disparado pelo caminho do produto (mudança de link
  # reconcilia a contabilidade, que persiste), e a reescrita é CONFERIDA — sem
  # isso a asserção passaria sobre um arquivo que ninguém reescreveu.
  #
  # O mtime é ATRASADO à força antes do gatilho. `stat -c %Y` tem resolução de
  # segundo: uma reescrita que caia no mesmo segundo da leitura anterior é
  # indistinguível de reescrita nenhuma, e a asserção que só uma máquina de
  # verdade prova viraria PULADA por artefato de relógio.
  local existe_conf
  existe_conf=$(vm "test -f /etc/nftables.conf && echo sim || echo nao" | tr -d '\r' | head -1)
  if [[ "$existe_conf" != "sim" ]]; then
    pular "Z4b. O arquivo de boot não ganha conversa" \
          "não há /etc/nftables.conf nesta caixa; não há arquivo de boot sobre o qual afirmar coisa nenhuma"
    pular "Z4c. O arquivo de boot guarda elemento de contabilidade (o perigo da #198 é real)" \
          "não há /etc/nftables.conf nesta caixa"
  else
    vm "touch -d '1 hour ago' /etc/nftables.conf" >/dev/null 2>&1
    local mtime_antes mtime_depois="" st_ad2
    mtime_antes=$(vm "stat -c %Y /etc/nftables.conf" | tr -d '\r' | head -1)
    st_ad2=$(status POST /api/links/auto-detect "$tok")
    for i in $(seq 1 12); do
      mtime_depois=$(vm "stat -c %Y /etc/nftables.conf" | tr -d '\r' | head -1)
      [[ -n "$mtime_depois" && "$mtime_depois" != "$mtime_antes" ]] && break
      sleep 2
    done
    if [[ -z "$mtime_antes" || -z "$mtime_depois" || "$mtime_depois" == "$mtime_antes" ]]; then
      pular "Z4b. O arquivo de boot não ganha conversa" \
            "o /etc/nftables.conf não foi reescrito nesta janela (auto-detect=$st_ad2, mtime '${mtime_antes:-ausente}' → '${mtime_depois:-ausente}'); afirmar que a conversa não está nele seria verde sem medida"
      pular "Z4c. O arquivo de boot guarda elemento de contabilidade (o perigo da #198 é real)" \
            "o /etc/nftables.conf não foi reescrito nesta janela; o contraste que dá peso à Z4 não pôde ser medido"
    else
      local conf_flows conf_tupla conf_acct_host conf_acct_qq
      conf_flows=$(vm "grep -c linkguard_flows /etc/nftables.conf 2>/dev/null; true" | tr -d '\r' | head -1)
      conf_tupla=$(vm "grep -c '$LAN_IP . $DEST_IP' /etc/nftables.conf 2>/dev/null; true" | tr -d '\r' | head -1)
      if [[ "${conf_flows:-1}" == "0" && "${conf_tupla:-1}" == "0" ]]; then
        ok "o arquivo de boot foi reescrito e NÃO ganhou nem a tabela de conversa nem elemento de conversa"
      else
        bad "O /etc/nftables.conf GANHOU A CONVERSA: o arquivo de boot passa a crescer com o tráfego da rede e a ressuscitar, a cada boot, a afirmação de que este aparelho falou com aquele destino" \
            "linkguard_flows=${conf_flows:-?} tuplas=${conf_tupla:-?} | $(vm "grep -o 'linkguard_flows.\{0,80\}' /etc/nftables.conf 2>/dev/null | head -1" | tr -d '\r' | head -c 160)"
      fi
      M_Z4B=1

      # Z4c — O CONTRASTE, MEDIDO. É ele que dá peso à Z4 inteira: o MESMO
      # arquivo guarda elementos de set dinâmico da contabilidade (é a #198,
      # viva em produção). Se o Persist parasse de despejar elementos, a tabela
      # irmã deixaria de ser necessária e ninguém saberia — então isto é
      # asserção, e não uma frase bonita dentro de um OK de outra coisa.
      conf_acct_host=$(vm "grep -c '$LAN_IP counter packets' /etc/nftables.conf 2>/dev/null; true" | tr -d '\r' | head -1)
      conf_acct_qq=$(vm "grep -c 'counter packets' /etc/nftables.conf 2>/dev/null; true" | tr -d '\r' | head -1)
      if [[ "${conf_acct_host:-0}" -gt 0 ]]; then
        ok "e o mesmo arquivo guarda ${conf_acct_host} contador(es) de contabilidade DESTE host: o perigo da #198 é real e medido, e a conversa escapa dele por morar noutra tabela"
      elif [[ "${conf_acct_qq:-0}" -gt 0 ]]; then
        ok "e o mesmo arquivo guarda ${conf_acct_qq} elemento(s) de contabilidade com contador: o perigo da #198 é real e medido (embora não com o host desta bateria)"
      else
        bad "o /etc/nftables.conf não guarda elemento de contabilidade nenhum: a premissa da #198 — Persist despeja os elementos dos sets dinâmicos — não se confirma nesta caixa, e a Z4 passou a afirmar uma separação cujo perigo ninguém mediu" \
            "$(vm "grep -c . /etc/nftables.conf 2>/dev/null; grep -o 'set acct[^ ]*' /etc/nftables.conf 2>/dev/null | head -2" | tr -d '\r' | tr '\n' ' ' | head -c 200)"
      fi
      M_Z4C=1
    fi
  fi

  # ── Z5 — O CONTADOR NÃO OBEDECE À JANELA, E A TELA NÃO PODE MENTIR ───────
  # MEDIDO no kernel, não deduzido: um elemento de set `dynamic,timeout` renova
  # o prazo a cada pacote, e o contador dele NÃO zera junto. Logo uma conversa
  # que nunca fica quieta acumula desde o PRIMEIRO pacote, muito além dos
  # minutos anunciados no topo da tela — e como a lista é ordenada por volume,
  # VoIP, VPN e backup sobem acima de quem de fato pesou na janela.
  local t1 b1 e1
  t1=$(tupla_z); b1=$(awk '{print $2}' <<<"$t1"); e1=$(awk '{print $3}' <<<"$t1")
  if [[ -z "$t1" || -z "${e1:-}" || "${e1:-0}" -le 0 ]]; then
    pular "Z5. O contador não obedece à janela" \
          "não consegui ler o prazo do elemento nesta caixa (o nft desta versão pode imprimir de outra forma); o elemento cru é: $(elemento_cru | head -c 140)"
  else
    # Primeiro o prazo TEM de andar para baixo — senão não há renovação nenhuma
    # para observar depois, e "voltou ao topo" não significaria nada.
    local e2="" t2=""
    for i in $(seq 1 20); do
      sleep 3
      t2=$(tupla_z); e2=$(awk '{print $3}' <<<"$t2")
      [[ -z "$t2" ]] && break
      [[ -n "$e2" && "$e2" -le $(( e1 - 12 )) ]] && break
    done
    if [[ -z "$t2" ]]; then
      bad "a conversa SUMIU do set enquanto o prazo era observado; o volume passaria a ser lido como 'este aparelho não falou'" \
          "antes: ${t1:-nada} | agora: $(elemento_cru | head -c 140)"
      M_Z5=1
    elif [[ -z "$e2" || "$e2" -gt $(( e1 - 12 )) ]]; then
      pular "Z5. O contador não obedece à janela" \
            "o prazo do elemento não andou nesta caixa em 60 s (${e1}s → ${e2:-nada}); sem ele andar, renovação não é observável"
    else
      local enviou3="" t3="" b3="" e3=""
      enviou3=$(fala_z 100)
      for i in $(seq 1 15); do
        t3=$(tupla_z); b3=$(awk '{print $2}' <<<"$t3"); e3=$(awk '{print $3}' <<<"$t3")
        [[ -n "$e3" && "$e3" -gt "$e2" ]] && break
        sleep 2
      done
      if [[ "$enviou3" != ok:* ]]; then
        pular "Z5. O contador não obedece à janela" \
              "a rajada de renovação não atravessou o firewall ('$enviou3')"
      elif [[ -z "$e3" || -z "$b3" ]]; then
        bad "a conversa SUMIU do set durante a medição de prazo; o volume passaria a ser lido como 'este aparelho não falou'" \
            "antes: ${t1:-nada} | agora: $(elemento_cru | head -c 140)"
        M_Z5=1
      elif [[ "$e3" -gt "$e2" && "$b3" -gt "$b1" ]]; then
        ok "a conversa que não fica quieta RENOVA o prazo (${e2}s → ${e3}s, de um teto de 300s) e o contador NÃO zera junto (${b1} → ${b3} bytes): o volume é desde o primeiro pacote, não o da janela"
        M_Z5=1
      elif [[ "$e3" -le "$e2" ]]; then
        # A Z2 já leu `update @flows` no kernel desta caixa, então isto não
        # absolve um `add @flows` que nunca renovaria: o que resta é o kernel
        # não renovar o timeout no update.
        pular "Z5. O contador não obedece à janela" \
              "o prazo não voltou a subir (${e2}s → ${e3}s) numa chain que a Z2 leu com 'update @flows': este kernel não renova o timeout no update, e a premissa da asserção não vale aqui"
      else
        bad "o contador ZEROU junto com a renovação do prazo (${b1} → ${b3} bytes)" \
            "elemento: $(elemento_cru | head -c 160)"
        M_Z5=1
      fi
    fi
  fi

  # ── Z5b — E O TEXTO QUE O PRODUTO REALMENTE ENTREGA ───────────────────────
  # A tela mostra "conversas dos últimos N min" ao lado de uma coluna de volume
  # que NÃO é dos últimos N min: sem uma frase que desfaça isso, a tela mente
  # com números certos. O texto é buscado do binário no ar (o painel é
  # embutido), e não do repositório — o que vale é o que chega ao navegador.
  #
  # E A CHAVE É CONTADA, não só procurada. As strings moram num objeto literal
  # com pt e en importado estaticamente: a frase está no pacote porque alguém a
  # escreveu no YAML, não porque algum componente a renderiza. Se o componente
  # parar de chamar t('svc.fluxos.limits.volume'), um grep pela frase continua
  # verde e o admin nunca vê o aviso — que é a asserção inteira. Três ocorrências
  # da chave é o padrão do bundle deste projeto (dicionário pt + dicionário en +
  # a chamada); duas querem dizer "a frase existe e ninguém a mostra".
  #
  # Os literais com acento são procurados sem o Ç por precaução de codificação,
  # não por necessidade: o Vite deste projeto emite UTF-8 literal no bundle.
  local idx assets js="" p
  idx=$(curl -s --max-time 10 "$API/" 2>/dev/null)
  assets=$(grep -oE '/assets/[A-Za-z0-9_.-]+\.js' <<<"$idx" | sort -u)
  for p in $assets; do
    js="$js$(curl -s --max-time 20 "$API$p" 2>/dev/null)"
  done
  if [[ -z "$assets" || -z "$js" ]]; then
    pular "Z5b. A tela entregue ao navegador não mente sobre o volume" \
          "não consegui baixar o pacote do painel para ler o texto entregue (assets='${assets:-nenhum}')"
  else
    local falta="" n_volume n_janela
    n_volume=$(grep -o 'svc\.fluxos\.limits\.volume' <<<"$js" | wc -l)
    n_janela=$(grep -o 'svc\.fluxos\.window' <<<"$js" | wc -l)
    grep -F -q 'SINCE IT STARTED' <<<"$js"                 || falta="$falta en:volume-acumulado"
    grep -F -q 'DESDE QUE ELA COME' <<<"$js"               || falta="$falta pt:volume-acumulado"
    grep -F -q 'not the period the volume covers' <<<"$js" || falta="$falta en:janela-nao-e-o-volume"
    [[ "${n_volume:-0}" -ge 3 ]] || falta="$falta volume:so-no-dicionario($n_volume)"
    [[ "${n_janela:-0}" -ge 3 ]] || falta="$falta janela:so-no-dicionario($n_janela)"
    if [[ -z "$falta" ]]; then
      ok "a tela entregue ao navegador diz, nos dois idiomas, que a janela é de QUEM falou e que o volume é o acumulado desde o começo da conversa — e as duas frases são CHAMADAS por um componente, não só declaradas no dicionário"
    else
      bad "A TELA NÃO DESFAZ A LEITURA ERRADA: ela anuncia uma janela de minutos ao lado de um volume que não é da janela, e o texto que corrige isso não chega ao navegador (faltando:$falta)" \
          "tamanho do pacote lido: ${#js} bytes | ocorrências: volume=$n_volume janela=$n_janela"
    fi
    M_Z5B=1
  fi

  # ── Z6 — SILÊNCIO: A IDENTIDADE NÃO SAI PELO /metrics ABERTO ─────────────
  # A medição está LIGADA e cheia de dado neste ponto — é o único momento em que
  # esta asserção significa alguma coisa.
  #
  # E ela é GUARDA DE REGRESSÃO, com todas as letras: esta entrega não registrou
  # série nenhuma de fluxo em coletor nenhum, então não existe hoje caminho de
  # código que publique conversa aqui. O que a asserção protege é a regra que
  # internal/metrics/exposicao.go escreve e que as issues #115, #117 e #118
  # herdam — endereço de host da LAN é inventário da rede do cliente e não sai
  # por canal não autenticado. Por onde este dado de fato quase escapou é a
  # asserção seguinte.
  local aberto
  aberto=$(curl -s --max-time 8 "$API/metrics" 2>/dev/null)
  if [[ -z "$aberto" ]]; then
    bad "o /metrics não respondeu; a asserção de silêncio não pôde ser feita"
  else
    if ! grep -q "$LAN_IP" <<<"$aberto" && ! grep -q "$DEST_IP" <<<"$aberto" &&
       ! grep -qiE 'linkguard_(flow|conversa|host_)' <<<"$aberto"; then
      ok "o /metrics aberto não publica endereço de aparelho, destino nem conversa"
    else
      bad "QUEM-FALOU-COM-QUEM NO /metrics SEM AUTENTICAÇÃO: é o inventário da rede do cliente num endpoint público" \
          "$(grep -E "$LAN_IP|$DEST_IP|linkguard_(flow|conversa|host_)" <<<"$aberto" | head -2 | tr '\n' ' ' | head -c 200)"
    fi
    # E continua servindo o que sempre serviu: sem isto, "não tem identidade"
    # passaria também com o endpoint quebrado.
    if grep -q 'linkguard_' <<<"$aberto"; then
      ok "o /metrics aberto continua servindo as métricas agregadas (agregado não é identidade)"
    else
      bad "o /metrics não serve mais nada; o silêncio acima não prova nada" "$(head -c 150 <<<"$aberto")"
    fi
  fi
  M_Z6=1

  # ── Z6b — O DUMP DE RULESET E O BACKUP SÃO ESCOPADOS ─────────────────────
  # É por aqui que o dado quase escapou, e por dois canais, não um: Ruleset e
  # Save eram `nft list ruleset`. O primeiro sai por firewall.read — que está no
  # papel de Operador E dentro do de Visualizador — sem auditoria; o segundo é
  # pior, porque CONGELA a janela numa linha de banco: o que era retenção
  # configurável em memória vira registro permanente em disco.
  #
  # Os dois têm CONTROLE POSITIVO. `body` nunca devolve vazio numa resposta de
  # erro — devolve {"error":...} —, então um 403, um 500 ou um token expirado
  # passariam por um teste de "não contém linkguard_flows" e a bateria
  # declararia silêncio sobre um endpoint que não respondeu.
  local rs
  rs=$(body GET /api/nftables/ruleset "$tok")
  if ! grep -F -q 'table inet linkguard' <<<"$rs"; then
    bad "a rota de ruleset não devolveu a tabela do firewall; a asserção de escopo não pôde ser feita (a ausência de 'linkguard_flows' aqui não prova nada)" \
        "$(head -c 200 <<<"$rs")"
  elif ! grep -F -q 'linkguard_flows' <<<"$rs" && ! grep -F -q "$LAN_IP . $DEST_IP" <<<"$rs"; then
    ok "o dump de ruleset devolve a tabela do firewall e SÓ ela — a tabela de conversa não sai por firewall.read"
  else
    bad "A TABELA DE CONVERSA SAI PELO DUMP DE RULESET: quem tem firewall.read (o papel de Visualizador inclusive) lê com quem cada aparelho falou, sem a permissão criada para isso e sem auditoria" \
        "$(grep -o 'linkguard_flows.\{0,80\}' <<<"$rs" | head -1 | head -c 160)"
  fi

  # O backup é uma MUTAÇÃO e deixa uma linha em iptables_backups (não há rota
  # para removê-la): é o preço de medir o canal que congela o dado, e é barato
  # perto de não medi-lo. O corpo da resposta E a linha guardada são conferidos,
  # porque o vazamento aconteceria nos dois.
  local resp_bk st_bk corpo_bk rotulo_bk="lgz-escopo-$$"
  resp_bk=$(api POST /api/nftables/backup "$tok" "{\"label\":\"$rotulo_bk\"}")
  st_bk=$(head -1 <<<"$resp_bk"); corpo_bk=$(tail -n +2 <<<"$resp_bk")
  if [[ "$st_bk" != "201" && "$st_bk" != "200" ]]; then
    pular "Z6b2. O backup de ruleset não congela a conversa numa linha de banco" \
          "o painel não criou o backup de teste ($st_bk): $(head -c 140 <<<"$corpo_bk")"
  else
    local guardado
    guardado=$(body GET /api/nftables/backups "$tok" | python3 -c "
import json,sys
rot=sys.argv[1]
for b in json.load(sys.stdin):
    if b.get('label')==rot:
        print(b.get('rules') or '')
        break" "$rotulo_bk" 2>/dev/null)
    if ! grep -F -q 'table inet linkguard' <<<"$corpo_bk" || ! grep -F -q 'table inet linkguard' <<<"$guardado"; then
      bad "o backup não guardou a tabela do firewall; a asserção de escopo não pôde ser feita sobre ele" \
          "corpo: $(head -c 120 <<<"$corpo_bk") | guardado: $(head -c 120 <<<"$guardado")"
    elif ! grep -F -q 'linkguard_flows' <<<"$corpo_bk" && ! grep -F -q "$LAN_IP . $DEST_IP" <<<"$corpo_bk" &&
         ! grep -F -q 'linkguard_flows' <<<"$guardado" && ! grep -F -q "$LAN_IP . $DEST_IP" <<<"$guardado"; then
      ok "o backup de ruleset guarda a tabela do firewall e não a de conversa: a janela rolante não vira linha permanente em disco"
    else
      bad "O BACKUP CONGELOU A CONVERSA NUMA LINHA DE BANCO: a retenção configurável de quem-falou-com-quem virou registro permanente em disco, fora da janela e fora da permissão criada para ela" \
          "$(grep -o 'linkguard_flows.\{0,60\}' <<<"$corpo_bk$guardado" | head -1 | head -c 160)"
    fi
  fi
  M_Z6B=1

  # ── Z6c — A PERMISSÃO NASCE FORA DOS PAPÉIS DE FÁBRICA ───────────────────
  # Se 'traffic.flows' entrar no papel de Operador ou de Visualizador, no dia do
  # upgrade todo mundo que já tinha "ver monitoramento" ganha o histórico de
  # navegação da empresa sem ninguém ter decidido.
  #
  # O papel de administrador entra junto por um motivo de medição, não de
  # simetria: se os ids de fábrica não existirem mais nesta caixa, `role_perms`
  # devolve vazio e a asserção de silêncio passaria SOZINHA, dizendo "não está no
  # operador" sobre um papel que ninguém consultou.
  local perms_adm perms_op perms_vis p_op p_vis p_adm
  perms_adm=$(role_perms "$tok" role-admin)
  perms_op=$(role_perms "$tok" role-operator)
  perms_vis=$(role_perms "$tok" role-viewer)
  p_adm=$(grep -cx 'traffic.flows' <<<"$perms_adm")
  p_op=$(grep -cx 'traffic.flows' <<<"$perms_op")
  p_vis=$(grep -cx 'traffic.flows' <<<"$perms_vis")
  if [[ -z "$perms_adm" ]]; then
    pular "Z6c. A permissão de ver conversa nasce fora dos papéis de fábrica" \
          "não consegui ler as permissões do papel de administrador de fábrica (role-admin) nesta caixa; sem essa leitura, 'não está no operador' não prova nada"
  elif [[ "${p_adm:-0}" == "0" ]]; then
    bad "nem o administrador tem traffic.flows: a permissão não chegou ao papel que é sincronizado no upgrade, e a tela não existe para ninguém"
    M_Z6C=1
  elif [[ "${p_op:-1}" == "0" && "${p_vis:-1}" == "0" ]]; then
    ok "a permissão de ver com quem os aparelhos falaram está no administrador e NÃO vem de brinde nos papéis de Operador nem de Visualizador"
    M_Z6C=1
  else
    bad "A PERMISSÃO DE VER O HISTÓRICO DE CONVERSA ESTÁ NUM PAPEL DE FÁBRICA (operador=$p_op, visualizador=$p_vis): quem já tinha 'ver monitoramento' ganhou o histórico de navegação da empresa sem ninguém decidir"
    M_Z6C=1
  fi

  # ── Z6d — A LEITURA FICA REGISTRADA, COM O ALVO ──────────────────────────
  # É a primeira consulta de LEITURA auditada do produto, e é o que responde
  # "quem olhou" no dia em que alguém reclamar. A conferência é no MESMO
  # registro: dois greps soltos dariam OK para um 'traffic.flows.read' com alvo
  # "rede inteira" mais um endereço qualquer noutra linha — e "fulano abriu uma
  # tela" é exatamente o registro inútil que a issue existe para não produzir.
  local casou
  casou=$(body GET "/api/logs?limit=200" "$tok" | python3 -c "
import json,sys
alvo=sys.argv[1]
n=0
for l in json.load(sys.stdin):
    if l.get('action')=='traffic.flows.read' and l.get('resource')==alvo:
        n+=1
print(n)" "$LAN_IP" 2>/dev/null)
  if [[ "${casou:-0}" -gt 0 ]]; then
    ok "as consultas desta bateria ficaram no log de auditoria com o aparelho consultado NOMEADO no mesmo registro ($casou)"
  else
    bad "a consulta de quem-falou-com-quem NÃO ficou no log de auditoria com o alvo: o cliente não tem como responder quem olhou o histórico da rede dele" \
        "$(body GET "/api/logs?limit=20" "$tok" | head -c 200)"
  fi
  M_Z6D=1

  # ── Z7 — O TETO APARECE NA LEITURA, EM VEZ DE SUMIR ──────────────────────
  # O teto vai ao mínimo (1024) e o set é enchido com tuplas de verdade: uma
  # rajada de UDP para portas distintas, que é o que um cliente de torrent ou de
  # VoIP produz sozinho numa hora. Salvar a configuração RECRIA o set (é o que o
  # nft oferece: não dá para trocar o timeout de um set mantendo os elementos),
  # então a contagem daqui não herda nada do que veio antes.
  #
  # A asserção NÃO é uma igualdade contra o kernel: com o set preso em size 1024
  # e as duas esperas saindo em ">= 1024", uma igualdade só poderia passar — e
  # qualquer defasagem legítima do cache de 10 s viraria falha. Que a ocupação
  # vem do kernel já foi medido na Z3c, com o set longe do teto. O que se cobra
  # aqui é o que só o teto batido revela: o número aparece, e a resposta AVISA.
  local st_teto
  st_teto=$(status PUT /api/hosts/traffic/flows/config "$tok" '{"ligado":true,"janela_minutos":5,"teto":1024}')
  if [[ "$st_teto" != "200" ]]; then
    pular "Z7. O teto aparece na leitura, em vez de sumir" \
          "o painel recusou baixar o teto para 1024 ($st_teto); sem teto pequeno não dá para enchê-lo dentro de uma bateria"
  else
    local enviados ocup_kernel=""
    enviados=$(vm "ip netns exec lanz timeout 60 python3 /tmp/lgz_enche.py $DEST_IP 20000 1400 2>/dev/null" | tr -d '\r' | tail -1)
    for i in $(seq 1 15); do
      ocup_kernel=$(ocupa_z)
      [[ -n "$ocup_kernel" && "$ocup_kernel" -ge 1024 ]] && break
      sleep 2
    done
    if [[ -z "$ocup_kernel" || "$ocup_kernel" -lt 1024 ]]; then
      # Não encher o set é falha de MEDIÇÃO, não do produto: sem o set cheio,
      # "a leitura mostrou cheio" não teria o que mostrar.
      pular "Z7. O teto aparece na leitura, em vez de sumir" \
            "não consegui encher o set nesta caixa (${enviados:-0} pacotes enviados, ${ocup_kernel:-0} tuplas no kernel de 1024)"
    else
      local corpo_cheio="" ocup="" teto cheio ja_cheio
      for i in $(seq 1 10); do
        corpo_cheio=$(body GET "/api/hosts/traffic/flows?ip=$LAN_IP" "$tok")
        ocup=$(campo_z "$corpo_cheio" ocupacao)
        [[ -n "$ocup" && "$ocup" -ge 900 ]] && break
        sleep 2
      done
      teto=$(campo_z "$corpo_cheio" teto)
      cheio=$(campo_z "$corpo_cheio" cheio)
      ja_cheio=$(campo_z "$corpo_cheio" ja_esteve_cheio)
      if [[ -n "$ocup" && "$ocup" -ge 900 && "$ocup" -le 1024 && "$teto" == "1024" ]]; then
        ok "a leitura do produto devolve a ocupação do set saturado ($ocup de $teto) — o teto batido aparece como número, não some"
      else
        bad "a leitura escondeu a ocupação do set: o kernel tem $ocup_kernel tuplas e o produto devolveu '${ocup:-nada}' de um teto '${teto:-nada}'" \
            "$(head -c 240 <<<"$corpo_cheio")"
      fi
      if [[ "$cheio" == "True" || "$ja_cheio" == "True" ]]; then
        ok "e a resposta AVISA que a medição encheu (cheio=$cheio, já esteve cheio=$ja_cheio): o que falta da lista é a conversa mais nova, não a menos importante"
      else
        bad "O SET ESTÁ CHEIO E A RESPOSTA NÃO AVISA (cheio=$cheio, já esteve cheio=$ja_cheio): a tela mostra uma lista incompleta como se fosse a rede inteira" \
            "$(head -c 240 <<<"$corpo_cheio")"
      fi
      M_Z7=1
    fi
  fi

  # ── Z8 — SILÊNCIO: DESLIGAR APAGA A MEDIÇÃO ──────────────────────────────
  # Desligar não é parar de mostrar: a base chain sai do hook forward (some o
  # custo por pacote da rede inteira) e o dado some junto — que é exatamente o
  # que o admin pediu ao desligar um registro de quem falou com quem.
  #
  # O `salvou` NÃO é zerado aqui. Zerá-lo depois do 200 desarmava a rede de
  # segurança no único caso para o qual ela existe: o produto responde 200 e
  # deixa a tabela de pé — e a limpeza, achando que não havia nada ligado, ia
  # embora deixando a chain no forward das baterias seguintes. Quem decide se há
  # o que limpar é o kernel, no limpa_z.
  local st_off
  st_off=$(status PUT /api/hosts/traffic/flows/config "$tok" '{"ligado":false,"janela_minutos":5,"teto":1024}')
  if [[ "$st_off" != "200" ]]; then
    bad "o painel recusou desligar o registro de conversa ($st_off)"
  else
    local sumiu corpo_fim lig_fim mont_fim
    sumiu=$(espera_z ausente 10)
    case "$sumiu" in
      ausente)
        ok "desligar apagou a tabela inteira: a chain saiu do hook forward, e o set e as conversas foram com ela" ;;
      existe)
        bad "DESLIGAR NÃO APAGOU: a chain continua no caminho de todo o tráfego da LAN e as conversas continuam guardadas depois de o admin ter dito não" \
            "$(vm "nft list table inet linkguard_flows 2>&1 | head -6" | tr -d '\r' | tr '\n' ' ' | head -c 240)" ;;
      *)
        pular "Z8b. Desligar tira a tabela do kernel" \
              "não consegui perguntar ao kernel se a tabela saiu (ssh/nft não responderam); a limpeza ainda vai tentar, e ela cobra o resultado" ;;
    esac
    corpo_fim=$(body GET "/api/hosts/traffic/flows?ip=$LAN_IP" "$tok")
    lig_fim=$(campo_z "$corpo_fim" ligado)
    mont_fim=$(campo_z "$corpo_fim" montada)
    if [[ "$lig_fim" == "False" && "$mont_fim" == "False" ]]; then
      ok "e a tela volta a dizer DESLIGADO e NÃO MONTADA, sem conversa nenhuma para mostrar"
    else
      bad "depois de desligar, a tela não diz desligado (ligado='$lig_fim', montada='$mont_fim')" \
          "$(head -c 240 <<<"$corpo_fim")"
    fi
  fi
  M_Z8=1

  # A limpeza cobra o resto: o setting desligado no banco (é ele que remonta a
  # chain sozinho a cada mudança de link), a janela e o teto originais de volta,
  # e a postura do forward como esta bateria a encontrou.
  limpa_z
}

# ─── D2. Alvo por domínio (issue #123, PR #204) ──────────────────────────────
#
# A ASSERÇÃO QUE JUSTIFICA A BATERIA. Esta feature transforma uma resposta de
# DNS em regra de DROP no caminho do pacote. O endereço não é escolhido pelo
# admin: é escolhido por quem responde o domínio — isto é, por um terceiro.
#
# Isso só se prova numa máquina, e por dois motivos que teste em Go não alcança:
#
#   1. O ENDEREÇO TEM DE VIR DO NOSSO RESOLVER. Um teste que semeia o endereço
#      prova que o set funciona, não que o APRENDIZADO funciona. Aqui a consulta
#      é feita ao unbound da caixa, e o endereço que a bateria depois procura no
#      kernel é o que o unbound respondeu — não um que ela escolheu.
#   2. O DROP TEM DE ACONTECER NO FIO. Regra que está na chain e não descarta
#      pacote é o defeito clássico desta base. Mede-se de um host da LAN
#      atravessando o firewall, nunca da própria caixa: tráfego local nasce no
#      hook output e não passa pelo forward.
#
# E METADE DA BATERIA É SILÊNCIO, sem a qual "barrou" não significa nada:
#
#   D2-2 — EM ENSAIO NÃO BARRA. O mesmo domínio, o mesmo tráfego, antes de
#          promover: tem de passar. Sem esta, a asserção de bloqueio não
#          distingue enforcement de qualquer outra regra da caixa que já
#          estivesse descartando aquele destino.
#   D2-6 — COM O DNSTAP DESLIGADO nada é aprendido, e a tela DIZ isso. Uma tela
#          que mostra zero endereços quando o coletor está desligado mente por
#          omissão: o admin lê "ninguém acessou" onde a verdade é "não estou
#          medindo".
battery_alvo_por_dominio() {
  head_ "D2. Alvo por domínio"

  local M1=0 M2=0 M3=0 M4=0 M5=0 M6=0
  local tok="" idd="" limpou=0 dnstap_antes=""
  local DOM="deb.debian.org"

  limpa_d() {
    [[ "$limpou" == 1 ]] && return
    limpou=1
    [[ -n "$tok" && -n "$idd" ]] && status DELETE "/api/domain-targets/$idd" "$tok" >/dev/null 2>&1
    # O DNSTAP VOLTA AO ESTADO EM QUE FOI ENCONTRADO. A bateria T também o liga
    # e desliga; se as duas deixarem o estado ao acaso, a que rodar depois mede
    # uma caixa que a outra configurou.
    if [[ -n "$tok" && -n "$dnstap_antes" ]]; then
      status PUT /api/dns/config "$tok" \
        "{\"upstreams\":[],\"log_queries\":false,\"force_local_dns\":false,\"block_dot\":false,\"dns_except_ips\":[],\"dnstap_enabled\":$dnstap_antes}" >/dev/null 2>&1
    fi
    vm "ip netns del lgdom 2>/dev/null; ip link del lg-dom 2>/dev/null; true" >/dev/null 2>&1
    local sobrou
    sobrou=$(vm "nft list set inet linkguard dom_blocked 2>/dev/null | grep -c elements" | tr -d '\r' | head -1)
    if [[ "${sobrou:-0}" != "0" ]]; then
      bad "sobraram endereços no dom_blocked depois da limpeza; a bateria seguinte roda com destino barrado" \
          "$(vm "nft list set inet linkguard dom_blocked 2>/dev/null" | tr -d '\r' | head -c 160)"
    fi
  }

  encerra_d() {
    [[ "$M1" == 1 ]] || pular "D2-1. O endereço aprendido veio do nosso resolver" "$1"
    [[ "$M2" == 1 ]] || pular "D2-2. Em ensaio NÃO barra" "$1"
    [[ "$M3" == 1 ]] || pular "D2-3. Promovido, barra no fio" "$1"
    [[ "$M4" == 1 ]] || pular "D2-4. A tela conta do kernel" "$1"
    [[ "$M5" == 1 ]] || pular "D2-5. Apagar tira o endereço na hora" "$1"
    [[ "$M6" == 1 ]] || pular "D2-6. Dnstap desligado não aprende, e a tela diz" "$1"
    limpa_d
  }

  local initial
  initial=$(vm "cat /etc/linkguard-fw/initial-admin-password 2>/dev/null" | tr -d '\r\n')
  tok=$(login admin "$initial"); [[ -z "$tok" ]] && tok=$(login admin "NovaSenhaForte123")
  if [[ -z "$tok" ]]; then bad "sem sessão administrativa; a bateria D2 não roda"; encerra_d "sem sessão"; return; fi

  dnstap_antes=$(body GET /api/dns/config "$tok" | python3 -c "
import json,sys
print('true' if json.load(sys.stdin).get('dnstap_enabled') else 'false')" 2>/dev/null)
  [[ "$dnstap_antes" =~ ^(true|false)$ ]] || dnstap_antes="false"

  # Um host de mentira que ATRAVESSA o firewall. Tráfego da própria caixa nasce
  # no hook output e nunca passa pelo forward — mediria outra coisa.
  vm "ip netns del lgdom 2>/dev/null; ip link del lg-dom 2>/dev/null
      ip netns add lgdom && ip link add lg-dom type veth peer name dom-far && \
      ip link set dom-far netns lgdom && \
      ip addr add 192.168.131.1/24 dev lg-dom && ip link set lg-dom up && \
      ip netns exec lgdom sh -c 'ip link set lo up; ip addr add 192.168.131.2/24 dev dom-far; ip link set dom-far up; ip route add default via 192.168.131.1'" >/dev/null 2>&1
  if ! vm "ip netns exec lgdom ip -br addr show dom-far 2>/dev/null" | grep -q 192.168.131.2; then
    bad "não consegui montar o host de teste; a bateria D2 não tem de onde medir"
    encerra_d "o host de teste não subiu"; return
  fi

  # ── D2-6 (a metade de silêncio vem PRIMEIRO, com o dnstap ainda desligado) ──
  status PUT /api/dns/config "$tok" '{"upstreams":[],"log_queries":false,"force_local_dns":false,"block_dot":false,"dns_except_ips":[],"dnstap_enabled":false}' >/dev/null 2>&1
  sleep 4
  local st
  st=$(status POST /api/domain-targets "$tok" "{\"domain\":\"$DOM\",\"capability\":\"barrar\",\"link_id\":\"\",\"note\":\"bateria D2\"}")
  if [[ "$st" != "200" && "$st" != "201" ]]; then
    bad "o painel não aceitou cadastrar o domínio ($st)"; encerra_d "o domínio não entrou"; return
  fi
  idd=$(body GET /api/domain-targets "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
alvos=d if isinstance(d,list) else (d.get('targets') or d.get('alvos') or [])
for t in alvos:
    if t.get('domain')=='$DOM': print(t.get('id',''))" 2>/dev/null | head -1)
  if [[ -z "$idd" ]]; then
    bad "o domínio foi aceito mas não voltou na listagem; sem id não há o que promover" \
        "$(body GET /api/domain-targets "$tok" | head -c 200)"
    encerra_d "sem id do domínio"; return
  fi

  vm "python3 -c \"
import socket,struct
q=struct.pack('>HHHHHH',0xd201,0x0100,1,0,0,0)+b'\\x03deb\\x06debian\\x03org\\x00'+struct.pack('>HH',1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5)
for _ in range(3):
    s.sendto(q,('127.0.0.1',53))
    try: s.recvfrom(4096)
    except Exception: pass
\"" >/dev/null 2>&1
  sleep 4
  local kern_desl diz_desl
  kern_desl=$(vm "nft list set inet linkguard dom_blocked 2>/dev/null | grep -c elements" | tr -d '\r' | head -1)
  # O QUE SE PROCURA É UM SINAL DE "NÃO ESTOU MEDINDO", em qualquer forma.
  #
  # Duas tentativas anteriores erraram o alvo: a primeira varria o JSON atrás
  # das palavras "desligado"/"coletor"/"inativo" — adivinhando como o produto se
  # expressaria; a segunda olhou `State.Ready`, que é prontidão interna do
  # coordenador e não tem relação com o coletor estar alimentando.
  #
  # Medido quando esta asserção nasceu: com o dnstap DESLIGADO a resposta trazia
  # `"ready": true` e zero endereços, sem campo nenhum que separasse "ninguém
  # acessou" de "não estou medindo".
  #
  # Depois disso o produto ganhou a ressalva, e batizou o campo de `observando`.
  # Esta lista, escrita antes, não sabia a palavra — e passou a reprovar
  # justamente o produto que já fazia o que ela cobrava. É a terceira forma de
  # errar o alvo: não adivinhar o comportamento nem olhar o campo errado, mas
  # deixar de acompanhar o vocabulário de quem se está medindo. Uma asserção que
  # reprova o acerto ensina a ignorá-la, que é como uma falha de verdade passa.
  #
  # Medido de novo na VM, com o coletor desligado: `"vivo": true` junto de
  # `"observando": false` — o alimentador de pé, sem observar nada. É essa a
  # distinção que interessa, e o produto a publica.
  #
  # A asserção aceita QUALQUER forma de dizer isso; o que ela reprova é a
  # ausência de todas — porque zero sem ressalva é uma afirmação sobre a rede, e
  # o produto não está em posição de fazê-la.
  diz_desl=$(body GET /api/domain-targets "$tok" | python3 -c "
import json,sys
bruto=sys.stdin.read()
d=json.loads(bruto)
# qualquer sinal serve: um campo booleano de coletor/alimentador, uma razão de
# suspensão, ou um texto que mencione o coletor.
sinais=('dnstap','collector','coletor','feeder','alimentador','not_measuring','nao_medindo',
        'observando','observing')
tem=any(s in bruto.lower() for s in sinais)
r=d.get(\"ready\") if isinstance(d,dict) else None
print(\"avisa\" if tem or r is False else \"cala\")" 2>/dev/null)
  if [[ "${kern_desl:-0}" != "0" ]]; then
    bad "com o dnstap DESLIGADO o produto aprendeu endereço: está medindo o que ninguém mandou medir" \
        "$(vm "nft list set inet linkguard dom_blocked 2>/dev/null" | tr -d '\r' | head -c 160)"
  elif [[ "$diz_desl" == "avisa" ]]; then
    ok "com o dnstap desligado nada é aprendido, e a resposta avisa que não está medindo"
  else
    bad "com o dnstap desligado a resposta não separa 'ninguém acessou' de 'não estou medindo': zero sem ressalva é afirmação sobre a rede" \
        "$(body GET /api/domain-targets "$tok" | head -c 220)"
  fi
  M6=1

  # ── Liga o dnstap e MEDE que o resolver respondeu, antes de cobrar o resto ──
  status PUT /api/dns/config "$tok" '{"upstreams":[],"log_queries":false,"force_local_dns":false,"block_dot":false,"dns_except_ips":[],"dnstap_enabled":true}' >/dev/null 2>&1
  sleep 6
  # O unbound recém-reconfigurado gasta a primeira consulta com priming da raiz
  # e DNSSEC. Sem separar "não respondeu" de "não aprendeu", a bateria acusaria
  # o produto de um problema que é de rede — a lição da bateria T.
  local respondeu
  respondeu=$(vm "python3 -c \"
import socket,struct
q=struct.pack('>HHHHHH',0xd202,0x0100,1,0,0,0)+b'\\x03deb\\x06debian\\x03org\\x00'+struct.pack('>HH',1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(6); n=0
for _ in range(6):
    s.sendto(q,('127.0.0.1',53))
    try:
        s.recvfrom(4096); n+=1
    except Exception: pass
print(n)
\"" | tr -d '\r' | tail -1)
  if [[ "${respondeu:-0}" -le 0 ]]; then
    bad "o unbound não respondeu; sem resposta não há endereço para aprender" \
        "$(vm "journalctl -u unbound --since '2 min ago' --no-pager | tail -3" | tr -d '\r' | head -c 200)"
    encerra_d "o resolver da caixa não respondeu"; return
  fi
  ok "o unbound da caixa respondeu a consulta ($respondeu de 6)"

  # ── D2-1 — O ENSAIO APRENDE, E APRENDE SEM ESCREVER NO KERNEL ─────────────
  #
  # ESTA ASSERÇÃO JÁ ESTEVE ERRADA, E O ERRO ERA MEU. A primeira versão
  # procurava o endereço aprendido dentro do `dom_blocked` enquanto o domínio
  # ainda estava em ensaio — e ensaio, por desenho declarado no próprio código,
  # "aprende os endereços, conta a rotatividade e NÃO escreve uma linha no
  # kernel". A bateria cobrava do produto exatamente o que ele promete não
  # fazer, e a falha que ela imprimia acusava o produto de um acerto.
  #
  # O ensaio tem telemetria própria — last_learned e rotation — e é ali que se
  # prova que o ciclo de aprendizado fechou sem enforcement nenhum.
  local resolvido aprendeu i kernel_ensaio
  resolvido=$(vm "python3 -c \"
import socket
print(sorted({i[4][0] for i in socket.getaddrinfo('$DOM',80,socket.AF_INET)})[0])
\" 2>/dev/null" | tr -d '\r' | tail -1)
  for i in $(seq 1 10); do
    aprendeu=$(body GET /api/domain-targets "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
alvos=d if isinstance(d,list) else (d.get('targets') or d.get('alvos') or [])
for t in alvos:
    if t.get('id')=='$idd':
        print(1 if (t.get('last_learned') or 0) > 0 or (t.get('rotation') or 0) > 0 else 0)" 2>/dev/null | head -1)
    [[ "$aprendeu" == "1" ]] && break
    sleep 3
  done
  kernel_ensaio=$(vm "nft list set inet linkguard dom_blocked 2>/dev/null | grep -c elements" | tr -d '\r' | head -1)
  if [[ "$aprendeu" != "1" ]]; then
    bad "o resolver respondeu e o domínio não registrou aprendizado nenhum: o ciclo não fechou" \
        "$(body GET /api/domain-targets "$tok" | head -c 220)"
    encerra_d "nada foi aprendido"; return
  fi
  if [[ "${kernel_ensaio:-0}" == "0" ]]; then
    ok "em ensaio o produto aprendeu o endereço E não escreveu uma linha no kernel — as duas metades do contrato"
  else
    bad "EM ENSAIO O PRODUTO ESCREVEU NO KERNEL: o estágio que promete só observar já está barrando" \
        "$(vm "nft list set inet linkguard dom_blocked 2>/dev/null" | tr -d '\r' | head -c 160)"
  fi
  M1=1

  # ── D2-2 — A METADE DE SILÊNCIO: em ensaio, NÃO barra ──────────────────────
  local estagio
  estagio=$(body GET /api/domain-targets "$tok" | python3 -c "
import json,sys
d=json.load(sys.stdin)
alvos=d if isinstance(d,list) else (d.get('targets') or d.get('alvos') or [])
for t in alvos:
    if t.get('id')=='$idd': print(t.get('effective_stage') or t.get('stage') or '')" 2>/dev/null | head -1)
  local passou_ensaio
  passou_ensaio=$(vm "ip netns exec lgdom timeout 8 python3 -c \"
import socket
try:
    socket.create_connection(('$resolvido',80),5); print('passou')
except Exception as e: print('bloqueado:%s' % type(e).__name__)
\" 2>/dev/null" | tr -d '\r' | tail -1)
  if [[ "$estagio" != "ensaio" ]]; then
    bad "o domínio não nasceu em ensaio (nasceu '$estagio'): o padrão de fábrica já barra sem ninguém promover"
  elif [[ "$passou_ensaio" == "passou" ]]; then
    ok "em ensaio o domínio NÃO barra: o tráfego do host da LAN passou"
  else
    bad "em ensaio o tráfego já foi bloqueado ('$passou_ensaio'): ou o ensaio não é ensaio, ou outra regra barrou" \
        "sem esta metade, a asserção de bloqueio não prova enforcement"
  fi
  M2=1

  # ── D2-3 — PROMOVIDO, BARRA NO FIO ────────────────────────────────────────
  st=$(status POST "/api/domain-targets/$idd/stage" "$tok" '{"stage":"ativo"}')
  if [[ "$st" != "200" && "$st" != "204" ]]; then
    bad "o painel recusou promover o domínio ($st)"; encerra_d "não foi promovido"; return
  fi
  sleep 4
  # DUAS MEDIÇÕES, PORQUE HÁ DUAS EXPLICAÇÕES COM GRAVIDADES DIFERENTES.
  #
  # Se promover não aplicar o que já foi aprendido, o bloqueio só passa a valer
  # na próxima resposta de DNS — e com o cache do cliente isso pode levar horas.
  # É falha, mas é outra falha, e o conserto é outro. Se nem depois de uma
  # consulta nova o tráfego for barrado, o enforcement não funciona.
  #
  # A primeira medição é logo após promover, sem consulta nova. A segunda é
  # depois de forçar uma resposta de DNS. Separar as duas é o que transforma
  # "não barrou" numa acusação precisa em vez de um dedo apontado.
  local depois
  depois=$(vm "ip netns exec lgdom timeout 8 python3 -c \"
import socket
try:
    socket.create_connection(('$resolvido',80),5); print('passou')
except Exception as e: print('bloqueado:%s' % type(e).__name__)
\" 2>/dev/null" | tr -d '\r' | tail -1)
  if [[ "$depois" == bloqueado:* ]]; then
    ok "promovido, o domínio barra o tráfego do host da LAN no fio, sem precisar de consulta nova ($depois)"
  elif [[ "$depois" != passou ]]; then
    bad "não consegui medir o tráfego depois da promoção" "${depois:-sem saída}"
  else
    # Segunda medição: força uma resposta de DNS nova e mede de novo.
    vm "python3 -c \"
import socket,struct
q=struct.pack('>HHHHHH',0xd203,0x0100,1,0,0,0)+b'\\x03deb\\x06debian\\x03org\\x00'+struct.pack('>HH',1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(6)
for _ in range(3):
    s.sendto(q,('127.0.0.1',53))
    try: s.recvfrom(4096)
    except Exception: pass
\"" >/dev/null 2>&1
    sleep 6
    local apos_consulta no_set
    no_set=$(vm "nft list set inet linkguard dom_blocked 2>/dev/null | grep -c elements" | tr -d '\r' | head -1)
    apos_consulta=$(vm "ip netns exec lgdom timeout 8 python3 -c \"
import socket
try:
    socket.create_connection(('$resolvido',80),5); print('passou')
except Exception as e: print('bloqueado:%s' % type(e).__name__)
\" 2>/dev/null" | tr -d '\r' | tail -1)
    if [[ "$apos_consulta" == bloqueado:* ]]; then
      bad "PROMOVER NÃO APLICA O QUE JÁ FOI APRENDIDO: só barrou depois de uma consulta de DNS nova" \
          "com o cache do cliente, o admin promove e o bloqueio demora — endereços no set após a consulta: ${no_set:-0}"
    else
      bad "O ENFORCEMENT NÃO BARRA: nem depois de promover, nem depois de consulta de DNS nova" \
          "set: ${no_set:-0} elemento(s) | chain: $(vm "nft list chain inet linkguard forward 2>/dev/null | grep dom_blocked" | tr -d '\r' | head -c 140)"
    fi
  fi
  M3=1

  # ── D2-4 — A TELA CONTA DO KERNEL ─────────────────────────────────────────
  local no_kernel na_tela
  no_kernel=$(vm "nft list set inet linkguard dom_blocked 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | sort -u | wc -l" | tr -d '\r' | tail -1)
  na_tela=$(body GET /api/domain-targets "$tok" | python3 -c "
import json,sys,re
d=json.load(sys.stdin)
alvos=d if isinstance(d,list) else (d.get('targets') or d.get('alvos') or [])
for t in alvos:
    if t.get('id')=='$idd':
        for k in ('addresses','enderecos','ip_count','addresses_v4','no_kernel'):
            v=t.get(k)
            if isinstance(v,int): print(v); raise SystemExit
            if isinstance(v,list): print(len(v)); raise SystemExit
print('')" 2>/dev/null | head -1)
  if [[ -z "$na_tela" ]]; then
    pular "D2-4. A tela conta do kernel" "não achei campo de contagem de endereços na resposta da API"
  elif [[ "$na_tela" == "$no_kernel" ]]; then
    ok "a contagem da tela ($na_tela) é a mesma do kernel — ela lê o que existe, não o que lembra"
  else
    bad "a tela diz $na_tela endereço(s) e o kernel tem $no_kernel: a contagem não vem de onde deveria"
  fi
  M4=1

  # ── D2-5 — APAGAR TIRA NA HORA, sem esperar o prazo ───────────────────────
  status DELETE "/api/domain-targets/$idd" "$tok" >/dev/null 2>&1
  idd=""
  local sobrou_apos
  for i in $(seq 1 8); do
    sobrou_apos=$(vm "nft list set inet linkguard dom_blocked 2>/dev/null | grep -c elements" | tr -d '\r' | head -1)
    [[ "${sobrou_apos:-0}" == "0" ]] && break
    sleep 3
  done
  if [[ "${sobrou_apos:-0}" == "0" ]]; then
    ok "apagar o domínio tirou os endereços na hora, sem esperar o prazo de 10 minutos vencer"
  else
    bad "os endereços continuaram no set depois de o domínio ser apagado" \
        "$(vm "nft list set inet linkguard dom_blocked 2>/dev/null" | tr -d '\r' | head -c 160)"
  fi
  M5=1

  limpa_d
}

battery_fresh
battery_upgrade
battery_confirm_revert
battery_policy
battery_capture
battery_quota
battery_accounting
battery_host_quota
battery_replyrouting
battery_dnsleak
battery_mssclamp
battery_schedule
battery_blocklog
battery_ddns
battery_waninput
battery_bloqueio_familias
battery_portforward_wan2
battery_reserva_dhcp
battery_contencao
battery_mapa_dns
battery_alvo_por_dominio
battery_metricas_host
battery_comportamento
battery_vlan_no_balanceamento
battery_fixacao_saida
battery_registro_de_fluxo
battery_fechar_gerencia

head_ "Resumo"
printf '  %d verificações OK, %d falhas\n' "$PASS" "$FAIL"
if [[ ${#PULADAS[@]} -gt 0 ]]; then
  printf '  \033[33m%d bateria(s) NÃO rodaram nesta execução:\033[0m\n' "${#PULADAS[@]}"
  for p in "${PULADAS[@]}"; do printf '    · %s\n' "$p"; done
fi
printf '\n'
[[ "$FAIL" -eq 0 ]] || exit 1
