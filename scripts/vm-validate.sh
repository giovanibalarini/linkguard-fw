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
  [[ -n "$FROM_DEB" ]] || return 0
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
  # Só faz sentido se o papel tem a permissão para revogar.
  local before after
  before=$(role_perms "$tok" "$op_role")
  if grep -qx 'monitoring.write' <<<"$before"; then
    body PUT "/api/roles/$op_role" "$tok" '{"name":"Operador VM","description":"operacional","permissions":["monitoring.read","firewall.write"]}' >/dev/null
    vm "systemctl restart linkguard-fw" >/dev/null 2>&1
    wait_api || { bad "o serviço não voltou depois do restart"; return; }
    tok=$(login admin "$basepw")
    after=$(role_perms "$tok" "$op_role")
    if grep -qx 'monitoring.write' <<<"$after"; then
      bad "o reboot devolveu uma permissão que o admin tinha revogado"
    else ok "revogação do admin sobrevive ao restart (a migração não roda de novo)"; fi
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
  st=$(status PUT "/api/quotas/$link" "$tok" '{"limit_gb":1,"cycle_day":31,"alert_pct":80,"enabled":true}')
  if [[ "$st" == "400" ]]; then ok "dia de fechamento 31 recusado (400)"
  else bad "dia 31 aceito ($st) — o ciclo sumiria em fevereiro"; fi

  # F3 — percentual de aviso fora da faixa.
  st=$(status PUT "/api/quotas/$link" "$tok" '{"limit_gb":1,"cycle_day":10,"alert_pct":150,"enabled":true}')
  if [[ "$st" == "400" ]]; then ok "aviso em 150% recusado (400)"
  else bad "percentual fora da faixa aceito ($st)"; fi

  # F4 — franquia válida, e o ciclo calculado.
  st=$(status PUT "/api/quotas/$link" "$tok" '{"limit_gb":1,"cycle_day":28,"alert_pct":80,"enabled":true}')
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
  printf '       (aguardando os fluxos saírem do conntrack)\n'
  sleep 45
  local vivos
  # `grep -c` imprime 0 E sai com código 1 quando não acha; o `|| echo 0`
  # acrescentava um segundo zero e a variável virava "0\n0".
  vivos=$(vm "grep -c 192.168.3.200 /proc/net/nf_conntrack 2>/dev/null; true" | tr -d '\r' | head -1)
  local depois
  depois=$(vm "nft list set inet linkguard acct_up 2>/dev/null" | grep -oE '192\.168\.3\.200 counter packets [0-9]+ bytes [0-9]+' | grep -oE 'bytes [0-9]+' | grep -oE '[0-9]+')
  if [[ "$vivos" == "0" ]]; then ok "os fluxos do host saíram do conntrack (a fonte antiga diria zero)"
  else printf '       (ainda há %s fluxo(s) no conntrack; a asserção seguinte vale do mesmo jeito)\n' "$vivos"; fi
  if [[ "$depois" == "14280" ]]; then ok "o consumo sobreviveu ao fim dos fluxos — é o defeito da #112, corrigido"
  else bad "o consumo mudou depois de os fluxos morrerem: ${depois:-vazio}"; fi

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

battery_fresh
battery_upgrade
battery_confirm_revert
battery_policy
battery_capture
battery_quota
battery_accounting
battery_replyrouting

head_ "Resumo"
printf '  %d verificações OK, %d falhas\n\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
