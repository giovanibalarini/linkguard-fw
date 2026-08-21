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
  if vm "grep -q '192.168.3.153' /etc/kea/kea-dhcp4.conf 2>/dev/null" && echo ok | grep -q ok; then
    ok "a reserva boa chegou na config do Kea"
  else bad "a reserva IPv4 não foi aplicada" "$(vm "grep -c reservations /etc/kea/kea-dhcp4.conf 2>/dev/null" | tr -d '\r')"; fi

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
  atual=$(body GET /api/dhcp/config "$tok")
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

  # S1 — o set existe e a regra que a alimenta está na chain, escopada por WAN.
  local chain
  chain=$(vm "nft list chain inet linkguard input 2>/dev/null" | tr -d '\r')
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
  # Se viesse depois, o accept curto-circuitaria e a contenção não valeria nada.
  local i_drop i_accept
  i_drop=$(grep -n 'ip saddr @abusers' <<<"$chain" | head -1 | cut -d: -f1)
  i_accept=$(grep -n 'tcp dport {.*} counter accept' <<<"$chain" | head -1 | cut -d: -f1)
  if [[ -n "$i_drop" && -n "$i_accept" && "$i_drop" -lt "$i_accept" ]]; then
    ok "o descarte de contido vem antes da liberação de gerência ($i_drop < $i_accept)"
  else bad "a ordem está errada (descarte $i_drop, liberação $i_accept): o accept curto-circuita a contenção"; fi

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

  local lid
  lid=$(body GET /api/links "$tok" | python3 -c "
import json,sys
for l in json.load(sys.stdin):
    if l['interface']=='lg-abus': print(l['id'])" 2>/dev/null)
  [[ -n "$lid" ]] && status DELETE "/api/links/$lid" "$tok" >/dev/null 2>&1
  vm "ip netns del lgabus 2>/dev/null; ip link del lg-abus 2>/dev/null; true" >/dev/null 2>&1
}

battery_fresh
battery_upgrade
battery_confirm_revert
battery_policy
battery_capture
battery_quota
battery_accounting
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
battery_fechar_gerencia

head_ "Resumo"
printf '  %d verificações OK, %d falhas\n\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
