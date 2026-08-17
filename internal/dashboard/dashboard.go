// Package dashboard é o catálogo de widgets do painel, o layout de fábrica e as
// regras que decidem o que dá para desenhar. É FOLHA de propósito: não importa
// nenhum pacote interno, e é por isso que ele pode morar longe da persistência.
//
// Estava tudo em internal/storage, que é a folha que todo mundo importa e por
// isso virava depósito: adicionar um widget exigia mexer no arquivo que também
// contém o schema do firewall, e a permissão de um widget ficava a 2.000 linhas
// do catálogo de RBAC com que ela precisa casar.
package dashboard

// ─── Layout do painel (Fase B, spec §4.1 e §6) ──────────────────────────────

// GridColumns é a largura da grade do painel. O mesmo número vale no
// frontend: um item só existe entre a coluna 0 e esta.
const GridColumns = 12

// MaxItems limita quantos itens um layout pode ter. É teto de sanidade,
// não regra de produto: o catálogo tem menos de dez widgets, e o único jeito de
// chegar perto disto é um cliente defeituoso (ou mal-intencionado) mandando uma
// lista sem fim para a gente gravar e reler a cada abertura de painel.
const MaxItems = 64

// MaxRowSpan limita a altura de um item, pelo mesmo motivo.
const MaxRowSpan = 24

// LayoutItem é um widget posicionado na grade do painel. É a MESMA forma no Go
// e no TypeScript, serializada em minúsculas — o frontend manda de volta o que
// leu, sem tradução de campo pelo caminho.
type LayoutItem struct {
	Widget string `json:"widget"`
	X      int    `json:"x"`
	Y      int    `json:"y"`
	W      int    `json:"w"`
	H      int    `json:"h"`
}

// Widget é uma entrada do catálogo: o nome estável que o layout grava
// e a permissão que o usuário precisa ter para ver aquele widget.
//
// Nunca renomeie um Name já publicado: o nome é o que está gravado no painel de
// quem já montou o dele, e trocá-lo faria o widget ser descartado na leitura —
// o painel do operador abriria sem ele, sem nenhuma mensagem.
type Widget struct {
	Name       string
	Permission string
}

// Catalog é o catálogo de widgets do painel (spec §5). A permissão de
// cada um é a MESMA que já protege a rota de onde ele tira o dado — é isso que
// impede o painel de oferecer um widget que só saberia mostrar um 403.
//
// "Alertas abertos" exige monitoring.read, e não um "alerts.read" que a spec
// menciona mas que não existe no catálogo do RBAC (internal/auth/permissions.go):
// GET /api/alerts é gated por monitoring.read hoje. Inventar a chave aqui não
// daria erro em lugar nenhum — ela simplesmente nunca casaria com a permissão de
// ninguém, e o widget sumiria do painel de todos os usuários para sempre.
// TestEveryWidgetPermissionExistsInTheRBACCatalog guarda essa fronteira.
//
// Os dois últimos não exigem nada: "Primeiros passos" é o estado de onboarding
// do próprio painel e "O que você quer fazer" é estático.
var Catalog = []Widget{
	{Name: "system_health", Permission: "monitoring.read"},
	{Name: "wan_links", Permission: "links.read"},
	{Name: "interface_traffic", Permission: "monitoring.read"},
	{Name: "top_talkers", Permission: "hosts.read"},
	{Name: "open_alerts", Permission: "monitoring.read"},
	{Name: "system_resources", Permission: "monitoring.read"},
	{Name: "lan_hosts", Permission: "hosts.read"},
	{Name: "onboarding", Permission: ""},
	{Name: "quick_actions", Permission: ""},
}

// IsKnown informa se o nome existe no catálogo.
func IsKnown(name string) bool {
	for _, w := range Catalog {
		if w.Name == name {
			return true
		}
	}
	return false
}

// Permission devolve a permissão exigida por um widget (vazia
// quando ele não exige nenhuma) e se o widget existe.
func Permission(name string) (string, bool) {
	for _, w := range Catalog {
		if w.Name == name {
			return w.Permission, true
		}
	}
	return "", false
}

// Default é o painel de fábrica: saúde, WANs e alertas na
// primeira dobra; tráfego, consumo e recursos abaixo (spec §5).
//
// "Primeiros passos" NÃO está aqui de propósito. Ele é justamente o que motivou
// esta entrega: parado em 5 de 6 há meses por causa do usuário padrão, ocupando
// os primeiros 60% da tela de uma máquina que roda há meses. Quem instalou
// agora vê o onboarding porque o painel o acrescenta enquanto os 6 passos não
// terminam (spec §4.5), não porque o layout de fábrica o carregue para sempre.
//
// Devolve uma cópia nova a cada chamada: quem chama pode ordenar, cortar e
// arrastar o resultado sem alterar o padrão de todo mundo.
func Default() []LayoutItem {
	return []LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 4, H: 2},
		{Widget: "wan_links", X: 4, Y: 0, W: 4, H: 2},
		{Widget: "open_alerts", X: 8, Y: 0, W: 4, H: 2},
		{Widget: "interface_traffic", X: 0, Y: 2, W: 8, H: 3},
		{Widget: "top_talkers", X: 8, Y: 2, W: 4, H: 3},
		{Widget: "system_resources", X: 0, Y: 5, W: 12, H: 2},
	}
}

// Sanitize descarta ITEM A ITEM o que não dá para desenhar: nome
// de widget que não existe (versão anterior, widget removido do produto) e
// geometria fora da grade. Nunca devolve erro e nunca rejeita o layout inteiro
// — o operador que perdesse o painel todo por causa de uma linha ruim no banco
// não teria como se recuperar pela própria tela (spec §6).
func Sanitize(items []LayoutItem) []LayoutItem {
	out := make([]LayoutItem, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, it := range items {
		if len(out) >= MaxItems {
			break
		}
		if !IsKnown(it.Widget) {
			continue
		}
		// O mesmo widget duas vezes no painel seria duas cópias disputando o
		// mesmo dado e a mesma alça de arrasto. A segunda cai fora.
		if seen[it.Widget] {
			continue
		}
		if it.X < 0 || it.Y < 0 || it.W < 1 || it.H < 1 {
			continue
		}
		if it.X+it.W > GridColumns || it.H > MaxRowSpan {
			continue
		}
		seen[it.Widget] = true
		out = append(out, it)
	}
	return out
}
