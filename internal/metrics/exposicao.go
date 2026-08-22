package metrics

// O que pode e o que não pode sair pelo /metrics.
//
// ESTE ARQUIVO É UMA DECISÃO, NÃO UM UTILITÁRIO, e existe porque três issues
// abertas (#115, #117, #118) tocam a MESMA classe de dado por três caminhos
// diferentes, e cada uma sozinha passaria em revisão:
//
//   - a #115 trata "quem é este aparelho e o que ele fez" como dado sensível:
//     propõe permissão RBAC própria, retenção configurável e auditoria em toda
//     consulta;
//   - a #118 propõe publicar o mesmo par (endereço físico, bytes) no /metrics,
//     que está registrado FORA do grupo autenticado (internal/api/server.go) e
//     que a própria suíte de validação exige que responda pela WAN;
//   - a #117 manda o mesmo par para FORA da caixa: o alerta nomeia o aparelho e
//     o apelido, e o padrão de severidade mínima das notificações é "warning" —
//     ou seja, sairia por Telegram/e-mail sem ninguém ter decidido isso.
//
// Juntas, elas deixariam o produto exigindo uma permissão nova para VER na tela
// exatamente o dado que ele já estaria publicando sem autenticação e empurrando
// para o telefone do admin. Ninguém perceberia, porque não há arquivo em comum
// entre as três.
//
// A REGRA, escrita uma vez, para as três herdarem:
//
//  1. IDENTIDADE DE APARELHO — endereço físico, apelido, nome de host, endereço
//     IP de host da LAN — é dado de inventário da rede do cliente. Ela NÃO sai
//     por canal não autenticado. O /metrics de hoje é não autenticado, logo
//     nenhuma série com rótulo de aparelho entra nele enquanto for assim.
//
//  2. AGREGADO NÃO É IDENTIDADE. Contagem de links, de alertas, tempo de
//     atividade, bytes por INTERFACE — nada disso diz quem é ninguém, e continua
//     saindo pelo /metrics como sempre saiu.
//
//  3. Série por aparelho é opt-in, desligada por padrão, e só existe atrás de
//     autenticação. Enquanto o /metrics for aberto, ela sai por outra rota.
//
//  4. Notificação que nomeia aparelho é escolha explícita de quem configura,
//     nunca padrão herdado da severidade.
//
// Se um dia o /metrics passar a exigir token, o item 1 muda de lugar — mas a
// decisão de que a mudança é DELIBERADA, e não efeito colateral de uma issue de
// métrica, é o que este arquivo preserva.

// SerieDeAparelho diz se uma série carrega identidade de aparelho e, portanto,
// não pode sair pelo /metrics não autenticado.
//
// Existe como função, e não como comentário, para que acrescentar uma série com
// rótulo de aparelho tenha de passar por aqui — e para que o teste possa afirmar
// que nenhuma delas está registrada no coletor aberto.
func SerieDeAparelho(nome string) bool {
	for _, p := range prefixosDeAparelho {
		if len(nome) >= len(p) && nome[:len(p)] == p {
			return true
		}
	}
	return false
}

// prefixosDeAparelho são os nomes de série que carregam identidade. A lista é
// curta de propósito: o que não está aqui é agregado, e agregado não identifica.
var prefixosDeAparelho = []string{
	"linkguard_host_",
	"linkguard_device_",
	"linkguard_client_",
}
