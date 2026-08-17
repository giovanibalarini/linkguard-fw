package storage

// ─── helpers ─────────────────────────────────────────────────────────────────
//
// Este arquivo é o único do pacote sem dono de domínio. Ele existe porque
// boolToInt é usado por sete domínios diferentes (links, alerts, failover
// events, RBAC, hosts, políticas de roteamento e firewall) e portanto não
// pertence a nenhum deles: colocá-lo em repo_links.go só faria os outros seis
// arquivos dependerem de um arquivo cujo nome não diz nada sobre eles.
//
// A regra para entrar aqui é essa mesma: mais de um domínio usa, nenhum é dono.
// Helper de um domínio só mora no arquivo do domínio.

// boolToInt converte um bool Go no 0/1 que o SQLite guarda — o schema não tem
// tipo booleano, então toda coluna de flag é INTEGER.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
