package auth

import "testing"

// TestRegistroDeConversaNaoEntraEmPapelDeFabricaAlemDoAdmin prende o defeito de
// privacidade da #115: a permissão de ver COM QUEM cada aparelho falou aparecer
// num papel que já existe.
//
// O estrago não é hipotético e não precisa de ninguém agir: no dia do upgrade,
// todo usuário que já tem o papel de operador (ou o de visualizador) passaria a
// ler o histórico de destinos de cada aparelho da rede — numa PME, o histórico
// de navegação de cada funcionário — sem nenhuma pessoa ter decidido isso. Foi
// exatamente assim que traffic.capture entrou no papel de operador.
//
// Administrador é a exceção legítima: aquele papel é "acesso total" por
// definição, e um administrador que não quiser isso remove a permissão.
func TestRegistroDeConversaNaoEntraEmPapelDeFabricaAlemDoAdmin(t *testing.T) {
	for _, papel := range DefaultRoles {
		if papel.ID == "role-admin" {
			continue
		}
		for _, p := range papel.Permissions {
			if p == PermTrafficFlows {
				t.Errorf("o papel de fábrica %q nasceu podendo ver com quem os aparelhos falaram", papel.Name)
			}
		}
	}
}

// TestRegistroDeConversaEstaNoCatalogo garante que a permissão é ATRIBUÍVEL. Uma
// chave exigida por uma rota mas ausente do catálogo é uma tela que ninguém
// consegue liberar: IsValidPermission recusa a chave na hora de montar o papel,
// e o administrador fica olhando um 403 sem nada para clicar.
func TestRegistroDeConversaEstaNoCatalogo(t *testing.T) {
	if !IsValidPermission(string(PermTrafficFlows)) {
		t.Fatal("a permissão do registro de conversa não está no catálogo")
	}
}
