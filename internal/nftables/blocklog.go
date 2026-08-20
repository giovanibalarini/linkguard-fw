package nftables

// Registro do que o firewall bloqueia (issue #122).
//
// O QUE FALTAVA. As regras de bloqueio já carregam `counter`, e o painel já
// mostra quantos pacotes cada uma descartou. O contador diz QUANTOS; não diz
// QUAIS. A pergunta mais comum de quem opera firewall — "por que isso não
// passa?" — continuava sem resposta na tela: o admin via o número subir e não
// tinha como saber se o que caiu era o acesso que ele está tentando liberar ou
// tráfego de outra coisa. Voltava para o SSH, e normalmente para tentativa e
// erro.
//
// DESLIGADO POR PADRÃO. Registrar todo descarte custa I/O no mesmo disco que
// guarda o banco, e numa varredura o volume é grande. É opção do admin, e a
// tela diz o que ela custa antes de ligar.
//
// O LIMITE DE TAXA É O DETALHE QUE DECIDE A CORREÇÃO — ver o comentário de
// comLog, em groups.go: ele vai na regra de LOG, nunca na de drop.
const (
	// BlockLogPrefixHost marca o descarte por host bloqueado; BlockLogPrefixDest,
	// o descarte por destino na blocklist. O prefixo é o que permite separar os
	// dois na leitura, e o "lg:" evita confundir com log de outro subsistema no
	// mesmo journal.
	//
	// O espaço final é de propósito: o kernel emenda o prefixo com "IN=..." sem
	// separador, e sem ele a primeira chave sairia grudada no prefixo.
	BlockLogPrefixHost = "lg:blk:host "
	BlockLogPrefixDest = "lg:blk:dest "

	// blockLogRate é quanto o kernel registra, no máximo. Sem limite, uma
	// varredura de portas enche o disco em minutos — e a primeira vítima é o
	// journal da própria máquina, que é onde se lê tudo o mais.
	blockLogRate = "10/second"
)

// BlockLogPrefixes são todos os prefixos que este produto escreve, para quem
// lê o journal saber o que procurar sem repetir as constantes.
func BlockLogPrefixes() []string {
	return []string{BlockLogPrefixHost, BlockLogPrefixDest}
}
