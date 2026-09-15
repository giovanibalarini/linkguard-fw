package nftables

// zonaOnPrem é a zona de uma caixa de VÁRIAS interfaces — a topologia que todo
// teste deste pacote sempre assumiu, e a única que existia antes das zonas.
// Renderiza por interface, que é a forma byte a byte da produção.
//
// Existe para que a troca do eixo não vire uma reescrita de asserção: os testes
// abaixo continuam afirmando exatamente o que afirmavam, sobre a mesma saída.
func zonaOnPrem(wanIfaces ...string) Zone {
	return NewZone(wanIfaces, nil, false, 0)
}

// zonaHairpin é a caixa de VNIC única: entra e sai pela mesma interface, e o
// eixo passa a ser o CIDR de dentro.
func zonaHairpin(localNets []string, wanIfaces ...string) Zone {
	return NewZone(wanIfaces, localNets, true, 0)
}

// zonaHairpinComMTU é a mesma caixa, com a MTU do CAMINHO externo conhecida —
// o que a plataforma afirma numa nuvem, e não o que a placa anuncia. Separada
// de zonaHairpin porque "não sei a MTU" é o estado de toda VM anterior a esta
// entrega, e os testes que não falam de MSS têm de continuar nele.
func zonaHairpinComMTU(pathMTU int, localNets []string, wanIfaces ...string) Zone {
	return NewZone(wanIfaces, localNets, true, pathMTU)
}

// zonaDasMarcasDe é a zona das chains que derivam de WANMark — conn_mark,
// conn_mark_out e mark_hosts. A lista de interfaces sai ORDENADA, que é a
// forma que essas chains têm em produção.
func zonaDasMarcasDe(wans []WANMark) Zone {
	return NewZone(wanMarkIfaces(wans), nil, false, 0)
}

// connMarkChainRulesDe e connMarkOutChainRulesDe montam a zona a partir das
// próprias marcas, que é o que EnsureConnMark faz. Existem para que os testes
// de conn_mark continuem falando de marcas, e não de zonas.
func connMarkChainRulesDe(wans []WANMark) [][]string {
	return connMarkChainRules(zonaDasMarcasDe(wans), wans)
}

func connMarkOutChainRulesDe(wans []WANMark) [][]string {
	return connMarkOutChainRules(zonaDasMarcasDe(wans), wans)
}
