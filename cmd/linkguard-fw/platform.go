package main

import (
	"context"
	"log/slog"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/platform"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// detectPlatformOnBoot descobre em que máquina o produto está e NUNCA derruba
// o boot: uma falha aqui devolve o instantâneo permissivo, que é exatamente o
// comportamento de hoje.
//
// Roda DEPOIS de openStore, porque o resultado é gravado na tabela settings, e
// ANTES de buildServices, porque é dali para baixo que todo o resto vai
// derivar. Não pode descer para provisionSystem: aquela função só é chamada
// depois de bootstrapdeps.Ensure, que num link ruim leva meia hora — nada que
// os outros serviços consultem pode nascer ali.
//
// Na caixa on-prem isto custa quatro leituras de arquivo e nenhum socket: sem
// sinal local de nuvem aceso, a detecção nem chega a tentar a rede. Ver
// internal/platform.
func detectPlatformOnBoot(db *storage.DB) platform.Snapshot {
	ctx, cancel := context.WithTimeout(context.Background(), platform.DetectBudget)
	defer cancel()

	snap, err := platform.NewDetector(db).Detect(ctx)
	if err != nil {
		slog.Warn("não foi possível detectar a plataforma; seguindo como máquina genérica", "err", err)
		return platform.UnknownSnapshot()
	}

	slog.Info("plataforma detectada",
		"plataforma", string(snap.Facts.Kind),
		"confianca", string(snap.Facts.Confidence),
		"sinais", strings.Join(snap.Facts.Signals, ","),
		"multi_wan", snap.Capabilities.MultiWAN,
		"origem", snap.Source)

	return snap
}
