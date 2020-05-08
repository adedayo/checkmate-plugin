package model

import (
	"context"

	checkmate "github.com/adedayo/checkmate-plugin/proto"
)

//CheckMatePluginServer is the gRPC server that the client talks to
type CheckMatePluginServer struct {
	Impl CheckMatePluginInterface
}

//GetPluginMetadata returns the plugin metadata
func (s *CheckMatePluginServer) GetPluginMetadata(
	ctx context.Context,
	req *checkmate.Empty) (*checkmate.PluginMetadata, error) {
	return s.Impl.GetPluginMetadata()
}
