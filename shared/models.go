package model

import (
	"context"

	checkmate "github.com/adedayo/checkmate-plugin/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

var (
	//MagicCookie is a global plugin cookie to be used by all CheckMate plugins
	MagicCookie = "CheckMate_Plugin_Cookie"
	//MagicCookieValue is a global plugin cookie to be used by all CheckMate plugins
	MagicCookieValue = "7ac3958e-8bbc-11ea-9455-5bcc09dc1c7d"
)

// CheckMatePluginInterface is the interface that all plugins must implement
type CheckMatePluginInterface interface {
	//GetPluginMetadata returns meta data description of the plugin
	GetPluginMetadata() (*checkmate.PluginMetadata, error)
}

// CheckMatePlugin is plugin.Plugin implementation
type CheckMatePlugin struct {
	plugin.Plugin
	Impl CheckMatePluginInterface
}

// GRPCServer registers this plugin for serving with the
// given GRPCServer. Unlike Plugin.Server, this is only called once
// since gRPC plugins serve singletons.
func (p *CheckMatePlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	checkmate.RegisterPluginServiceServer(s, &CheckMatePluginServer{Impl: p.Impl})
	return nil
}

// GRPCClient returns the interface implementation for the plugin
// you're serving via gRPC. The provided context will be canceled by
// go-plugin in the event of the plugin process exiting.
func (p *CheckMatePlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &CheckMatePluginClient{client: checkmate.NewPluginServiceClient(c)}, nil
}
