package main

import (
	secrets "github.com/adedayo/checkmate-plugin/cmd/plugins/secrets-finder/pkg"
	model "github.com/adedayo/checkmate-plugin/shared"
	"github.com/hashicorp/go-plugin"
)

func main() {
	plugin.Serve(
		&plugin.ServeConfig{
			HandshakeConfig: plugin.HandshakeConfig{
				ProtocolVersion:  1,
				MagicCookieKey:   model.MagicCookie,
				MagicCookieValue: model.MagicCookieValue,
			},
			Plugins: map[string]plugin.Plugin{
				"secrets-finder": &model.CheckMatePlugin{Impl: &secrets.FinderPlugin{}},
			},
			GRPCServer: plugin.DefaultGRPCServer,
		},
	)
}
