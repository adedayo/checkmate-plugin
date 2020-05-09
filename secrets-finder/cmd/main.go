package main

import (
	model "github.com/adedayo/checkmate-plugin/pkg"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
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
