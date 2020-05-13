package main

import (
	"os"

	model "github.com/adedayo/checkmate-plugin/pkg"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
)

func main() {
	pluginID := "secrets-finder"
	plugin.Serve(
		&plugin.ServeConfig{
			HandshakeConfig: plugin.HandshakeConfig{
				ProtocolVersion:  1,
				MagicCookieKey:   model.MagicCookie,
				MagicCookieValue: model.MagicCookieValue,
			},
			Plugins: map[string]plugin.Plugin{
				pluginID: &model.CheckMatePluginContainer{Impl: &secrets.FinderPlugin{}},
			},
			GRPCServer: plugin.DefaultGRPCServer,
			Logger: hclog.New(&hclog.LoggerOptions{
				Name:   pluginID,
				Output: os.Stdout,
				Level:  hclog.Error,
			}),
		},
	)
}
