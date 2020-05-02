package secrets

import (
	checkmate "github.com/adedayo/checkmate-plugin/proto"
	model "github.com/adedayo/checkmate-plugin/shared"
)

// FinderPlugin is the plugin interface to the CheckMate Secret Finder module
type FinderPlugin struct {
	model.CheckMatePluginInterface
}

func (sfp *FinderPlugin) GetPluginMetadata() (*checkmate.PluginMetadata, error) {
	return &checkmate.PluginMetadata{
		Description: "CheckMate's secrets-in-code detection plugin",
		Name:        "Secrets Finder",
	}, nil
}
