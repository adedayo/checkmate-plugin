package secrets

import (
	model "github.com/adedayo/checkmate-plugin/pkg"
	checkmate "github.com/adedayo/checkmate-plugin/proto"
)

// FinderPlugin is the plugin interface to the CheckMate Secret Finder module
type FinderPlugin struct {
	model.CheckMatePluginInterface
}

//GetPluginMetadata returns the plugin metadata
func (sfp *FinderPlugin) GetPluginMetadata() (*checkmate.PluginMetadata, error) {
	return &checkmate.PluginMetadata{
		Description: "CheckMate's secrets-in-code detection plugin",
		Name:        "Secrets Finder",
	}, nil
}
