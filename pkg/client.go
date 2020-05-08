package model

import (
	"context"

	checkmate "github.com/adedayo/checkmate-plugin/proto"
)

// CheckMatePluginClient client
type CheckMatePluginClient struct {
	client checkmate.PluginServiceClient
}

//GetPluginMetadata returns the plugin metadata
func (c *CheckMatePluginClient) GetPluginMetadata() (*checkmate.PluginMetadata, error) {
	return c.client.GetPluginMetadata(context.Background(), &checkmate.Empty{})
}
