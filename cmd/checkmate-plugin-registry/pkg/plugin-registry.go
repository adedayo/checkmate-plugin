package host

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	plug "github.com/adedayo/checkmate-plugin/pkg"
	pb "github.com/adedayo/checkmate-plugin/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
)

var (
	handshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   plug.MagicCookie,
		MagicCookieValue: plug.MagicCookieValue,
	}
	pluginGlobs = []string{"*checkmate-plugin*"}
	registry    = make(map[string]*pb.PluginMetadata)

	logger = hclog.New(&hclog.LoggerOptions{
		Name:   "plugin-registry",
		Output: os.Stdout,
		Level:  hclog.Error,
	})
)

//GetPluginClient retrieves a plugin from the registry (if previously found), or searches for it
//on the optionally-specified search paths (updating the registry with any plugin found in the process)
func GetPluginClient(pluginID string, searchPaths ...string) (*plug.CheckMatePluginClient, *plugin.Client, error) {
	var pl *plug.CheckMatePluginClient
	var client *plugin.Client
	var metadata *pb.PluginMetadata
	foundMeta := false
	if meta, present := registry[pluginID]; present {
		metadata = meta
		foundMeta = true
	} else {
		updateRegistry(searchPaths)
		if meta, present := registry[pluginID]; present {
			metadata = meta
			foundMeta = true
		}
	}

	if foundMeta {
		pluginID := metadata.GetId()

		newClient := plugin.NewClient(&plugin.ClientConfig{
			HandshakeConfig: plugin.HandshakeConfig{
				ProtocolVersion:  1,
				MagicCookieKey:   plug.MagicCookie,
				MagicCookieValue: plug.MagicCookieValue,
			},
			Plugins: map[string]plugin.Plugin{
				pluginID: &plug.CheckMatePluginContainer{},
			},
			Cmd:              exec.Command(metadata.Path),
			AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		})
		rpcClient, err := newClient.Client()
		if err != nil {
			return pl, client, err
		}

		raw, err := rpcClient.Dispense(pluginID)
		if err != nil {
			return pl, client, err
		}

		if plugin, ok := raw.(*plug.CheckMatePluginClient); ok {

			return plugin, newClient, nil
		}
	}
	return pl, client, fmt.Errorf("Could not find CheckMate plugin with ID: %s", pluginID)
}

//GetAllPluginMetadata returns plugin metadata found on the supplied paths
//and updates the registry with any plugin found during the search
func GetAllPluginMetadata(paths []string) []*pb.PluginMetadata {

	updateRegistry(paths)
	meta := []*pb.PluginMetadata{}
	for _, v := range registry {
		meta = append(meta, v)
	}
	sort.Sort(byName(meta))
	return meta
}

type byName []*pb.PluginMetadata

func (a byName) Len() int           { return len(a) }
func (a byName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byName) Less(i, j int) bool { return a[i].Name < a[j].Name }

func updateRegistry(paths []string) {
	for _, path := range discoverPlugins(pluginGlobs, paths) {
		if _, present := registry[path]; !present {
			pluginID := getID(path)
			client := plugin.NewClient(&plugin.ClientConfig{
				HandshakeConfig: handshakeConfig,
				Logger:          logger,
				Plugins: map[string]plugin.Plugin{
					pluginID: &plug.CheckMatePluginContainer{},
				},
				Cmd:              exec.Command(path),
				AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
			})

			rpcClient, err := client.Client()
			if err != nil {
				fmt.Println("Error:", err.Error())
				continue
			}

			raw, err := rpcClient.Dispense(pluginID)
			if err != nil {
				fmt.Println("Error:", err.Error())
				continue
			}

			pl := raw.(*plug.CheckMatePluginClient)
			meta, err := pl.GetPluginMetadata()
			if err != nil {
				fmt.Println("Error:", err.Error())
				continue
			}
			meta.Path = path
			fmt.Printf("Adding meta %s %#v\n", pluginID, meta)
			registry[pluginID] = meta
			client.Kill()
		}
	}
}

//getID returns the plugin ID used to serve the plugin as a convention
// of the form pluginID_version_checkmate-plugin
func getID(path string) string {
	return strings.Split(filepath.Base(path), "_")[0]
}
