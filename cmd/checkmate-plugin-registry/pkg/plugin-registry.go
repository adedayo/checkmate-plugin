package host

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	plug "github.com/adedayo/checkmate-plugin/pkg"
	checkmate "github.com/adedayo/checkmate-plugin/proto"
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
	registry    = make(map[string]*checkmate.PluginMetadata)

	logger = hclog.New(&hclog.LoggerOptions{
		Name:   "plugin-registry",
		Output: os.Stdout,
		Level:  hclog.Error,
	})
)

//GetAllPluginMetadata returns plugin metadata found on the supplied paths
func GetAllPluginMetadata(paths []string) []*checkmate.PluginMetadata {

	updateRegistry(paths)
	meta := []*checkmate.PluginMetadata{}
	for _, v := range registry {
		meta = append(meta, v)
	}
	sort.Sort(byName(meta))
	return meta
}

type byName []*checkmate.PluginMetadata

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
					pluginID: &plug.CheckMatePlugin{},
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

			pl := raw.(plug.CheckMatePluginInterface)
			meta, err := pl.GetPluginMetadata()
			if err != nil {
				fmt.Println("Error:", err.Error())
				continue
			}
			registry[path] = meta
			client.Kill()

		}
	}
}

//getID returns the plugin ID used to serve the plugin as a convention
// of the form pluginID_version_checkmate-plugin
func getID(path string) string {
	return strings.Split(path, "_")[0]
}
