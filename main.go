package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	plug "github.com/adedayo/checkmate-plugin/shared"
	"github.com/hashicorp/go-plugin"
)

func main() {

	log.SetOutput(ioutil.Discard)

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   plug.MagicCookie,
			MagicCookieValue: plug.MagicCookieValue,
		},
		Plugins: map[string]plugin.Plugin{
			"secret-finder": &plug.CheckMatePlugin{},
		},
		Cmd:              exec.Command("./build/secrets-finder-checkmate-plugin"),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
	})

	defer client.Kill()

	rpcClient, err := client.Client()
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	raw, err := rpcClient.Dispense("secret-finder")
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	pl := raw.(plug.CheckMatePluginInterface)
	meta, err := pl.GetPluginMetadata()
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	fmt.Printf("\n\n=========Metadata %#v\n\n================", meta)
}
