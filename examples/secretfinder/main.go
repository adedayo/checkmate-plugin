package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	host "github.com/adedayo/checkmate-plugin/cmd/checkmate-plugin-registry/pkg"
	pb "github.com/adedayo/checkmate-plugin/proto"
)

func main() {
	log.SetOutput(ioutil.Discard)

	plugin, client, err := host.GetPluginClient("secrets-finder", "build")
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}
	defer client.Kill()

	meta, err := plugin.GetPluginMetadata()
	fmt.Printf("\n\n=========Metadata %#v\n\n================", meta)

	stream, err := plugin.Scan(&pb.ScanRequest{
		ScanType:    pb.ScanType_PATH_SCAN,
		PathsToScan: []string{"."},
		ShowSource:  true,
		Excludes:    &pb.ExcludeDefinition{},
	})
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}
	for {
		diagnostic, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("Error:", err.Error())
			os.Exit(1)
		}

		fmt.Printf("Diagnostic %s\n", diagnostic.GetJustification().GetHeadline().GetConfidence().String())
	}
}
