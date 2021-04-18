package secrets

import (
	"os"

	diagnostics "github.com/adedayo/checkmate-core/pkg/diagnostics"
	model "github.com/adedayo/checkmate-plugin/pkg"
	pb "github.com/adedayo/checkmate-plugin/proto"
)

// FinderPlugin is the plugin interface to the CheckMate Secret Finder module
type FinderPlugin struct {
	model.CheckMatePluginInterface
}

//GetPluginMetadata returns the plugin metadata
func (sfp *FinderPlugin) GetPluginMetadata() (*pb.PluginMetadata, error) {
	var path string
	if exe, err := os.Executable(); err == nil {
		path = exe
	}
	return &pb.PluginMetadata{
		Description: "CheckMate's secrets-in-code detection plugin",
		Name:        "Secrets Finder",
		Id:          "secrets-finder",
		Path:        path,
	}, nil
}

//Scan runs the static analysis scan to find secrets in code and configuration files
func (sfp *FinderPlugin) Scan(req *pb.ScanRequest, stream pb.PluginService_ScanServer) error {

	wl, err := diagnostics.CompileExcludes(model.ConvertExcludeDefinition(req.Excludes))
	if err != nil {
		return err
	}
	diags, paths := SearchSecretsOnPaths(req.PathsToScan, SecretSearchOptions{
		ShowSource:            req.ShowSource,
		Exclusions:            wl,
		ConfidentialFilesOnly: req.ConfidentialFilesOnly,
		CalculateChecksum:     req.CalculateChecksum,
	})
	for diagnostic := range diags {
		if err := stream.Send(model.ConvertSecurityDiagnostic(diagnostic)); err != nil {
			return err
		}
	}
	<-paths
	return nil
}
