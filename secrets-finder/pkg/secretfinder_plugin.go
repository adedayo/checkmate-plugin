package secrets

import (
	"os"

	common "github.com/adedayo/checkmate-core/pkg"
	diagnostics "github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/util"
)

// FinderPlugin is the plugin interface to the CheckMate Secret Finder module
// type FinderPlugin struct {
// 	model.CheckMatePluginInterface
// }

//GetPluginMetadata returns the plugin metadata
// func (sfp *FinderPlugin) GetPluginMetadata() (*pb.PluginMetadata, error) {
// 	var path string
// 	if exe, err := os.Executable(); err == nil {
// 		path = exe
// 	}
// 	return &pb.PluginMetadata{
// 		Description: "CheckMate's secrets-in-code detection plugin",
// 		Name:        "Secrets Finder",
// 		Id:          "secrets-finder",
// 		Path:        path,
// 	}, nil
// }

// //Scan runs the static analysis scan to find secrets in code and configuration files
// func (sfp *FinderPlugin) Scan(req *pb.ScanRequest, stream pb.PluginService_ScanServer) error {

// 	container := diagnostics.ExcludeContainer{
// 		ExcludeDef: model.ConvertExcludeDefinition(req.Excludes),
// 		Repositories:/**empty repository locations*/ []string{},
// 	}
// 	wl, err := diagnostics.CompileExcludes(container)
// 	if err != nil {
// 		return err
// 	}
// 	diags, paths := SearchSecretsOnPaths(req.PathsToScan, SecretSearchOptions{
// 		ShowSource:            req.ShowSource,
// 		Exclusions:            wl,
// 		ConfidentialFilesOnly: req.ConfidentialFilesOnly,
// 		CalculateChecksum:     req.CalculateChecksum,
// 	})
// 	for diagnostic := range diags {
// 		if err := stream.Send(model.ConvertSecurityDiagnostic(diagnostic)); err != nil {
// 			return err
// 		}
// 	}
// 	<-paths
// 	return nil
// }

//SearchSecretsOnPaths searches for secrets on indicated paths (may include local paths and git repositories)
//Streams back security diagnostics and paths
func SearchSecretsOnPaths(paths []string, options SecretSearchOptions) (chan *diagnostics.SecurityDiagnostic, chan []util.RepositoryIndexedFile) {
	out := make(chan *diagnostics.SecurityDiagnostic)
	pathsOut := make(chan []util.RepositoryIndexedFile)
	repositories, local := determineAndCloneRepositories(paths)
	pathTransposer := locationTransposer(toPathsandLocationIDs(local, repositories))
	// paths = local
	// for _, path := range repositories {
	// 	paths = append(paths, path)
	// }
	// //reverse map local paths to git URLs
	// repoMapper := make(map[string]string)
	// for repo, loc := range repositories {
	// 	repoMapper[loc] = repo
	// }
	collector := func(diagnostic *diagnostics.SecurityDiagnostic) {
		// location := *diagnostic.Location
		// for loc, repo := range repoMapper {
		// 	location = strings.Replace(location, loc, repo, 1)
		// }
		// diagnostic.Location = &location
		// if repo, present := repoMapper[*diagnostic.Location]; present {
		// 	diagnostic.Location = &repo
		// }

		location := pathTransposer(util.RepositoryIndexedFile{
			RepositoryIndex: diagnostic.RepositoryIndex,
			File:            *diagnostic.Location,
		})

		diagnostic.Location = &location
		out <- diagnostic
	}

	var pathConsumers []util.PathConsumer
	if options.ConfidentialFilesOnly {
		pathConsumers = []util.PathConsumer{
			&confidentialFilesFinder{
				ExclusionProvider: options.Exclusions,
				options:           options,
			},
		}
	} else {
		pathConsumers = []util.PathConsumer{
			&confidentialFilesFinder{
				ExclusionProvider: options.Exclusions,
				options:           options,
			},
			&pathBasedSourceSecretFinder{
				showSource:        options.ShowSource,
				ExclusionProvider: options.Exclusions,
				options:           options,
			},
		}

	}
	providers := []diagnostics.SecurityDiagnosticsProvider{}
	for _, c := range pathConsumers {
		providers = append(providers, c.(diagnostics.SecurityDiagnosticsProvider))
	}
	common.RegisterDiagnosticsConsumer(collector, providers...)

	mux := util.NewPathMultiplexer(pathConsumers...)

	go func() {
		allFiles := []util.RepositoryIndexedFile{}
		defer func() {
			//clean downloaded repositories
			for _, r := range repositories {
				os.RemoveAll(r)
			}
			close(out)
			pathsOut <- allFiles
			close(pathsOut)
		}()
		allFiles = util.FindFiles(paths)
		for _, path := range allFiles {
			mux.ConsumePath(path)
		}
	}()

	return out, pathsOut
}
