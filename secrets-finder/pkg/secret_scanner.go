package secrets

import (
	"os"
	"strings"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	gitutils "github.com/adedayo/checkmate-core/pkg/git"
	"github.com/adedayo/checkmate-core/pkg/projects"
	"github.com/adedayo/checkmate-core/pkg/util"
)

type SecretScanner struct {
	options SecretSearchOptions
}

func (scanner SecretScanner) Scan(projectID string, scanID string, pm projects.ProjectManager,
	progressCallback func(diagnostics.Progress), consumers ...diagnostics.SecurityDiagnosticsConsumer) {

	//ensure project and scan config exist
	proj := pm.GetProject(projectID)
	if proj.ID != projectID {
		return // no such project
	}

	scanConfig := pm.GetScanConfig(projectID, scanID)
	if scanConfig.ID == "" {
		return //no such scan confguration
	}

	if excl, err := diagnostics.CompileExcludes(&scanConfig.Policy); err == nil {
		scanner.options.Exclusions = excl
	}

	if o, present := scanConfig.Config["secret-search-options"]; present {
		if opts, ok := o.(SecretSearchOptions); ok {
			scanner.options = opts
		}
	}

	//get paths and check out repositories as may be necessary
	repos := proj.Repositories
	repositories, local := cloneRepositories(repos)
	paths := local
	for _, path := range repositories {
		paths = append(paths, path)
	}
	//reverse map local paths to git URLs
	repoMapper := make(map[string]string)
	for repo, loc := range repositories {
		repoMapper[loc] = repo
	}

	//a diagnostics collect function that fixes location for git repositories
	//and multiplexes the diagnostic to all provided diagnostic consumers
	transposePathsToRepoBaseDiagnosticConsumer := func(diagnostic *diagnostics.SecurityDiagnostic) {
		location := *diagnostic.Location
		for loc, repo := range repoMapper {
			location = strings.Replace(location, loc, repo, 1)
		}
		diagnostic.Location = &location
		if repo, present := repoMapper[*diagnostic.Location]; present {
			diagnostic.Location = &repo
		}
		for _, consumer := range consumers {
			consumer.ReceiveDiagnostic(diagnostic)
		}
	}

	//set up secret finders as path consumers
	pathConsumers := []util.PathConsumer{
		//we always do confidential files search
		&confidentialFilesFinder{
			ExclusionProvider: scanner.options.Exclusions,
			options:           scanner.options,
		},
	}

	if !scanner.options.ConfidentialFilesOnly {
		pathConsumers = append(pathConsumers, &pathBasedSourceSecretFinder{
			showSource:        scanner.options.ShowSource,
			ExclusionProvider: scanner.options.Exclusions,
			options:           scanner.options,
		})
	}
	//multiplex the path consumers
	mux := util.NewPathMultiplexer(pathConsumers...)

	//these path consumers are security diagnostic providers
	diagnosticProviders := []diagnostics.SecurityDiagnosticsProvider{}
	for _, c := range pathConsumers {
		diagnosticProviders = append(diagnosticProviders, c.(diagnostics.SecurityDiagnosticsProvider))
	}

	//next call connects the diagnostic output of the providers to the
	//diagnostic consumers provided to this function
	common.RegisterDiagnosticsConsumer(transposePathsToRepoBaseDiagnosticConsumer, diagnosticProviders...)

	//we are now ready to scan for secrets

	//1. search for files to scan
	allFiles := util.FindFiles(paths)
	fileCount := len(allFiles)

	//2. scan them (mux.ConsumePath), sending progress indicators
	for index, path := range allFiles {
		progress := diagnostics.Progress{
			ProjectID:   projectID,
			ScanID:      scanID,
			CurrentFile: path, //TODO transpose path
			Position:    int64(index + 1),
			Total:       int64(fileCount),
		}
		progressCallback(progress)
		mux.ConsumePath(path)
	}

	//3. cleanup: delete checked out repositories
	for _, r := range repositories {
		os.RemoveAll(r)
	}
}

func MakeSecretScanner(config SecretSearchOptions) SecretScanner {
	return SecretScanner{
		options: config,
	}
}

//cloneRepositories returns local paths after cloning git URLs. A map of git URL to the local map is the first argument
//and the second argument are non-git local paths
func cloneRepositories(repo []projects.Repository) (map[string]string, []string) {
	repoMap := make(map[string]string)
	local := []string{}
	for _, p := range repo {
		switch p.LocationType {
		case "filesystem":
			local = append(local, p.Location)
		case "git":
			if _, present := repoMap[p.Location]; !present {
				if repo, err := gitutils.Clone(p.Location); err == nil {
					repoMap[p.Location] = repo
				}
			}
		default:
			//ignore any other types of repos
		}
	}
	return repoMap, local
}
