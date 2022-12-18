package secrets

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
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

func (scanner SecretScanner) Scan(ctx context.Context, projectID string, scanID string, pm projects.ProjectManager,
	progressCallback func(diagnostics.Progress), consumers ...diagnostics.SecurityDiagnosticsConsumer) {

	//ensure project and scan config exist
	proj, err := pm.GetProject(projectID)
	if err != nil {
		return // no such project
	}

	scanConfig, err := pm.GetScanConfig(projectID, scanID)
	if err != nil {
		return //no such scan configuration
	}

	container := diagnostics.ExcludeContainer{
		ExcludeDef: &scanConfig.Policy,
	}

	for _, loc := range proj.Repositories {
		container.Repositories = append(container.Repositories, loc.Location)
	}

	if excl, err := diagnostics.CompileExcludes(container); err == nil {
		scanner.options.Exclusions = excl
	}

	if o, present := scanConfig.Config["secret-search-options"]; present {
		if opts, ok := o.(SecretSearchOptions); ok {
			scanner.options = opts
		}
	}

	//get paths and check out repositories as may be necessary
	repositories, local := cloneRepositories(ctx, &proj, scanID, pm, progressCallback)

	paths, locID := toPathsandLocationIDs(local, repositories)

	//reverse map local (temporary code checkout) paths to git URLs
	// repoMapper := make(map[string]string)
	// for repo, path := range repositories {
	// 	paths = append(paths, path)
	// 	repoMapper[path] = repo
	// }

	transposePath := locationTransposer(paths, locID)

	//a diagnostics collect function that fixes location for git repositories
	//and multiplexes the diagnostic to all provided diagnostic consumers
	transposePathsToRepoBaseDiagnosticConsumer := func(diagnostic *diagnostics.SecurityDiagnostic) {
		location, branch := transposePath(util.RepositoryIndexedFile{
			RepositoryIndex: diagnostic.RepositoryIndex,
			File:            *diagnostic.Location})
		diagnostic.Location = &location
		if branch != "" {
			diagnostic.AddTag(fmt.Sprintf("branch=%s", branch))
		}
		for _, consumer := range consumers {
			consumer.ReceiveDiagnostic(diagnostic)
		}
	}

	//set up secret finders as path consumers
	size := 1
	if !scanner.options.ConfidentialFilesOnly {
		size = 2
	}

	pathConsumers := make([]util.PathConsumer, 0, size)

	//we always do confidential files search
	pathConsumers = append(pathConsumers, &confidentialFilesFinder{
		ExclusionProvider: scanner.options.Exclusions,
		options:           scanner.options,
	})

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
	// log.Printf("Searching for files")
	allFiles := util.FindFiles(paths)
	fileCount := len(allFiles)

	//2. scan them (mux.ConsumePath), sending progress indicators
	for index, rif := range allFiles {
		f, _ := transposePath(rif)
		progress := diagnostics.Progress{
			ProjectID:   projectID,
			ScanID:      scanID,
			CurrentFile: f,
			Position:    int64(index + 1),
			Total:       int64(fileCount),
		}
		progressCallback(progress)
		mux.ConsumePath(rif)
	}

	//3. cleanup: delete checked out repositories if required
	if proj.DeleteCheckedOutCode {
		for _, r := range repositories {
			os.RemoveAll(r.Location)
		}
	}
}

// create a location ID for each repository/local path
// align paths[id] to the corresponding loc[id] map
func toPathsandLocationIDs(local []string, repositories map[string]gitutils.CloneDetail) ([]string, map[int]gitutils.CloneDetail) {
	paths := make([]string, len(local)+len(repositories))

	locID := make(map[int]gitutils.CloneDetail)
	id := 0
	for _, p := range local {
		locID[id] = gitutils.CloneDetail{
			Location:   p,
			Repository: p,
		}
		paths[id] = p
		id++
	}
	for _, detail := range repositories {
		locID[id] = detail
		paths[id] = detail.Location
		id++
	}
	return paths, locID
}

func locationTransposer(paths []string, locID map[int]gitutils.CloneDetail) func(util.RepositoryIndexedFile) (transposedLocation, branch string) {

	return func(location util.RepositoryIndexedFile) (string, string) {
		transposedLocation := location.File
		branch := ""
		if repo, exists := locID[location.RepositoryIndex]; exists && location.RepositoryIndex < len(paths) {
			localPath := paths[location.RepositoryIndex]
			if repo.Branch != nil {
				branch = *repo.Branch
			}
			transposedLocation = strings.Replace(transposedLocation, localPath, repo.Repository, 1)
		}
		return transposedLocation, branch
	}
}

func MakeSecretScanner(config SecretSearchOptions) SecretScanner {
	return SecretScanner{
		options: config,
	}
}

// cloneRepositories returns local paths after cloning git URLs. A map of git URL to the local map is the first argument
// and the second argument are non-git local paths
func cloneRepositories(ctx context.Context, project *projects.Project, scanID string, pm projects.ProjectManager, progressMonitor func(diagnostics.Progress)) (map[string]gitutils.CloneDetail, []string) {

	repoMap := make(map[string]gitutils.CloneDetail)
	local := []string{}
	repositories := project.Repositories
	gitConfig := &gitutils.GitServiceConfig{
		GitServices: make(map[gitutils.GitServiceType]map[string]*gitutils.GitService),
	}

	confManager, err := pm.GetGitConfigManager()
	if err == nil {
		if conf, err := confManager.GetConfig(); err == nil {
			gitConfig = conf
		} else {
			log.Printf("Error getting Config service: %v", err)

		}
	} else {
		log.Printf("Error getting DB Config manager: %v", err)
	}

	repoCount := int64(len(repositories))
	for i, p := range repositories {
		switch p.LocationType {
		case "filesystem":
			local = append(local, p.Location)
		case "git":
			if _, present := repoMap[p.Location]; !present {
				options := &gitutils.GitCloneOptions{
					BaseDir: path.Join(pm.GetCodeBaseDir(), project.ID),
					Depth:   1, //shallow
				}
				if service, err := gitConfig.FindService(p.GitServiceID); err == nil {
					options.Auth = service.MakeAuth()
				} else {
					log.Printf("Error finding Git service: %v, Project: %#v", err, p)
				}
				progressMonitor(diagnostics.Progress{
					ProjectID:   project.ID,
					ScanID:      scanID,
					Position:    int64(i),
					Total:       repoCount,
					CurrentFile: fmt.Sprintf("cloning repository %s", p.Location),
				})
				if repo, err := gitutils.Clone(ctx, p.Location, options); err == nil {
					repoMap[p.Location] = repo
				} else {
					repoMap[p.Location] = repo
					log.Printf("%v", err)
				}
			}
		default:
			//ignore any other types of repos
		}
	}
	return repoMap, local
}
