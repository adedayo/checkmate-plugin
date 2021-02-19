package secrets

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	gitutils "github.com/adedayo/checkmate-core/pkg/git"
	"github.com/adedayo/checkmate-core/pkg/util"
)

var (
	confidentialFilesProviderID     = "ConfidentialFiles"
	pathBasedSecretFinderProviderID = "PathBasedSecretsFinder"
	gitURL                          = regexp.MustCompile(`\s*(?i:https?://|git@).*`)
)

//SearchSecretsOnPaths searches for secrets on indicated paths (may include local paths and git repositories)
//Streams back security diagnostics and paths
func SearchSecretsOnPaths(paths []string, options SecretSearchOptions) (chan diagnostics.SecurityDiagnostic, chan []string) {
	out := make(chan diagnostics.SecurityDiagnostic)
	pathsOut := make(chan []string)
	repositories, local := determineAndCloneRepositories(paths)
	paths = local
	for _, path := range repositories {
		paths = append(paths, path)
	}
	//reverse map local paths to git URLs
	repoMapper := make(map[string]string)
	for repo, loc := range repositories {
		repoMapper[loc] = repo
	}
	collector := func(diagnostic diagnostics.SecurityDiagnostic) {
		location := *diagnostic.Location
		for loc, repo := range repoMapper {
			location = strings.Replace(location, loc, repo, 1)
		}
		diagnostic.Location = &location
		if repo, present := repoMapper[*diagnostic.Location]; present {
			diagnostic.Location = &repo
		}
		out <- diagnostic
	}

	var consumers []util.PathConsumer
	if options.ConfidentialFilesOnly {
		consumers = []util.PathConsumer{
			&confidentialFilesFinder{
				ExclusionProvider: options.Exclusions,
				options:           options,
			},
		}
	} else {
		consumers = []util.PathConsumer{
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
	for _, c := range consumers {
		providers = append(providers, c.(diagnostics.SecurityDiagnosticsProvider))
	}
	common.RegisterDiagnosticsConsumer(collector, providers...)

	mux := util.NewPathMultiplexer(consumers...)

	go func() {
		allFiles := []string{}
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

//determineAndCloneRepositories returns local paths after cloning git URLs. A map of git URL to the local map is the first argument
//and the second argument are non-git local paths
func determineAndCloneRepositories(paths []string) (map[string]string, []string) {
	repoMap := make(map[string]string)
	local := []string{}
	for _, p := range paths {
		if !gitURL.MatchString(p) {
			local = append(local, p)
		} else {
			if _, present := repoMap[p]; !present {
				if repo, err := gitutils.Clone(p); err == nil {
					repoMap[p] = repo
				}
			}
		}
	}
	return repoMap, local
}

type confidentialFilesFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.ExclusionProvider
	verbose bool //if set, generate diagnostics for excluded files/paths
	options SecretSearchOptions
}

func (cff confidentialFilesFinder) ConsumePath(path string) {
	if cff.ShouldExcludePath(path) {
		if cff.verbose {
			why := fmt.Sprintf("Skipped: An exclusion matches path %s", path)
			issue := diagnostics.SecurityDiagnostic{
				Location:   &path,
				ProviderID: &confidentialFilesProviderID,
				Justification: diagnostics.Justification{
					Headline: diagnostics.Evidence{
						Description: why,
						Confidence:  diagnostics.High,
					},
				},
				Excluded: true,
				SHA256:   computeFileHash(cff.options.CalculateChecksum, path),
			}
			cff.Broadcast(issue)
		}
		return
	}
	if confidential, why := common.IsConfidentialFile(path); confidential {
		why = fmt.Sprintf("Warning! You may be sharing confidential (%s) data with your code", why)
		issue := diagnostics.SecurityDiagnostic{
			Location:   &path,
			ProviderID: &confidentialFilesProviderID,
			SHA256:     computeFileHash(cff.options.CalculateChecksum, path),
			Justification: diagnostics.Justification{
				Headline: diagnostics.Evidence{
					Description: why,
					Confidence:  diagnostics.Medium,
				},
				Reasons: []diagnostics.Evidence{
					{
						Description: why,
						Confidence:  diagnostics.Medium,
					},
				},
			},
		}
		cff.Broadcast(issue)
	}
}

type pathBasedSourceSecretFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.ExclusionProvider
	showSource bool
	options    SecretSearchOptions
}

func (pathBSF pathBasedSourceSecretFinder) ConsumePath(path string) {

	if pathBSF.options.Verbose {
		log.Printf("Processing file: %s\n", path)
	}

	if pathBSF.ShouldExcludePath(path) {
		if pathBSF.options.ReportIgnored {
			why := fmt.Sprintf("Skipped: An exclusion matches path %s", path)
			issue := diagnostics.SecurityDiagnostic{
				Location:   &path,
				ProviderID: &pathBasedSecretFinderProviderID,
				Justification: diagnostics.Justification{
					Headline: diagnostics.Evidence{
						Description: why,
						Confidence:  diagnostics.High,
					},
				},
				Excluded: true,
			}
			pathBSF.Broadcast(issue)
		}
		return
	}
	ext := filepath.Ext(path)
	cutOffSize := int64(10240)

	if _, present := common.TextFileExtensions[ext]; present {
		if f, err := os.Open(path); err == nil {
			if _, present := recognisedFiles[ext]; !present {
				//Skip searching file not in standard recognised parsable files and greater than 10Mb in size
				if stat, err := f.Stat(); err == nil && stat.Size() > cutOffSize {
					if pathBSF.options.ReportIgnored {
						why := fmt.Sprintf("Skipped: File %s exceeds %d bytes in size", path, cutOffSize)
						issue := diagnostics.SecurityDiagnostic{
							Location:   &path,
							ProviderID: &confidentialFilesProviderID,
							Justification: diagnostics.Justification{
								Headline: diagnostics.Evidence{
									Description: why,
									Confidence:  diagnostics.High,
								},
							},
							Excluded: true,
							SHA256:   computeFileHash(pathBSF.options.CalculateChecksum, path),
						}
						pathBSF.Broadcast(issue)
					}
					f.Close()
					return
				}
			}
			for issue := range FindSecret(path, f, GetFinderForFileType(ext, path, pathBSF.options), pathBSF.options.ShowSource) {
				issue.Location = &path
				pathBSF.Broadcast(issue)
			}

			f.Close()
		}
	} else {
		if pathBSF.options.ReportIgnored {
			why := fmt.Sprintf("Skipped: File extension %s is ignored", ext)
			issue := diagnostics.SecurityDiagnostic{
				Location:   &path,
				ProviderID: &pathBasedSecretFinderProviderID,
				Justification: diagnostics.Justification{
					Headline: diagnostics.Evidence{
						Description: why,
						Confidence:  diagnostics.High,
					},
				},
			}
			pathBSF.Broadcast(issue)
		}
	}
}
