package secrets

import (
	"fmt"
	"log"
	"net/http"
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
	TenMB                           = int64(1024 * 1000 * 10) // 10Mb
)

//SearchSecretsOnPaths searches for secrets on indicated paths (may include local paths and git repositories)
//Streams back security diagnostics and paths
func SearchSecretsOnPaths(paths []string, options SecretSearchOptions) (chan *diagnostics.SecurityDiagnostic, chan []string) {
	out := make(chan *diagnostics.SecurityDiagnostic)
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
	collector := func(diagnostic *diagnostics.SecurityDiagnostic) {
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
	options SecretSearchOptions
}

func (cff confidentialFilesFinder) ConsumePath(path string) {
	isTestFile := testFile.MatchString(path)
	if confidential, why := common.IsConfidentialFile(path); confidential {

		if cff.options.Verbose {
			log.Printf("Processing file: %s\n", path)
		}

		if cff.options.ExcludeTestFiles {
			if isTestFile {
				if cff.options.Verbose {
					log.Printf("Skipping suspected test file %s\n", path)
				}
				if cff.options.ReportIgnored {
					why := fmt.Sprintf("Skipped: Suspected test file %s", path)
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
					issue.AddTag("test")
					cff.Broadcast(&issue)
				}
				return
			}
		}

		if cff.ShouldExcludePath(path) {
			if cff.options.Verbose {
				log.Printf("Skipping excluded path %s\n", path)
			}

			if cff.options.ReportIgnored {
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
				if isTestFile {
					issue.AddTag("test")
				}
				cff.Broadcast(&issue)
			}
			return
		}

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
		if isTestFile {
			issue.AddTag("test")
		}
		if confidential {
			issue.AddTag("confidential")
		}
		cff.Broadcast(&issue)
	}
}

type pathBasedSourceSecretFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.ExclusionProvider
	showSource bool
	options    SecretSearchOptions
}

func (pathBSF pathBasedSourceSecretFinder) ConsumePath(path string) {

	isTestFile := testFile.MatchString(path)

	if pathBSF.options.Verbose {
		log.Printf("Processing file: %s\n", path)
	}

	if pathBSF.options.ExcludeTestFiles {
		if isTestFile {
			if pathBSF.options.Verbose {
				log.Printf("Skipping suspected test File %s\n", path)
			}
			if pathBSF.options.ReportIgnored {
				why := fmt.Sprintf("Skipped: Suspected test file %s", path)
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
				issue.AddTag("test")
				pathBSF.Broadcast(&issue)
			}
			return
		}
	}

	if pathBSF.ShouldExcludePath(path) {

		if pathBSF.options.Verbose {
			log.Printf("Skipping excluded path %s\n", path)
		}

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
			if isTestFile {
				issue.AddTag("test")
			}
			pathBSF.Broadcast(&issue)
		}
		return
	}
	ext := filepath.Ext(path)
	cutOffSize := TenMB

	if _, present := common.TextFileExtensions[ext]; present || ext == "" { //now scan files without extensions, TODO: avoid binary files
		if f, err := os.Open(path); err == nil {
			defer f.Close()
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
						if isTestFile {
							issue.AddTag("test")
						}
						pathBSF.Broadcast(&issue)
					}
					return
				}

				if ext == "" {
					buff := make([]byte, 512)
					_, err := f.Read(buff)
					if err == nil && !strings.Contains(http.DetectContentType(buff), "text/plain") {
						//we found a non-textual file with no extension, skip scanning
						return
					}
				}
			}
			for issue := range FindSecret(path, f, GetFinderForFileType(ext, path, pathBSF.options), pathBSF.options.ShowSource) {
				issue.Location = &path
				if isTestFile {
					issue.AddTag("test")
				}

				val := issue.GetValue()
				if !pathBSF.ShouldExclude(path, val) {
					pathBSF.Broadcast(issue)
				}
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
			if isTestFile {
				issue.AddTag("test")
			}
			pathBSF.Broadcast(&issue)
		}
	}
}
