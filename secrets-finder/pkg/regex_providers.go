package secrets

import (
	"regexp"
	"strings"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/code"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/util"
)

var (
	//JavaFinder provides secret detection in Java-like programming languages
	// JavaFinder                     MatchProvider
	descHardCodedSecretAssignment  = "Hard-coded secret assignment"
	descVarSecret                  = "Variable name suggests it is a secret"
	descEncodedSecret              = "Value looks suspiciously like an encoded secret (e.g. Base64 or Hex encoded)"
	descSecretUnbrokenString       = "Unbroken string may be a secret"
	descConstantAssignment         = "Constant assignment to a variable name that suggests it is a secret"
	descHardCodedSecret            = "Hard-coded secret"
	descDefaultSecret              = "Default or common secret value"
	descCommonSecret               = "Value contains or appears to be a common credential"
	descSuspiciousSecret           = "Value looks suspiciously like a secret"
	descHighEntropy                = "Value has a high entropy, may be a secret"
	descNotSecret                  = "Value does not appear to be a secret"
	unusualPasswordStartCharacters = `<>&^%?#({|/`

	assignmentProviderID       = "SecretAssignment"
	confAssignmentProviderID   = "ConfSecretAssignment"
	cppAssignmentProviderID    = "CPPSecretAssignment"
	longTagValueProviderID     = "LongTagValueSecretAssignment"
	secretTagProviderID        = "CommonSecretTagValue"
	jsonAssignmentProviderID   = "JSONSecretAssignment"
	yamlAssignmentProviderID   = "YAMLSecretAssignment"
	arrowAssignmentProviderID  = "ArrowSecretAssignment"
	defineAssignmentProviderID = "DefineSecretAssignment"
	tagAssignmentProviderID    = "TagSecretAssignment"

	longStringProviderID   = "LongString"
	secretStringProviderID = "SecretString"
)

//GetFinderForFileType returns the appropriate MatchProvider based on the file type hint
func GetFinderForFileType(fileType string, whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	switch strings.ToLower(fileType) {
	case ".java", ".scala", ".kt", ".go":
		return NewJavaFinder(whitelistProvider)
	case ".c", ".cpp", ".cc", ".c++", ".h++", ".hh", ".hpp":
		return NewCPPSecretsFinders(whitelistProvider)
	case ".xml":
		return NewXMLSecretsFinders(whitelistProvider)
	case ".json":
		return NewJSONSecretsFinders(whitelistProvider)
	case ".yaml", ".yml":
		return NewYamlSecretsFinders(whitelistProvider)
	case ".rb":
		return NewRubySecretsFinders(whitelistProvider)
	case ".erb":
		return NewERubySecretsFinders(whitelistProvider)
	case ".conf":
		return NewConfigurationSecretsFinder(whitelistProvider)
	default:
		return defaultFinder(whitelistProvider)
	}
}

func defaultFinder(whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(assignmentProviderID, secretAssignment, whitelistProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, whitelistProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, whitelistProvider),
		},
	}
}

//NewJavaFinder provides secret detection in Java-like programming languages
func NewJavaFinder(whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(assignmentProviderID, secretAssignment, whitelistProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, whitelistProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, whitelistProvider),
		},
	}
}

//MatchProvider provides regular expressions and other facilities for locating secrets in source data
type MatchProvider interface {
	// common.WhitelistProvider
	GetFinders() []common.SourceToSecurityDiagnostics
}

//RegexFinder provides secret detection using regular expressions
type RegexFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	res           []*regexp.Regexp
	lineKeeper    *util.LineKeeper
	providerID    string
	provideSource bool
}

//GetRegularExpressions returns the underlying compiled regular expressions
func (finder RegexFinder) GetRegularExpressions() []*regexp.Regexp {
	return finder.res
}

//Consume allows a source processor receive `source` data streamed in "chunks", with `startIndex` indicating the
//character location of the first character in the stream
func (finder *RegexFinder) Consume(startIndex int, source string) {
}

//SetLineKeeper allows this source consumer to keep track of `code.Position`
func (finder *RegexFinder) SetLineKeeper(lk *util.LineKeeper) {
	finder.lineKeeper = lk
}

//End is used to signal to the consumer that the source stream has ended
func (finder *RegexFinder) End() {

}

//ShouldProvideSourceInDiagnostics toggles whether source evidence should be provided with diagnostics, defaults to false
func (finder *RegexFinder) ShouldProvideSourceInDiagnostics(provideSource bool) {
	finder.provideSource = provideSource
}

type defaultMatchProvider struct {
	finders []common.SourceToSecurityDiagnostics
}

func (dmp defaultMatchProvider) GetFinders() []common.SourceToSecurityDiagnostics {
	return dmp.finders
}

func (dmp defaultMatchProvider) ShouldWhitelist(pathContext, value string) bool {
	return false
}

//NewConfigurationSecretsFinder is a `MatchProvider` for finding secrets in configuration `.conf` files
func NewConfigurationSecretsFinder(whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(confAssignmentProviderID, confAssignment, whitelistProvider),
			makeAssignmentFinder(assignmentProviderID, secretAssignment, whitelistProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool, whitelistProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, whitelistProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, whitelistProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, whitelistProvider),
		},
	}
}

//NewCPPSecretsFinders is a `MatchProvider` for finding secrets in files with C++-like content
func NewCPPSecretsFinders(whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(cppAssignmentProviderID, secretCPPAssignment, whitelistProvider),
			makeAssignmentFinder(defineAssignmentProviderID, secretDefine, whitelistProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, whitelistProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, whitelistProvider),
		},
	}
}

//NewXMLSecretsFinders is a `MatchProvider` for finding secrets in files with XML content
func NewXMLSecretsFinders(whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(tagAssignmentProviderID, secretTags, whitelistProvider),
			makeAssignmentFinder(assignmentProviderID, secretAssignment, whitelistProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, whitelistProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, whitelistProvider),
		},
	}
}

//NewJSONSecretsFinders is a `MatchProvider` for finding secrets in files with JSON content
func NewJSONSecretsFinders(whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, whitelistProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool, whitelistProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, whitelistProvider),
		},
	}
}

//NewRubySecretsFinders is a `MatchProvider` for finding secrets in files with Ruby content
func NewRubySecretsFinders(whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(tagAssignmentProviderID, secretTags, whitelistProvider),
			makeAssignmentFinder(assignmentProviderID, secretAssignment, whitelistProvider),
			makeAssignmentFinder(longTagValueProviderID, longTagValues, whitelistProvider),
			makeAssignmentFinder(secretTagProviderID, secretTagValues, whitelistProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, whitelistProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, whitelistProvider),
		},
	}
}

//NewERubySecretsFinders is a `MatchProvider` for finding secrets in files with ERuby content
func NewERubySecretsFinders(whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(tagAssignmentProviderID, secretTags, whitelistProvider),
			makeAssignmentFinder(assignmentProviderID, secretAssignment, whitelistProvider),
			makeAssignmentFinder(longTagValueProviderID, longTagValues, whitelistProvider),
			makeAssignmentFinder(secretTagProviderID, secretTagValues, whitelistProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, whitelistProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool, whitelistProvider),
			makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment, whitelistProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, whitelistProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, whitelistProvider),
		},
	}
}

//NewYamlSecretsFinders is a `MatchProvider` for finding secrets in files with YAML content
func NewYamlSecretsFinders(whitelistProvider diagnostics.WhitelistProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment, whitelistProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, whitelistProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, whitelistProvider),
		},
	}
}

func makeAssignmentFinder(providerID string, re *regexp.Regexp, whitelistProvider diagnostics.WhitelistProvider) *assignmentFinder {
	sa := assignmentFinder{
		secretFinder{WhitelistProvider: whitelistProvider},
	}
	sa.providerID = providerID
	sa.res = []*regexp.Regexp{re}
	return &sa
}

func makeSecretStringFinder(providerID string, re *regexp.Regexp, whitelistProvider diagnostics.WhitelistProvider) *secretStringFinder {
	sf := secretStringFinder{
		secretFinder{
			WhitelistProvider: whitelistProvider,
		},
	}
	sf.providerID = providerID
	sf.res = []*regexp.Regexp{re}
	return &sf
}

type secretFinder struct {
	RegexFinder
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.WhitelistProvider
}

type assignmentFinder struct {
	secretFinder
}

func (sa *assignmentFinder) Consume(startIndex int, source string) {
	for _, re := range sa.GetRegularExpressions() {
		matches := re.FindAllStringSubmatchIndex(source, -1)
		for _, match := range matches {
			if len(match) == 6 { //we are expecting 6 elements
				start := match[0]
				end := match[1]

				rhsStart := match[4] //beginning of assigned value
				assignedVal := source[rhsStart:end]
				assignedVal, count := trimQuotes(assignedVal)
				rhsStart += count
				rhsEnd := rhsStart + len(assignedVal)
				evidence := detectSecret(assignedVal)
				variable := strings.ToLower(source[match[2]:match[3]])
				if strings.Contains(variable, "passphrase") {
					//special "passphrase" case:
					//if the assigned variable is a passphrase bypass any result of the assigned value
					evidence.Description = descHardCodedSecret
					evidence.Confidence = diagnostics.High
				}

				diagnostic := diagnostics.SecurityDiagnostic{
					Justification: diagnostics.Justification{
						Headline: diagnostics.Evidence{
							Description: descHardCodedSecretAssignment,
							Confidence:  diagnostics.Medium,
						},
						Reasons: []diagnostics.Evidence{
							{
								Description: descVarSecret,
								Confidence:  diagnostics.High,
							},
							evidence},
					},
					Range: code.Range{
						Start: sa.lineKeeper.GetPositionFromCharacterIndex(startIndex + start - 1),
						End:   sa.lineKeeper.GetPositionFromCharacterIndex(startIndex + end - 1),
					},
					HighlightRange: code.Range{
						Start: sa.lineKeeper.GetPositionFromCharacterIndex(startIndex + rhsStart - 1),
						End:   sa.lineKeeper.GetPositionFromCharacterIndex(startIndex + rhsEnd - 1),
					},
					ProviderID:  &sa.providerID,
					Whitelisted: sa.ShouldWhitelistValue(assignedVal),
				}
				if diagnostic.Justification.Reasons[1].Confidence != diagnostics.Low {
					diagnostic.Justification.Headline.Confidence = diagnostics.High
				}
				if diagnostic.Justification.Reasons[1].Description == descNotSecret &&
					diagnostic.Justification.Headline.Confidence > diagnostics.Medium {
					diagnostic.Justification.Headline.Confidence = diagnostics.Medium
				}
				if sa.provideSource {
					s := source[start:end]
					diagnostic.Source = &s
				}
				sa.Broadcast(diagnostic)
			}
		}
	}

}

//trimQuotes attempts to remove balanced quotes around a piece of string
//returns the trimmed text and the number of characters trimmed from the prefix
func trimQuotes(text string) (string, int) {
	text = strings.TrimSpace(text)
	count := 0
	text, c := balancedTrim(text, '`')
	count += c
	text, c = balancedTrim(text, []byte(`'`)[0])
	count += c
	text, c = balancedTrim(text, '"')
	count += c
	//for tripple quoted strings deal with the next pair of quotes
	if len(text) > 3 && strings.HasPrefix(text, `""`) && strings.HasSuffix(text, `""`) {
		text = strings.TrimPrefix(text, `""`)
		text = strings.TrimSuffix(text, `""`)
		count += 2
	}
	return text, count
}

func balancedTrim(text string, quote byte) (string, int) {
	trimmed := text
	count := 0
	if len(text) > 0 && text[0] == quote && text[len(text)-1] == quote {
		trimmed = text[1 : len(text)-1]
		count++
	}
	return trimmed, count
}

func isQuote(q rune) bool {
	return strings.ContainsRune("`'"+`"`, q)
}

type secretStringFinder struct {
	secretFinder
}

func (sf *secretStringFinder) Consume(startIndex int, source string) {
	for _, re := range sf.GetRegularExpressions() {
		matches := re.FindAllStringSubmatchIndex(source, -1)
		for _, match := range matches {
			if len(match) == 4 && space.FindAllStringIndex(source[match[0]:match[1]], -1) == nil {
				start := match[0]
				end := match[1]

				value := source[start:end]
				// value = strings.Trim(value, `"'`+"`")
				value, count := trimQuotes(value)
				stringStart := start + count
				stringEnd := stringStart + len(value)

				evidence := detectSecret(value)
				diagnostic := diagnostics.SecurityDiagnostic{
					Justification: diagnostics.Justification{
						Headline: diagnostics.Evidence{
							Description: descSecretUnbrokenString,
							Confidence:  diagnostics.Medium,
						},
						Reasons: []diagnostics.Evidence{
							{
								Description: descSecretUnbrokenString,
								Confidence:  diagnostics.Medium,
							},
							evidence},
					},
					Range: code.Range{
						Start: sf.lineKeeper.GetPositionFromCharacterIndex(startIndex + start - 1),
						End:   sf.lineKeeper.GetPositionFromCharacterIndex(startIndex + end - 1),
					},
					HighlightRange: code.Range{
						Start: sf.lineKeeper.GetPositionFromCharacterIndex(startIndex + stringStart - 1),
						End:   sf.lineKeeper.GetPositionFromCharacterIndex(startIndex + stringEnd - 1),
					},
					ProviderID:  &sf.providerID,
					Whitelisted: sf.ShouldWhitelistValue(value),
				}
				if diagnostic.Justification.Reasons[1].Confidence == diagnostics.High {
					diagnostic.Justification.Headline.Confidence = diagnostics.High
				}
				if sf.provideSource {
					s := source[start:end]
					diagnostic.Source = &s
				}
				sf.Broadcast(diagnostic)
			}
		}
	}

}
