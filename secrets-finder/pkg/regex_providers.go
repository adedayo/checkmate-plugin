package secrets

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
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

	assignmentProviderID          = "SecretAssignment"
	confAssignmentProviderID      = "ConfSecretAssignment"
	cppAssignmentProviderID       = "CPPSecretAssignment"
	longTagValueProviderID        = "LongTagValueSecretAssignment"
	secretTagProviderID           = "CommonSecretTagValue"
	jsonAssignmentProviderID      = "JSONSecretAssignment"
	yamlAssignmentProviderID      = "YAMLSecretAssignment"
	arrowAssignmentProviderID     = "ArrowSecretAssignment"
	defineAssignmentProviderID    = "DefineSecretAssignment"
	tagAssignmentProviderID       = "ElementSecretAssignment"
	attributeAssignmentProviderID = "AttributeSecretAssignment"
	longStringProviderID          = "LongString"
	secretStringProviderID        = "SecretString"
)

//GetFinderForFileType returns the appropriate MatchProvider based on the file type hint
func GetFinderForFileType(fileType, filePath string, exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	switch strings.ToLower(fileType) {
	case ".java", ".scala", ".kt", ".go":
		return NewJavaFinder(exclusionProvider)
	case ".c", ".cpp", ".cc", ".c++", ".h++", ".hh", ".hpp":
		return NewCPPSecretsFinders(exclusionProvider)
	case ".xml":
		return NewXMLSecretsFinders(filePath, exclusionProvider)
	case ".json":
		return NewJSONSecretsFinders(exclusionProvider)
	case ".yaml", ".yml":
		return NewYamlSecretsFinders(exclusionProvider)
	case ".rb":
		return NewRubySecretsFinders(exclusionProvider)
	case ".erb":
		return NewERubySecretsFinders(exclusionProvider)
	case ".conf":
		return NewConfigurationSecretsFinder(exclusionProvider)
	default:
		return defaultFinder(exclusionProvider)
	}
}

func defaultFinder(exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.ResourceToSecurityDiagnostics{
			makeAssignmentFinder(assignmentProviderID, secretAssignment, exclusionProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, exclusionProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, exclusionProvider),
		},
	}
}

//NewJavaFinder provides secret detection in Java-like programming languages
func NewJavaFinder(exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.ResourceToSecurityDiagnostics{
			makeAssignmentFinder(assignmentProviderID, secretAssignment, exclusionProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, exclusionProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, exclusionProvider),
		},
	}
}

//MatchProvider provides regular expressions and other facilities for locating secrets in source data and resources
type MatchProvider interface {
	// common.exclusionProvider
	GetFinders() []common.ResourceToSecurityDiagnostics
}

//RegexFinder provides secret detection using regular expressions
type RegexFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	res           []*regexp.Regexp
	regexIDs      []string //used to map each regex above to a potentially unique ID.
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
func (finder *RegexFinder) Consume(startIndex int64, source string) {
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
	finders []common.ResourceToSecurityDiagnostics
}

func (dmp defaultMatchProvider) GetFinders() []common.ResourceToSecurityDiagnostics {
	return dmp.finders
}

func (dmp defaultMatchProvider) ShouldExclude(pathContext, value string) bool {
	return false
}

//NewConfigurationSecretsFinder is a `MatchProvider` for finding secrets in configuration `.conf` files
func NewConfigurationSecretsFinder(exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.ResourceToSecurityDiagnostics{
			makeAssignmentFinder(confAssignmentProviderID, confAssignment, exclusionProvider),
			makeAssignmentFinder(assignmentProviderID, secretAssignment, exclusionProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool, exclusionProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, exclusionProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, exclusionProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, exclusionProvider),
		},
	}
}

//NewCPPSecretsFinders is a `MatchProvider` for finding secrets in files with C++-like content
func NewCPPSecretsFinders(exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.ResourceToSecurityDiagnostics{
			makeAssignmentFinder(cppAssignmentProviderID, secretCPPAssignment, exclusionProvider),
			makeAssignmentFinder(defineAssignmentProviderID, secretDefine, exclusionProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, exclusionProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, exclusionProvider),
		},
	}
}

type idRegexPair struct {
	id    string
	regex *regexp.Regexp
}

//NewXMLSecretsFinders is a `MatchProvider` for finding secrets in files with XML content
func NewXMLSecretsFinders(filePath string, exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.ResourceToSecurityDiagnostics{
			makeXMLSecretsFinder(filePath, exclusionProvider, []idRegexPair{
				{secretStringProviderID, secretStrings},
				{longStringProviderID, longStrings},
			}),
		},
	}
}

//NewJSONSecretsFinders is a `MatchProvider` for finding secrets in files with JSON content
func NewJSONSecretsFinders(exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.ResourceToSecurityDiagnostics{
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, exclusionProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool, exclusionProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, exclusionProvider),
		},
	}
}

//NewRubySecretsFinders is a `MatchProvider` for finding secrets in files with Ruby content
func NewRubySecretsFinders(exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.ResourceToSecurityDiagnostics{
			makeAssignmentFinder(tagAssignmentProviderID, secretTags, exclusionProvider),
			makeAssignmentFinder(assignmentProviderID, secretAssignment, exclusionProvider),
			makeAssignmentFinder(longTagValueProviderID, longTagValues, exclusionProvider),
			makeAssignmentFinder(secretTagProviderID, secretTagValues, exclusionProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, exclusionProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, exclusionProvider),
		},
	}
}

//NewERubySecretsFinders is a `MatchProvider` for finding secrets in files with ERuby content
func NewERubySecretsFinders(exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.ResourceToSecurityDiagnostics{
			makeAssignmentFinder(tagAssignmentProviderID, secretTags, exclusionProvider),
			makeAssignmentFinder(assignmentProviderID, secretAssignment, exclusionProvider),
			makeAssignmentFinder(longTagValueProviderID, longTagValues, exclusionProvider),
			makeAssignmentFinder(secretTagProviderID, secretTagValues, exclusionProvider),
			makeSecretStringFinder(secretStringProviderID, secretStrings, exclusionProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool, exclusionProvider),
			makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment, exclusionProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, exclusionProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, exclusionProvider),
		},
	}
}

//NewYamlSecretsFinders is a `MatchProvider` for finding secrets in files with YAML content
func NewYamlSecretsFinders(exclusionProvider diagnostics.ExclusionProvider) MatchProvider {
	return &defaultMatchProvider{
		finders: []common.ResourceToSecurityDiagnostics{
			makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment, exclusionProvider),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, exclusionProvider),
			makeSecretStringFinder(longStringProviderID, longStrings, exclusionProvider),
		},
	}
}

func makeXMLSecretsFinder(filePath string, exclusionProvider diagnostics.ExclusionProvider, stringRegexes []idRegexPair) *xmlSecretFinder {
	sxml := xmlSecretFinder{
		secretFinder{ExclusionProvider: exclusionProvider},
	}
	for _, pair := range stringRegexes {
		sxml.regexIDs = append(sxml.regexIDs, pair.id)
		sxml.res = append(sxml.res, pair.regex)
	}

	return &sxml
}

func makeAssignmentFinder(providerID string, re *regexp.Regexp, exclusionProvider diagnostics.ExclusionProvider) *assignmentFinder {
	sa := assignmentFinder{
		secretFinder{ExclusionProvider: exclusionProvider},
	}
	sa.providerID = providerID
	sa.res = []*regexp.Regexp{re}
	return &sa
}

func makeSecretStringFinder(providerID string, re *regexp.Regexp, exclusionProvider diagnostics.ExclusionProvider) *secretStringFinder {
	sf := secretStringFinder{
		secretFinder{
			ExclusionProvider: exclusionProvider,
		},
	}
	sf.providerID = providerID
	sf.res = []*regexp.Regexp{re}
	return &sf
}

type secretFinder struct {
	RegexFinder
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.ExclusionProvider
}

type assignmentFinder struct {
	secretFinder
}

func (sa *assignmentFinder) Consume(startIndex int64, source string) {
	for _, re := range sa.GetRegularExpressions() {
		matches := re.FindAllStringSubmatchIndex(source, -1)
		for _, match := range matches {
			if len(match) == 6 { //we are expecting 6 elements
				start := int64(match[0])
				end := int64(match[1])

				rhsStart := int64(match[4]) //beginning of assigned value
				assignedVal := source[rhsStart:end]
				assignedVal, count := trimQuotes(assignedVal)
				rhsStart += int64(count)
				rhsEnd := rhsStart + int64(len(assignedVal))
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
					ProviderID: &sa.providerID,
					Excluded:   sa.ShouldExcludeValue(assignedVal),
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

func (sa *assignmentFinder) ConsumePath(path string) {
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
	if len(text) > 1 && text[0] == quote && text[len(text)-1] == quote {
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

func (sf *secretStringFinder) Consume(startIndex int64, source string) {
	for _, re := range sf.GetRegularExpressions() {
		matches := re.FindAllStringSubmatchIndex(source, -1)
		for _, match := range matches {
			if len(match) == 4 && space.FindAllStringIndex(source[match[0]:match[1]], -1) == nil {
				start := int64(match[0])
				end := int64(match[1])

				value := source[start:end]
				value, count := trimQuotes(value)
				stringStart := start + int64(count)
				stringEnd := stringStart + int64(len(value))

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
					ProviderID: &sf.providerID,
					Excluded:   sf.ShouldExcludeValue(value),
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

func (sf *secretStringFinder) ConsumePath(path string) {

}

type xmlSecretFinder struct {
	secretFinder
}

func (xf *xmlSecretFinder) Consume(startIndex int64, source string) {
	// the xml parser uses its own streamer to parse the content, so we do nothing here
}

func (xf *xmlSecretFinder) ConsumePath(path string) {

	//file for decoding the XML
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	//Scanner opening the same file for navigating and seeking XML positions
	scan, err := os.Open(path)
	if err != nil {
		return
	}
	defer scan.Close()

	decoder := xml.NewDecoder(file)
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	decoder.Entity = xml.HTMLEntity

	//to push and pop xml elements as we parse the document
	var stack stack

	for {
		t, _ := decoder.RawToken()
		if t == nil || t == io.EOF {
			break
		}

		switch se := t.(type) {
		case xml.StartElement:
			stack.push(se.Name.Local)
			for _, attr := range se.Attr {
				processXMLAssignment(attr.Name.Local, attr.Value, decoder.InputOffset(), false, xf)
			}
		case xml.CharData: //CDATA <![CDATA[ some CDATA content ]]>
			//- decoder also sends raw element values e.g. <el>element value</el> as CharData
			cdata := string(se)
			if strings.TrimSpace(cdata) == "" {
				continue
			}
			isChar := isCharData(scan, decoder.InputOffset())
			if !isChar {
				//deal with element value
				if el, e := stack.peek(); e == nil {
					processXMLAssignment(el, cdata, decoder.InputOffset(), true, xf)
				}
			} else {
				processXMLStrings(cdata, decoder.InputOffset(), xf)
			}
		case xml.Comment: // <!-- comments in xml -->
			processXMLStrings(string(se), decoder.InputOffset(), xf)
		case xml.EndElement:
			if x, e := stack.pop(); e != nil || se.Name.Local != x {
				log.Printf("%s, got tag %s, expecting %s", e.Error(), x, se.Name.Local)
			}
		default:
		}
	}
}

func processXMLStrings(data string, sourceIndex int64, finder *xmlSecretFinder) {
	for i, re := range finder.res {
		providerID := finder.regexIDs[i]
		findXMLStringSecret(data, sourceIndex, providerID, re, finder)
	}
}

func findXMLStringSecret(source string, startIndex int64, providerID string, re *regexp.Regexp, sf *xmlSecretFinder) {
	if strings.TrimSpace(source) == "" {
		return
	}
	matches := re.FindAllStringSubmatchIndex(source, -1)
	// fmt.Printf("Matches %#v, %d, `%s`\n", matches, startIndex, source)
	for _, match := range matches {
		if len(match) == 4 && space.FindAllStringIndex(source[match[0]:match[1]], -1) == nil {
			start := int64(match[0])
			end := int64(match[1])
			value := source[start:end]
			value, count := trimQuotes(value)
			stringStart := start + int64(count)
			stringEnd := stringStart + int64(len(value))

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
				ProviderID: &providerID,
				Excluded:   sf.ShouldExcludeValue(value),
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

//checks whether the current event is true CharData by checking for the closing marker ]]>
func isCharData(file io.ReadSeeker, start int64) bool {
	if start > 3 {
		if _, err := file.Seek(start-3, 0); err != nil {
			return false
		}
		data := make([]byte, 3)
		if n, err := file.Read(data); n == 3 && err == nil && string(data) == "]]>" {
			return true
		}
	}
	return false
}

//used for XML elements and attribute "assignments"
func processXMLAssignment(variable, assignedVal string, sourceIndex int64, isElement bool, finder *xmlSecretFinder) {

	start := sourceIndex - int64(len(assignedVal))
	end := sourceIndex
	variable = strings.ToLower(variable)
	assignedVal = strings.TrimSpace(assignedVal)

	if isElement && assignedVal == "" {
		//ignore xml elements that are not pure value e.g. <secret><otherElement></otherElement></secret>
		//we are interested in values such as <secret>some value</secret>
		return
	}
	if secretVarCompile.MatchString(variable) {
		evidence := detectSecret(assignedVal)
		if strings.Contains(variable, "passphrase") {
			//special "passphrase" case:
			//if the assigned variable is a passphrase bypass any result of the assigned value
			evidence.Description = descHardCodedSecret
			evidence.Confidence = diagnostics.High
		}

		providerID := tagAssignmentProviderID
		if !isElement {
			providerID = attributeAssignmentProviderID
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
				Start: finder.lineKeeper.GetPositionFromCharacterIndex(start),
				End:   finder.lineKeeper.GetPositionFromCharacterIndex(end),
			},
			HighlightRange: code.Range{
				Start: finder.lineKeeper.GetPositionFromCharacterIndex(start),
				End:   finder.lineKeeper.GetPositionFromCharacterIndex(end),
			},
			ProviderID: &providerID,
			Excluded:   finder.ShouldExcludeValue(assignedVal),
		}
		if diagnostic.Justification.Reasons[1].Confidence != diagnostics.Low {
			diagnostic.Justification.Headline.Confidence = diagnostics.High
		}
		if diagnostic.Justification.Reasons[1].Description == descNotSecret &&
			diagnostic.Justification.Headline.Confidence > diagnostics.Medium {
			diagnostic.Justification.Headline.Confidence = diagnostics.Medium
		}
		if finder.provideSource {
			s := fmt.Sprintf(`%s="%s"`, variable, assignedVal)
			if isElement {
				s = fmt.Sprintf(`%s > %s`, variable, assignedVal)
			}
			diagnostic.Source = &s
		}
		finder.Broadcast(diagnostic)
	}
}
