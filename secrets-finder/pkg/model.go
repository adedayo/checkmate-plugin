package secrets

import "github.com/adedayo/checkmate-core/pkg/diagnostics"

//SecretSearchOptions search options for the secret finder plugin
type SecretSearchOptions struct {
	ShowSource            bool
	Exclusions            diagnostics.ExclusionProvider
	ConfidentialFilesOnly bool
	CalculateChecksum     bool
	Verbose               bool //Verbose logging of file paths about to be scanned
	ReportIgnored         bool //if set, generate diagnostics for excluded files/paths and values
}
