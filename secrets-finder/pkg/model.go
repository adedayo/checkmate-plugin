package secrets

import "github.com/adedayo/checkmate-core/pkg/diagnostics"

//SecretSearchOptions search options for the secret finder plugin
type SecretSearchOptions struct {
	ShowSource            bool
	Exclusions            diagnostics.ExclusionProvider
	ConfidentialFilesOnly bool
	CalculateChecksum     bool
}
