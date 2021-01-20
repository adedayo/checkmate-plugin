package secrets

import (
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/adedayo/checkmate-core/pkg/code"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

func TestFindSecret(t *testing.T) {
	type args struct {
		source                           io.Reader
		matcher                          MatchProvider
		extension                        string
		shouldProvideSourceInDiagnostics bool
	}
	tests := []struct {
		name      string
		value     string
		extension string
		provider  string
		evidences [3]diagnostics.Evidence
	}{
		{
			name:      "Assignment 1",
			value:     `pwd = "232d222x2324c2ecc2c2e"`,
			extension: ".java",
			provider:  assignmentProviderID,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.Medium},
				{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				{
					Description: descNotSecret,
					Confidence:  diagnostics.Low},
			},
		},

		{
			name:      "Assignment 2",
			value:     `crypt = "HbjZ!+{c]Y5!kNzB+-p^A6bCt(zNtf=V"`,
			extension: ".java",
			provider:  assignmentProviderID,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.High},
				{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				{
					Description: descHighEntropy,
					Confidence:  diagnostics.Medium},
			},
		},
		{
			name:      "Assignment 3",
			value:     `PassPhrase4 = "This should trigger a high"`,
			extension: ".java",
			provider:  assignmentProviderID,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.High},
				{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				{
					Description: descHardCodedSecret,
					Confidence:  diagnostics.High},
			},
		},
		{
			name:      "JSON Assignment 1",
			value:     `"Password": "This_is_A_{§pwd1"`,
			extension: ".json",
			provider:  jsonAssignmentProviderID,
			evidences: [3]diagnostics.Evidence{
				{
					Description: descHardCodedSecretAssignment,
					Confidence:  diagnostics.High},
				{
					Description: descVarSecret,
					Confidence:  diagnostics.High},
				{
					Description: descHighEntropy,
					Confidence:  diagnostics.Medium},
			},
		},
	}

	wl := diagnostics.MakeEmptyExcludes()
	path := "" // dummy path
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for got := range FindSecret(path, strings.NewReader(tt.value), GetFinderForFileType(tt.extension, path, wl), false) {
				want := makeDiagnostic(tt.value, tt.evidences, tt.provider)
				if !reflect.DeepEqual(got.Justification, want.Justification) {
					g, _ := json.MarshalIndent(got, "", " ")
					w, _ := json.MarshalIndent(want, "", " ")

					t.Errorf("FindSecret() = %s, \n\n ========want===========\n %s", string(g), string(w))
				}
			}
		})
	}
}

func makeDiagnostic(source string, evidences [3]diagnostics.Evidence, providerID string) diagnostics.SecurityDiagnostic {
	return diagnostics.SecurityDiagnostic{
		Justification: diagnostics.Justification{
			Headline: evidences[0],
			Reasons:  evidences[1:],
		},
		Range: code.Range{
			Start: code.Position{Line: 0, Character: 0},
			End:   code.Position{Line: 0, Character: int64(len(source) - 1)}},
		Source:     nil,
		ProviderID: &providerID}
}
