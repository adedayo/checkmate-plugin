package model

import (
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	pb "github.com/adedayo/checkmate-plugin/proto"
)

//ConvertWhitelistDefinition goes from protobuf struct to model
func ConvertWhitelistDefinition(wl *pb.WhitelistDefinition) *diagnostics.WhitelistDefinition {
	wld := &diagnostics.WhitelistDefinition{
		GloballyExcludedRegExs:  wl.GloballyExcludedRegExs,
		GloballyExcludedStrings: wl.GloballyExcludedStrings,
		PerFileExcludedStrings:  stringListMapConvert(wl.PerFileExcludedStrings),
		PathExclusionRegExs:     wl.PathExclusionRegExs,
		PathRegexExcludedRegExs: stringListMapConvert(wl.PathRegexExcludedRegExs),
	}

	return wld
}

//ConvertSecurityDiagnostic goes from protobuf struct to model
func ConvertSecurityDiagnostic(d *diagnostics.SecurityDiagnostic) *pb.SecurityDiagnostic {
	diagnostic := &pb.SecurityDiagnostic{
		Justification: convertJustification(d.Justification),
		Location:      *d.Location,
		ProviderId:    d.ProviderID,
		Source:        *d.Source,
		Range: &pb.Range{
			Start: &pb.Position{
				Line:      int32(d.Range.Start.Line),
				Character: int32(d.Range.Start.Character),
			},
			End: &pb.Position{
				Line:      int32(d.Range.End.Line),
				Character: int32(d.Range.End.Character),
			},
		},
	}
	return diagnostic
}

func convertJustification(j diagnostics.Justification) *pb.Justification {
	just := &pb.Justification{
		Headline: convertEvidence(j.Headline),
		Reasons:  convertEvidences(j.Reasons),
	}
	return just
}

func convertEvidences(es []diagnostics.Evidence) (evs []*pb.Evidence) {
	for _, e := range es {
		evs = append(evs, convertEvidence(e))
	}
	return
}

func convertEvidence(e diagnostics.Evidence) *pb.Evidence {
	ev := &pb.Evidence{
		Description: e.Description,
		Confidence:  pb.Confidence(e.Confidence),
	}

	return ev
}

func stringListMapConvert(pf map[string]*pb.StringList) map[string][]string {
	out := make(map[string][]string)
	for k, v := range pf {
		out[k] = v.Value
	}
	return out
}
