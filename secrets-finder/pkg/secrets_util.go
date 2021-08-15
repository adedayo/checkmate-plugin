package secrets

import (
	"fmt"
	"math"
	"strings"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

var (
	entropyCutoff = 0.8 //80% of maximum achievable entropy as a cutoff to determine if string is a secret
)

func detectSecret(secret string) (evidence diagnostics.Evidence) {
	evidence.Description = descSuspiciousSecret
	evidence.Confidence = diagnostics.Low
	secret = strings.TrimSpace(secret)
	data := strings.ToLower(secret)
	if data == "" ||
		//secrets seldom start with http or urn:
		strings.HasPrefix(data, "http") || strings.HasPrefix(data, "urn:") ||
		//spaces are unusual to be found in passwords/secrets
		space.FindStringSubmatchIndex(data) != nil ||
		//anecdotal passwords in config don't typically start with these characters,
		//and if it does but is longer than 45 characters, they probably are security-minded
		//and will know not to put secrets in plaintext, so assume not a secret!
		(strings.Contains(unusualPasswordStartCharacters, string(data[0])) && len(data) > 45) {
		evidence.Description = descNotSecret
		evidence.Confidence = diagnostics.High
	} else if description, isVendor := isVendorSecret(data); isVendor {
		evidence.Description = description
		evidence.Confidence = diagnostics.High
	} else if isCommonSecret(data) {
		evidence.Description = descCommonSecret
		evidence.Confidence = diagnostics.High
	} else if length := float64(len(secret)); length > float64(minSecretLength) && length <= 256 &&
		getShannonEntropy(secret) > entropyCutoff*math.Log2(length) && digit.FindStringSubmatchIndex(secret) != nil {
		//for strings up to 64 characters in length, check that the entropy is at most half the maximum entropy possible for that data
		//also check that there is at least a number in the secret
		evidence.Description = descHighEntropy
		evidence.Confidence = diagnostics.Medium
	} else if isEncodedSecret(data) {
		evidence.Description = descEncodedSecret
		evidence.Confidence = diagnostics.High
	} else if validateSpecial(secret) {
		evidence.Description = descSuspiciousSecret
		evidence.Confidence = diagnostics.Medium
	} else if validate(secret) {
		evidence.Description = descSuspiciousSecret
		evidence.Confidence = diagnostics.Medium
	}
	return
}

func isVendorSecret(data string) (description string, isVendor bool) {
	for desc, re := range vendorSecrets {
		if re.FindStringSubmatchIndex(data) != nil {
			return desc, true
		}
	}

	return
}

func isCommonSecret(data string) bool {
	for _, re := range commonSecrets {
		if re.FindStringSubmatchIndex(data) != nil {
			return true
		}
	}
	return false
}
func isEncodedSecret(data string) bool {
	for _, re := range encodedSecrets {
		if re.MatchString(data) {
			return true
		}
	}
	return false
}

func validateSpecial(data string) bool {
	if len(data) >= minSecretLength && special.FindStringSubmatchIndex(data) != nil &&
		upperCase.FindStringSubmatchIndex(data) != nil &&
		lowerCase.FindStringSubmatchIndex(data) != nil &&
		digit.FindStringSubmatchIndex(data) != nil &&
		space.FindStringSubmatchIndex(data) == nil {
		return true
	}
	return false
}
func validate(data string) bool {
	if length := len(data); length >= minSecretLength && length <= 256 &&
		upperCase.FindStringSubmatchIndex(data) != nil &&
		lowerCase.FindStringSubmatchIndex(data) != nil &&
		digit.FindStringSubmatchIndex(data) != nil &&
		space.FindStringSubmatchIndex(data) == nil {
		return true
	}
	return false
}

func getShannonEntropy(data string) float64 {
	var entropy float64
	m := make(map[rune]float64)
	for _, c := range data {
		m[c]++
	}
	if n := float64(len(data)); n > 0 {
		for _, r := range m {
			px := r / n
			entropy += px * math.Log2(px)
		}
		return -entropy
	}
	return entropy
}

type stack struct {
	data []string
}

func (s *stack) push(x string) {
	s.data = append(s.data, x)
}

func (s *stack) pop() (out string, err error) {
	if len(s.data) == 0 {
		return "", fmt.Errorf("Popping an empty stack")
	}
	index := len(s.data) - 1
	out = s.data[index]
	s.data = s.data[0:index]

	return out, nil
}

func (s *stack) peek() (out string, err error) {
	if len(s.data) == 0 {
		return "", fmt.Errorf("Peeking an empty stack")
	}
	index := len(s.data) - 1
	out = s.data[index]

	return out, nil
}
