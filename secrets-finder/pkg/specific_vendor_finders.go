package secrets

import (
	"fmt"
	"regexp"

	common "github.com/adedayo/checkmate-core/pkg"
)

/**
Higher recall/confidence patterns from vendors and other well-known secret patterns
*/

var (
	//https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
	//https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available/
	githubRegex     = fmt.Sprintf(`(?i:(gh[pousr]_[A-Za-z0-9_]{%d,255}))`, 36) // Current min is 40 chars hence 36 = 40-len(gho_),
	descGithubToken = "GitHub Authentication Token"

	//https://api.slack.com/authentication/token-types
	slackRegex     = fmt.Sprintf(`(?i:(xox[apbr]-2?[A-Za-z0-9-]{%d,}))`, 24) //examples here https://api.slack.com/authentication/basics longer than 24 chars,
	descSlackToken = "Slack Bot/User Token"

	//https://stripe.com/docs/api
	stripeRegex     = fmt.Sprintf(`(?i:(?:sk_(?:live|test)|whsec)_[A-Za-z0-9-]{%d,})`, 24) //examples here https://stripe.com/docs/api/authentication longer than 24 chars,
	descStripeToken = "Stripe Token"

	//https://developer.gocardless.com/api-reference/#oauth-disconnecting-a-user-from-your-app
	goCardlessRegex     = fmt.Sprintf(`(?i:(live_[A-Za-z0-9_-]{%d,255}))`, 20) //
	descGoCardlessToken = "GoCardless Token"

	vendorSecretPatterns = map[string]string{
		descGithubToken:     githubRegex,
		descSlackToken:      slackRegex,
		descStripeToken:     stripeRegex,
		descGoCardlessToken: goCardlessRegex,
	}
)

func makeVendorSecretsFinders(options SecretSearchOptions) (out []common.ResourceToSecurityDiagnostics) {

	for id, re := range vendorSecrets {
		sf := secretStringFinder{
			secretFinder{
				ExclusionProvider: options.Exclusions,
				options:           options,
			},
		}
		sf.providerID = id
		sf.res = []*regexp.Regexp{re}
		out = append(out, &sf)
	}
	return
}
