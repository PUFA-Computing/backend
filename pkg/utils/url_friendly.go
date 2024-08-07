package utils

import (
	"strings"
	"unicode"
)

// GenerateFriendlyURL generates a friendly URL from a title
func GenerateFriendlyURL(title string) string {
	var friendlyURL strings.Builder
	var lastCharNonAlphanumeric bool

	for _, char := range title {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			friendlyURL.WriteRune(unicode.ToLower(char))
			lastCharNonAlphanumeric = false
		} else if !lastCharNonAlphanumeric {
			friendlyURL.WriteRune('-')
			lastCharNonAlphanumeric = true
		}
	}

	result := friendlyURL.String()
	if strings.HasSuffix(result, "-") {
		result = strings.TrimSuffix(result, "-")
	}

	return result
}
