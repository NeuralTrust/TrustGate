package pii_entities

import (
	"regexp"
	"strconv"
	"strings"
)

func normalizeForValidation(s string) string {
	s = strings.ToUpper(s)
	s = strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || r == '/' || r == ' ' {
			return -1
		}
		return r
	}, s)
	return s
}

func extractDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhnCheckDigits performs the Luhn algorithm on a string of digit characters.
func luhnCheckDigits(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// validateLuhn verifies a credit card number using the Luhn algorithm.
func validateLuhn(s string) bool {
	digits := extractDigits(s)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	return luhnCheckDigits(digits)
}

// validateIMEI checks the Luhn check digit on the first 15 digits of an IMEI.
func validateIMEI(s string) bool {
	digits := extractDigits(s)
	if len(digits) < 15 || len(digits) > 17 {
		return false
	}
	return luhnCheckDigits(digits[:15])
}

// validateSSN rejects structurally impossible SSN values.
func validateSSN(s string) bool {
	digits := extractDigits(s)
	if len(digits) != 9 {
		return false
	}
	area, _ := strconv.Atoi(digits[0:3])
	group, _ := strconv.Atoi(digits[3:5])
	serial, _ := strconv.Atoi(digits[5:9])
	if area == 0 {
		return false
	}
	if group == 0 {
		return false
	}
	if serial == 0 {
		return false
	}
	return true
}

// validateIBAN verifies an IBAN using an ISO 3166-1 country code pre-filter
// followed by the ISO 7064 mod-97 check.
func validateIBAN(s string) bool {
	normalized := normalizeForValidation(s)
	if len(normalized) < 5 || len(normalized) > 34 {
		return false
	}
	if normalized[0] < 'A' || normalized[0] > 'Z' ||
		normalized[1] < 'A' || normalized[1] > 'Z' {
		return false
	}
	if !validISO3166Alpha2[normalized[0:2]] {
		return false
	}
	rearranged := normalized[4:] + normalized[:4]
	remainder := 0
	for _, ch := range rearranged {
		if ch >= 'A' && ch <= 'Z' {
			val := int(ch - 'A' + 10)
			remainder = (remainder*10 + val/10) % 97
			remainder = (remainder*10 + val%10) % 97
		} else if ch >= '0' && ch <= '9' {
			remainder = (remainder*10 + int(ch-'0')) % 97
		}
	}
	return remainder == 1
}

const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// validateSpanishDNI verifies that the trailing letter matches the number mod 23.
func validateSpanishDNI(s string) bool {
	normalized := normalizeForValidation(s)
	if len(normalized) < 2 {
		return false
	}
	letter := normalized[len(normalized)-1]
	digits := extractDigits(normalized)
	if len(digits) != 8 {
		return false
	}
	num := 0
	for _, d := range digits {
		num = num*10 + int(d-'0')
	}
	expected := dniLetters[num%23]
	return letter == expected
}

// validateSpanishNIE replaces the X/Y/Z prefix with 0/1/2 and applies the DNI check.
func validateSpanishNIE(s string) bool {
	normalized := normalizeForValidation(s)
	if len(normalized) < 2 {
		return false
	}
	prefix := normalized[0]
	var replacement byte
	switch prefix {
	case 'X':
		replacement = '0'
	case 'Y':
		replacement = '1'
	case 'Z':
		replacement = '2'
	default:
		return false
	}
	converted := string(replacement) + normalized[1:]
	return validateSpanishDNI(converted)
}

// validateBrazilianCPF verifies the two check digits of a CPF number.
func validateBrazilianCPF(s string) bool {
	digits := extractDigits(s)
	if len(digits) != 11 {
		return false
	}
	allSame := true
	for i := 1; i < len(digits); i++ {
		if digits[i] != digits[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}

	d := make([]int, 11)
	for i := range digits {
		d[i] = int(digits[i] - '0')
	}

	sum := 0
	for i := 0; i < 9; i++ {
		sum += d[i] * (10 - i)
	}
	rem := sum % 11
	c1 := 0
	if rem >= 2 {
		c1 = 11 - rem
	}
	if d[9] != c1 {
		return false
	}

	sum = 0
	for i := 0; i < 10; i++ {
		sum += d[i] * (11 - i)
	}
	rem = sum % 11
	c2 := 0
	if rem >= 2 {
		c2 = 11 - rem
	}
	return d[10] == c2
}

// validateBrazilianCNPJ verifies the two check digits of a CNPJ number.
func validateBrazilianCNPJ(s string) bool {
	digits := extractDigits(s)
	if len(digits) != 14 {
		return false
	}
	d := make([]int, 14)
	for i := range digits {
		d[i] = int(digits[i] - '0')
	}

	weights1 := []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += d[i] * weights1[i]
	}
	rem := sum % 11
	c1 := 0
	if rem >= 2 {
		c1 = 11 - rem
	}
	if d[12] != c1 {
		return false
	}

	weights2 := []int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	sum = 0
	for i := 0; i < 13; i++ {
		sum += d[i] * weights2[i]
	}
	rem = sum % 11
	c2 := 0
	if rem >= 2 {
		c2 = 11 - rem
	}
	return d[13] == c2
}

// validateChileanRUT verifies the modulo-11 check digit (including K).
func validateChileanRUT(s string) bool {
	normalized := normalizeForValidation(s)
	if len(normalized) < 2 {
		return false
	}
	checkChar := normalized[len(normalized)-1]
	body := extractDigits(normalized[:len(normalized)-1])
	if len(body) < 1 || len(body) > 8 {
		return false
	}

	sum := 0
	weight := 2
	for i := len(body) - 1; i >= 0; i-- {
		sum += int(body[i]-'0') * weight
		weight++
		if weight > 7 {
			weight = 2
		}
	}
	rem := sum % 11
	check := 11 - rem

	var expected byte
	switch check {
	case 11:
		expected = '0'
	case 10:
		expected = 'K'
	default:
		expected = byte('0' + check)
	}
	return checkChar == expected
}

// swiftBICBlocklist contains English words that happen to embed a valid ISO
// country code at positions 4-5 and therefore pass the country code check.
// Kept as secondary defense after the country code validation.
var swiftBICBlocklist = map[string]bool{
	"ABSOLUTE": true, "DELIVERY": true, "STRENGTH": true,
	"NATIONAL": true, "EXCHANGE": true, "INTEREST": true,
	"PERSONAL": true, "WHATEVER": true, "YOURSELF": true,
	"THOUSAND": true, "TOGETHER": true, "POSSIBLE": true,
	"SCHEDULE": true, "STANDARD": true, "ANYTHING": true,
	"AUDIENCE": true, "BUILDING": true, "BUSINESS": true,
	"CHILDREN": true, "COMPLETE": true, "CONSIDER": true,
	"CONTINUE": true, "CUSTOMER": true, "EVERYONE": true,
	"EVIDENCE": true, "EXERCISE": true, "FUNCTION": true,
	"MATERIAL": true, "OVERVIEW": true, "PHYSICAL": true,
	"PLANNING": true, "PLATFORM": true, "PRACTICE": true,
	"PROBLEMS": true, "PROGRESS": true, "PROPERTY": true,
	"QUESTION": true, "REMEMBER": true, "REQUIRES": true,
	"RESEARCH": true, "RESOURCE": true, "RESPONSE": true,
	"CHAPTERS": true, "SECURITY": true, "SOFTWARE": true,
	"SOLUTION": true, "STRATEGY": true, "STUDENTS": true,
	"THINKING": true, "TRAINING": true,
	"APPLICATION": true, "COMFORTABLE": true, "COMPETITIVE": true,
	"DEVELOPMENT": true, "ENVIRONMENT": true, "INDEPENDENT": true,
	"INFORMATION": true, "PERFORMANCE": true, "ALTERNATIVE": true,
	"COMBINATION": true, "EDUCATIONAL": true, "ENGINEERING": true,
	"ESTABLISHED": true, "PARTNERSHIP": true, "PERSPECTIVE": true,
	"SIGNIFICANT": true, "TEMPERATURE": true, "TRADITIONAL": true,
	"SPRINGFIELD": true,
}

// validateSwiftBIC checks that the match has a valid ISO country code at
// positions 4-5 (BIC structure: BBBBCCLL[BBB]), then rejects known English
// words that happen to embed a valid country code.
func validateSwiftBIC(s string) bool {
	upper := strings.ToUpper(strings.TrimSpace(s))
	if len(upper) != 8 && len(upper) != 11 {
		return false
	}
	if !validISO3166Alpha2[upper[4:6]] {
		return false
	}
	return !swiftBICBlocklist[upper]
}

var dateLikePattern = regexp.MustCompile(`^\+?\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}$`)

const minPhoneDigits = 7

// validatePhoneNumber rejects matches with fewer than 7 digits or that look
// like a date (e.g. 2024-07-18, 18/07/2024).
func validatePhoneNumber(s string) bool {
	if len(extractDigits(s)) < minPhoneDigits {
		return false
	}
	return !dateLikePattern.MatchString(strings.TrimSpace(s))
}

// validISO3166Alpha2 contains all ISO 3166-1 alpha-2 country codes.
// Used by both validateIBAN (country pre-filter) and validateSwiftBIC.
var validISO3166Alpha2 = map[string]bool{
	"AD": true, "AE": true, "AF": true, "AG": true, "AI": true,
	"AL": true, "AM": true, "AO": true, "AQ": true, "AR": true,
	"AS": true, "AT": true, "AU": true, "AW": true, "AX": true,
	"AZ": true, "BA": true, "BB": true, "BD": true, "BE": true,
	"BF": true, "BG": true, "BH": true, "BI": true, "BJ": true,
	"BL": true, "BM": true, "BN": true, "BO": true, "BQ": true,
	"BR": true, "BS": true, "BT": true, "BV": true, "BW": true,
	"BY": true, "BZ": true, "CA": true, "CC": true, "CD": true,
	"CF": true, "CG": true, "CH": true, "CI": true, "CK": true,
	"CL": true, "CM": true, "CN": true, "CO": true, "CR": true,
	"CU": true, "CV": true, "CW": true, "CX": true, "CY": true,
	"CZ": true, "DE": true, "DJ": true, "DK": true, "DM": true,
	"DO": true, "DZ": true, "EC": true, "EE": true, "EG": true,
	"EH": true, "ER": true, "ES": true, "ET": true, "FI": true,
	"FJ": true, "FK": true, "FM": true, "FO": true, "FR": true,
	"GA": true, "GB": true, "GD": true, "GE": true, "GF": true,
	"GG": true, "GH": true, "GI": true, "GL": true, "GM": true,
	"GN": true, "GP": true, "GQ": true, "GR": true, "GS": true,
	"GT": true, "GU": true, "GW": true, "GY": true, "HK": true,
	"HM": true, "HN": true, "HR": true, "HT": true, "HU": true,
	"ID": true, "IE": true, "IL": true, "IM": true, "IN": true,
	"IO": true, "IQ": true, "IR": true, "IS": true, "IT": true,
	"JE": true, "JM": true, "JO": true, "JP": true, "KE": true,
	"KG": true, "KH": true, "KI": true, "KM": true, "KN": true,
	"KP": true, "KR": true, "KW": true, "KY": true, "KZ": true,
	"LA": true, "LB": true, "LC": true, "LI": true, "LK": true,
	"LR": true, "LS": true, "LT": true, "LU": true, "LV": true,
	"LY": true, "MA": true, "MC": true, "MD": true, "ME": true,
	"MF": true, "MG": true, "MH": true, "MK": true, "ML": true,
	"MM": true, "MN": true, "MO": true, "MP": true, "MQ": true,
	"MR": true, "MS": true, "MT": true, "MU": true, "MV": true,
	"MW": true, "MX": true, "MY": true, "MZ": true, "NA": true,
	"NC": true, "NE": true, "NF": true, "NG": true, "NI": true,
	"NL": true, "NO": true, "NP": true, "NR": true, "NU": true,
	"NZ": true, "OM": true, "PA": true, "PE": true, "PF": true,
	"PG": true, "PH": true, "PK": true, "PL": true, "PM": true,
	"PN": true, "PR": true, "PS": true, "PT": true, "PW": true,
	"PY": true, "QA": true, "RE": true, "RO": true, "RS": true,
	"RU": true, "RW": true, "SA": true, "SB": true, "SC": true,
	"SD": true, "SE": true, "SG": true, "SH": true, "SI": true,
	"SJ": true, "SK": true, "SL": true, "SM": true, "SN": true,
	"SO": true, "SR": true, "SS": true, "ST": true, "SV": true,
	"SX": true, "SY": true, "SZ": true, "TC": true, "TD": true,
	"TF": true, "TG": true, "TH": true, "TJ": true, "TK": true,
	"TL": true, "TM": true, "TN": true, "TO": true, "TR": true,
	"TT": true, "TV": true, "TW": true, "TZ": true, "UA": true,
	"UG": true, "UM": true, "US": true, "UY": true, "UZ": true,
	"VA": true, "VC": true, "VE": true, "VG": true, "VI": true,
	"VN": true, "VU": true, "WF": true, "WS": true, "XK": true,
	"YE": true, "YT": true, "ZA": true, "ZM": true, "ZW": true,
}
