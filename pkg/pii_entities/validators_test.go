package pii_entities

import "testing"

func TestValidateLuhn(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid visa", "4111111111111111", true},
		{"valid mastercard", "5500000000000004", true},
		{"valid amex", "378282246310005", true},
		{"valid with spaces", "4111 1111 1111 1111", true},
		{"valid with dashes", "4111-1111-1111-1111", true},
		{"valid with dots", "4111.1111.1111.1111", true},
		{"invalid last digit", "4111111111111112", false},
		{"invalid sequential", "1234567890123456", false},
		{"too short", "123456", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateLuhn(tt.input); got != tt.want {
				t.Errorf("validateLuhn(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateIBAN(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid GB", "GB29NWBK60161331926819", true},
		{"valid DE", "DE89370400440532013000", true},
		{"valid ES", "ES9121000418450200051332", true},
		{"valid lowercase", "gb29nwbk60161331926819", true},
		{"valid with spaces", "GB29 NWBK 6016 1331 9268 19", true},
		{"invalid check digits", "GB00NWBK60161331926819", false},
		{"too short", "GB29", false},
		{"invalid country AB", "AB12345670", false},
		{"invalid country XX", "XX12345678901234", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateIBAN(tt.input); got != tt.want {
				t.Errorf("validateIBAN(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateSpanishDNI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// 12345678 % 23 = 14 → Z
		{"valid 12345678Z", "12345678Z", true},
		// 00000001 % 23 = 1 → R
		{"valid 00000001R", "00000001R", true},
		{"valid with separators", "12.345.678-Z", true},
		{"valid lowercase", "12345678z", true},
		{"invalid letter", "12345678A", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateSpanishDNI(tt.input); got != tt.want {
				t.Errorf("validateSpanishDNI(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateSpanishNIE(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// X→0: 01234567 % 23 = 19 → L
		{"valid X1234567L", "X1234567L", true},
		{"valid lowercase", "x1234567l", true},
		{"invalid letter", "X1234567Z", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateSpanishNIE(tt.input); got != tt.want {
				t.Errorf("validateSpanishNIE(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateBrazilianCPF(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid with separators", "123.456.789-09", true},
		{"valid compact", "12345678909", true},
		{"invalid check digits", "123.456.789-00", false},
		{"all same digits", "11111111111", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateBrazilianCPF(tt.input); got != tt.want {
				t.Errorf("validateBrazilianCPF(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateBrazilianCNPJ(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid with separators", "12.345.678/0001-95", true},
		{"valid compact", "12345678000195", true},
		{"invalid check digits", "12.345.678/0001-00", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateBrazilianCNPJ(tt.input); got != tt.want {
				t.Errorf("validateBrazilianCNPJ(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateChileanRUT(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// 12345678: 8*2+7*3+6*4+5*5+4*6+3*7+2*2+1*3=138; 138%11=6; 11-6=5
		{"valid with separators", "12.345.678-5", true},
		{"valid compact", "123456785", true},
		// 32345678: sum=144; 144%11=1; 11-1=10 → K
		{"valid K check digit", "32.345.678-K", true},
		{"valid K lowercase", "32345678-k", true},
		{"invalid check", "12.345.678-0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateChileanRUT(tt.input); got != tt.want {
				t.Errorf("validateChileanRUT(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateSSN(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid standard", "123-45-6789", true},
		{"valid compact", "123456789", true},
		{"valid with dots", "123.45.6789", true},
		{"valid area 987", "987-65-4321", true},
		{"area 000 invalid", "000-12-3456", false},
		{"group 00 invalid", "123-00-6789", false},
		{"serial 0000 invalid", "123-45-0000", false},
		{"too short", "12345678", false},
		{"too long", "1234567890", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateSSN(tt.input); got != tt.want {
				t.Errorf("validateSSN(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateIMEI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid IMEI", "490154203237518", true},
		{"valid IMEI 2", "356938035643809", true},
		{"invalid Luhn", "490154203237510", false},
		{"too short 14 digits", "49015420323751", false},
		{"too long 18 digits", "490154203237518123", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateIMEI(tt.input); got != tt.want {
				t.Errorf("validateIMEI(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateSpanishPhone(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"9 digits no prefix", "612345678", true},
		{"9 digits with spaces", "612 34 56 78", true},
		{"9 digits with dashes", "612-345-678", true},
		{"9 digits with dots", "612.345.678", true},
		{"+34 prefix compact", "+34612345678", true},
		{"+34 prefix with spaces", "+34 612 34 56 78", true},
		{"0034 prefix compact", "0034612345678", true},
		{"0034 prefix with spaces", "0034 612 34 56 78", true},
		{"too few digits", "61234567", false},
		{"too many digits", "6123456789", false},
		{"wrong prefix digits", "+33612345678", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateSpanishPhone(tt.input); got != tt.want {
				t.Errorf("validateSpanishPhone(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCountryPhoneValidators(t *testing.T) {
	tests := []struct {
		name   string
		fn     func(string) bool
		digits string
		want   bool
	}{
		// US
		{"US 10 digits", phoneMatchesUS, "2125551234", true},
		{"US 11 digits +1", phoneMatchesUS, "12125551234", true},
		{"US bad area 0xx", phoneMatchesUS, "0125551234", false},
		{"US 9 digits", phoneMatchesUS, "212555123", false},

		// UK
		{"UK 11 digits 07", phoneMatchesUK, "07911123456", true},
		{"UK 10 digits 02", phoneMatchesUK, "0207946000", true},
		{"UK +44", phoneMatchesUK, "447911123456", true},
		{"UK 0044", phoneMatchesUK, "00447911123456", true},
		{"UK bad start", phoneMatchesUK, "1234567890", false},

		// FR
		{"FR 10 digits", phoneMatchesFR, "0612345678", true},
		{"FR +33", phoneMatchesFR, "33612345678", true},
		{"FR 0033", phoneMatchesFR, "0033612345678", true},
		{"FR bad start", phoneMatchesFR, "1234567890", false},

		// DE
		{"DE mobile 11d", phoneMatchesDE, "01711234567", true},
		{"DE landline 10d", phoneMatchesDE, "0301234567", true},
		{"DE +49", phoneMatchesDE, "491711234567", true},
		{"DE 0049", phoneMatchesDE, "00491711234567", true},

		// IT
		{"IT mobile 10d", phoneMatchesIT, "3331234567", true},
		{"IT landline 10d", phoneMatchesIT, "0612345678", true},
		{"IT +39", phoneMatchesIT, "393331234567", true},

		// PT
		{"PT 9 digits mobile", phoneMatchesPT, "912345678", true},
		{"PT 9 digits landline", phoneMatchesPT, "212345678", true},
		{"PT +351", phoneMatchesPT, "351912345678", true},
		{"PT bad start", phoneMatchesPT, "512345678", false},

		// BR
		{"BR 11 digits mobile", phoneMatchesBR, "11987654321", true},
		{"BR 10 digits landline", phoneMatchesBR, "1134567890", true},
		{"BR +55", phoneMatchesBR, "5511987654321", true},

		// MX
		{"MX 10 digits", phoneMatchesMX, "5512345678", true},
		{"MX +52", phoneMatchesMX, "525512345678", true},
		{"MX 9 digits", phoneMatchesMX, "551234567", false},

		// AR
		{"AR 10 digits", phoneMatchesAR, "1112345678", true},
		{"AR +54", phoneMatchesAR, "541112345678", true},

		// CO
		{"CO mobile 3xx", phoneMatchesCO, "3101234567", true},
		{"CO landline 6xx", phoneMatchesCO, "6012345678", true},
		{"CO +57", phoneMatchesCO, "573101234567", true},
		{"CO bad start", phoneMatchesCO, "1234567890", false},

		// CL
		{"CL mobile 9d", phoneMatchesCL, "912345678", true},
		{"CL landline 9d", phoneMatchesCL, "212345678", true},
		{"CL +56", phoneMatchesCL, "56912345678", true},
		{"CL bad start", phoneMatchesCL, "512345678", false},

		// ES (via generic)
		{"ES 9 digits", phoneMatchesES, "612345678", true},
		{"ES +34", phoneMatchesES, "34612345678", true},
		{"ES 0034", phoneMatchesES, "0034612345678", true},
		{"ES bad start 5", phoneMatchesES, "512345678", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fn(tt.digits); got != tt.want {
				t.Errorf("%s(%q) = %v, want %v", tt.name, tt.digits, got, tt.want)
			}
		})
	}
}

func TestValidatePhoneNumber(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Country-specific matches (cascade)
		{"US international", "+1 555-123-4567", true},
		{"ES compact", "+34612345678", true},
		{"US local", "555-123-4567", true},
		{"US with parens", "(555) 123-4567", true},
		{"UK mobile", "+44 7911 123456", true},
		{"FR mobile", "+33 6 12 34 56 78", true},
		{"DE mobile", "+49 171 1234567", true},
		{"BR mobile", "+55 11 98765-4321", true},
		{"ES with spaces", "612 34 56 78", true},

		// Generic fallback (enough digits, not a date)
		{"generic 7 digits", "1234567", true},
		{"generic 8 digits", "12345678", true},

		// Rejections
		{"date YYYY-MM-DD", "2024-07-18", false},
		{"date YYYY/MM/DD", "2026/08/14", false},
		{"date DD.MM.YYYY", "18.07.2024", false},
		{"date DD-MM-YYYY", "18-07-2024", false},
		{"too few digits", "12-34-56", false},
		{"too few digits short", "123-456", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validatePhoneNumber(tt.input); got != tt.want {
				t.Errorf("validatePhoneNumber(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLuhnCheckDigits(t *testing.T) {
	tests := []struct {
		name   string
		digits string
		want   bool
	}{
		{"valid CC", "4111111111111111", true},
		{"invalid CC", "4111111111111112", false},
		{"valid IMEI 15 digits", "490154203237518", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := luhnCheckDigits(tt.digits); got != tt.want {
				t.Errorf("luhnCheckDigits(%q) = %v, want %v", tt.digits, got, tt.want)
			}
		})
	}
}
