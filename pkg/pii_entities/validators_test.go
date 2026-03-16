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

func TestValidateSwiftBIC(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid 8-char", "DEUTDEFF", true},
		{"valid 11-char", "BNPAFRPPXXX", true},
		{"valid DEUTDEFF500", "DEUTDEFF500", true},
		{"blocklisted CHAPTERS", "CHAPTERS", false},
		{"blocklisted DELIVERY", "DELIVERY", false},
		{"blocklisted STRENGTH", "STRENGTH", false},
		{"blocklisted ABSOLUTE", "ABSOLUTE", false},
		{"blocklisted lowercase", "chapters", false},
		{"valid lowercase bic", "deutdeff", true},
		{"invalid country code TE", "BANKTEXX", false},
		{"invalid length 7", "DEUTDEF", false},
		{"invalid length 9", "DEUTDEFFX", false},
		{"SPRINGFIELD blocked", "SPRINGFIELD", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateSwiftBIC(tt.input); got != tt.want {
				t.Errorf("validateSwiftBIC(%q) = %v, want %v", tt.input, got, tt.want)
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

func TestValidatePhoneNumber(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"international with plus", "+1 555-123-4567", true},
		{"international compact", "+34612345678", true},
		{"local US", "555-123-4567", true},
		{"with parens", "(555) 123-4567", true},
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
