package pii_entities

import (
	"strings"
	"testing"
)

func allEntitiesEnabled() map[Entity]bool {
	m := make(map[Entity]bool, len(Entities))
	for e := range Entities {
		m[e] = true
	}
	return m
}

func enableOnly(entities ...Entity) map[Entity]bool {
	m := make(map[Entity]bool, len(entities))
	for _, e := range entities {
		m[e] = true
	}
	return m
}

func findMatch(matches []Match, entity Entity) *Match {
	for i := range matches {
		if matches[i].Entity == entity {
			return &matches[i]
		}
	}
	return nil
}

func TestDetectAll_EmptyContent(t *testing.T) {
	matches := DetectAll("", allEntitiesEnabled())
	if matches != nil {
		t.Errorf("expected nil for empty content, got %v", matches)
	}
}

func TestDetectAll_OverLimitContent(t *testing.T) {
	huge := strings.Repeat("a", MaxDetectContentLength+1)
	matches := DetectAll(huge, allEntitiesEnabled())
	if matches != nil {
		t.Errorf("expected nil for over-limit content, got %d matches", len(matches))
	}
}

func TestDetectAll_DisabledEntities(t *testing.T) {
	matches := DetectAll("test@example.com", enableOnly(SSN))
	if findMatch(matches, Email) != nil {
		t.Error("email should not be detected when disabled")
	}
}

func TestDetectAll_TierPriority_NonOverlapping(t *testing.T) {
	content := "Email test@example.com, SSN 123-45-6789"
	matches := DetectAll(content, enableOnly(Email, SSN))
	emailMatch := findMatch(matches, Email)
	ssnMatch := findMatch(matches, SSN)
	if emailMatch == nil {
		t.Error("expected email to be detected")
	}
	if ssnMatch == nil {
		t.Error("expected SSN to be detected")
	}
	if emailMatch != nil && emailMatch.Value != "test@example.com" {
		t.Errorf("email value = %q, want %q", emailMatch.Value, "test@example.com")
	}
	if ssnMatch != nil && ssnMatch.Value != "123-45-6789" {
		t.Errorf("SSN value = %q, want %q", ssnMatch.Value, "123-45-6789")
	}
}

func TestDetectAll_CrossTierDisambiguation_IBAN_over_BankAccount(t *testing.T) {
	content := "IBAN: GB29NWBK60161331926819"
	matches := DetectAll(content, enableOnly(IBAN, BankAccount))
	ibanMatch := findMatch(matches, IBAN)
	bankMatch := findMatch(matches, BankAccount)
	if ibanMatch == nil {
		t.Error("expected IBAN to be detected")
	}
	if bankMatch != nil {
		t.Error("BankAccount should not be detected when IBAN claims the region")
	}
}

func TestDetectAll_WithinTierSuperset_MedicareBeforeSSN(t *testing.T) {
	content := "Medicare: 123-45-6789A"
	matches := DetectAll(content, enableOnly(USMedicareID, SSN))
	medicareMatch := findMatch(matches, USMedicareID)
	if medicareMatch == nil {
		t.Error("expected USMedicareID to be detected")
	}
	ssnMatch := findMatch(matches, SSN)
	if ssnMatch != nil {
		t.Error("SSN should not be detected when MedicareID claims the overlapping region")
	}
}

func TestDetectAll_ValidatorRejectionFallthrough(t *testing.T) {
	// 1234567890123456 fails Luhn → CreditCard rejects → BankAccount (Tier 3) claims
	content := "Number: 1234567890123456"
	matches := DetectAll(content, enableOnly(CreditCard, BankAccount))
	ccMatch := findMatch(matches, CreditCard)
	bankMatch := findMatch(matches, BankAccount)
	if ccMatch != nil {
		t.Error("CreditCard should be rejected by Luhn validator")
	}
	if bankMatch == nil {
		t.Error("expected BankAccount to claim the region after CreditCard rejection")
	}
}

func TestDetectAll_BitmapOverlapBlocking(t *testing.T) {
	content := "password= secret123-45-6789"
	matches := DetectAll(content, enableOnly(Password, SSN))
	pwMatch := findMatch(matches, Password)
	if pwMatch == nil {
		t.Fatal("expected Password to be detected")
	}
	ssnMatch := findMatch(matches, SSN)
	if ssnMatch != nil {
		t.Error("SSN should be blocked by Password's bitmap claim")
	}
}

func TestDetectAll_MultiPII(t *testing.T) {
	content := "Email test@a.com, SSN 123-45-6789"
	matches := DetectAll(content, enableOnly(Email, SSN))
	if len(matches) < 2 {
		t.Errorf("expected at least 2 matches, got %d", len(matches))
	}
	if findMatch(matches, Email) == nil {
		t.Error("expected Email match")
	}
	if findMatch(matches, SSN) == nil {
		t.Error("expected SSN match")
	}
}

func TestDetectAll_RepeatedSameEntity(t *testing.T) {
	content := "SSN 123-45-6789 and 987-65-4321"
	matches := DetectAll(content, enableOnly(SSN))
	count := 0
	for _, m := range matches {
		if m.Entity == SSN {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 SSN matches, got %d", count)
	}
}

func TestDetectAll_TierOrderGuarantee(t *testing.T) {
	// Results are in tier order (Tier 1 before Tier 2), not byte-position order.
	// Email (Tier 1) at position 26 appears before SSN (Tier 2) at position 4.
	content := "SSN 123-45-6789 and email test@a.com"
	matches := DetectAll(content, enableOnly(SSN, Email))
	if len(matches) < 2 {
		t.Fatalf("expected at least 2 matches, got %d", len(matches))
	}
	if matches[0].Entity != Email {
		t.Errorf("first match should be Email (Tier 1), got %s", matches[0].Entity)
	}
	if matches[1].Entity != SSN {
		t.Errorf("second match should be SSN (Tier 2), got %s", matches[1].Entity)
	}
}

func TestDetectAll_ValidCreditCard(t *testing.T) {
	content := "Card: 4111 1111 1111 1111"
	matches := DetectAll(content, enableOnly(CreditCard))
	ccMatch := findMatch(matches, CreditCard)
	if ccMatch == nil {
		t.Error("expected CreditCard to be detected (passes Luhn)")
	}
}

func TestDetectAll_DateNotDetectedAsPhone(t *testing.T) {
	dates := []string{
		"2024-07-18",
		"2026-08-14",
		"18/07/2024",
		"14.08.2026",
		"01-12-2025",
	}
	for _, d := range dates {
		t.Run(d, func(t *testing.T) {
			matches := DetectAll("given at "+d, enableOnly(PhoneNumber, Date))
			if phoneMatch := findMatch(matches, PhoneNumber); phoneMatch != nil {
				t.Errorf("date %q was detected as phone_number (value=%q)", d, phoneMatch.Value)
			}
		})
	}
}

func TestDetectAll_SpanishPhoneWithSpaces(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"compact", "llama al 612345678 ahora", "612345678"},
		{"spaces 3-2-2-2", "llama al 612 34 56 78 ahora", "612 34 56 78"},
		{"spaces 3-3-3", "llama al 612 345 678 ahora", "612 345 678"},
		{"dashes", "llama al 612-34-56-78 ahora", "612-34-56-78"},
		{"with +34", "llama al +34 612 34 56 78 ahora", "+34 612 34 56 78"},
		{"with 0034", "llama al 0034 612 34 56 78 ahora", "0034 612 34 56 78"},
		{"in markdown bold", "**612 34 56 78**", "612 34 56 78"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectAll(tt.content, enableOnly(SpanishPhone))
			m := findMatch(matches, SpanishPhone)
			if m == nil {
				t.Fatalf("expected SpanishPhone match for %q", tt.content)
			}
			if m.Value != tt.want {
				t.Errorf("SpanishPhone value = %q, want %q", m.Value, tt.want)
			}
		})
	}
}

func TestDetectAll_PhoneNumberMultiGroup(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"US with dashes", "call 555-123-4567", "555-123-4567"},
		{"US with parens", "call (212) 555-1234", "(212) 555-1234"},
		{"intl with spaces", "call +1 555 123 4567", "+1 555 123 4567"},
		{"four groups", "call 612 34 56 78", "612 34 56 78"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := DetectAll(tt.content, enableOnly(PhoneNumber))
			m := findMatch(matches, PhoneNumber)
			if m == nil {
				t.Fatalf("expected PhoneNumber match for %q", tt.content)
			}
			if m.Value != tt.want {
				t.Errorf("PhoneNumber value = %q, want %q", m.Value, tt.want)
			}
		})
	}
}

func TestDetectAll_SpanishPhone_BeforeGenericPhone(t *testing.T) {
	content := "llama al 612 34 56 78 ahora"
	matches := DetectAll(content, enableOnly(SpanishPhone, PhoneNumber))
	esMatch := findMatch(matches, SpanishPhone)
	genMatch := findMatch(matches, PhoneNumber)
	if esMatch == nil {
		t.Error("expected SpanishPhone to claim the number (Tier 2 before Tier 3)")
	}
	if genMatch != nil {
		t.Error("generic PhoneNumber should not match when SpanishPhone already claimed the region")
	}
}

func TestDetectAll_SpanishIBAN_BeforeGenericIBAN(t *testing.T) {
	content := "ES9121000418450200051332"
	matches := DetectAll(content, enableOnly(SpanishIBAN, IBAN))
	esMatch := findMatch(matches, SpanishIBAN)
	genMatch := findMatch(matches, IBAN)
	if esMatch == nil {
		t.Error("expected SpanishIBAN to claim the ES-prefixed IBAN")
	}
	if genMatch != nil {
		t.Error("generic IBAN should not match when SpanishIBAN already claimed the region")
	}
}
