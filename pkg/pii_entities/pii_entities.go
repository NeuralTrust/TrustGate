// Package pii_entities provides predefined PII (Personally Identifiable Information)
// entity types and their detection patterns. This package is shared between
// data_masking and doc_analyzer plugins.
package pii_entities

import "regexp"

// Entity represents a type of sensitive data that can be detected
type Entity string

const (
	// Default is used as a fallback mask
	Default Entity = "default"

	// Generic entities
	CreditCard     Entity = "credit_card"
	CVV            Entity = "cvv"
	Email          Entity = "email"
	PhoneNumber    Entity = "phone_number"
	SSN            Entity = "ssn"
	IPAddress      Entity = "ip_address"
	IPv6Address    Entity = "ip6_address"
	BankAccount    Entity = "bank_account"
	Password       Entity = "password"
	APIKey         Entity = "api_key"
	AccessToken    Entity = "access_token"
	IBAN           Entity = "iban"
	SwiftBIC       Entity = "swift_bic"
	CryptoWallet   Entity = "crypto_wallet"
	TaxID          Entity = "tax_id"
	RoutingNumber  Entity = "routing_number"
	UUID           Entity = "uuid"
	JWTToken       Entity = "jwt_token"
	MACAddress     Entity = "mac_address"
	StripeKey      Entity = "stripe_key"
	DriversLicense Entity = "drivers_license"
	Passport       Entity = "passport"
	Address        Entity = "address"
	ZipCode        Entity = "zip_code"
	Date           Entity = "date"

	// Spain
	SpanishDNI   Entity = "spanish_dni"
	SpanishNIE   Entity = "spanish_nie"
	SpanishCIF   Entity = "spanish_cif"
	SpanishNSS   Entity = "spanish_nss"
	SpanishIBAN  Entity = "spanish_iban"
	SpanishPhone Entity = "spanish_phone"

	// France
	FrenchNIR Entity = "french_nir"

	// Italy
	ItalianCF Entity = "italian_cf"

	// Germany
	GermanID Entity = "german_id"

	// Brazil
	BrazilianCPF  Entity = "brazilian_cpf"
	BrazilianCNPJ Entity = "brazilian_cnpj"

	// Mexico
	MexicanCURP Entity = "mexican_curp"
	MexicanRFC  Entity = "mexican_rfc"

	// USA
	USMedicareID Entity = "us_medicare"

	// Financial
	ISIN Entity = "isin"

	// Devices/Vehicles
	VehicleVIN Entity = "vehicle_vin"
	DeviceIMEI Entity = "device_imei"
	DeviceMAC  Entity = "device_mac"

	// Latin America
	ArgentineDNI Entity = "argentine_dni"
	ChileanRUT   Entity = "chilean_rut"
	ColombianCC  Entity = "colombian_cc"
	PeruvianDNI  Entity = "peruvian_dni"
)

// Tier represents the detection priority tier for an entity.
type Tier int

const (
	Tier1 Tier = 1 // structurally unique, near-zero false positives
	Tier2 Tier = 2 // has structural markers but some ambiguity
	Tier3 Tier = 3 // pure format patterns, high false positive rate
)

// EntityInfo contains the detection configuration for a PII entity type.
type EntityInfo struct {
	Pattern     *regexp.Regexp
	Validate    func(match string) bool // nil means accept all regex matches
	Tier        Tier
	DefaultMask string
}

// Entities is the unified registry of all PII entity types.
// #nosec G101 -- These are PII mask placeholder strings, not hardcoded credentials
var Entities = map[Entity]EntityInfo{
	// --- Tier 1: structurally unique, near-zero false positives ---
	Password: {
		Pattern:     regexp.MustCompile(`(?i)password[\s]*[=:]\s*\S+`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_PASSWORD]",
	},
	APIKey: {
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?key)[\s]*[=:]\s*\S+`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_API_KEY]",
	},
	AccessToken: {
		Pattern:     regexp.MustCompile(`(?i)(access[_-]?token|bearer)[\s]*[=:]\s*\S+`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_TOKEN]",
	},
	Email: {
		Pattern:     regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_EMAIL]",
	},
	UUID: {
		Pattern:     regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_UUID]",
	},
	JWTToken: {
		Pattern:     regexp.MustCompile(`\beyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_JWT_TOKEN]",
	},
	CryptoWallet: {
		Pattern:     regexp.MustCompile(`\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_WALLET]",
	},
	StripeKey: {
		Pattern:     regexp.MustCompile(`(?i)(sk|pk|rk|whsec)_(test|live)_[a-z0-9]{24}`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_API_KEY]",
	},
	IPAddress: {
		Pattern:     regexp.MustCompile(`\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_IP]",
	},
	IPv6Address: {
		Pattern:     regexp.MustCompile(`\b(?:[a-fA-F0-9]{1,4}:){6,7}[a-fA-F0-9]{1,4}|\b(?:[a-fA-F0-9]{1,4}:){1,7}:\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_IP6]",
	},
	MACAddress: {
		Pattern:     regexp.MustCompile(`\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_MAC]",
	},
	DeviceMAC: {
		Pattern:     regexp.MustCompile(`\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_MAC]",
	},
	ItalianCF: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_IT_CF]",
	},
	MexicanCURP: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_MX_CURP]",
	},
	FrenchNIR: {
		Pattern:     regexp.MustCompile(`\b[1-2]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_FR_NIR]",
	},
	CVV: {
		Pattern:     regexp.MustCompile(`(?i)cvv[\s-]*\d{3}`),
		Tier:        Tier1,
		DefaultMask: "[MASKED_CVV]",
	},

	// --- Tier 2: has structural markers but some ambiguity ---
	SpanishIBAN: {
		Pattern:     regexp.MustCompile(`\bES\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
		Validate:    validateIBAN,
		Tier:        Tier2,
		DefaultMask: "[MASKED_ES_IBAN]",
	},
	IBAN: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`),
		Validate:    validateIBAN,
		Tier:        Tier2,
		DefaultMask: "[MASKED_IBAN]",
	},
	USMedicareID: {
		Pattern:     regexp.MustCompile(`(?i)\b[1-9]\d{2}[-\s]\d{2}[-\s]\d{4}[A-Z]\b`),
		Tier:        Tier2,
		DefaultMask: "[MASKED_MEDICARE]",
	},
	SSN: {
		Pattern:     regexp.MustCompile(`\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b`),
		Validate:    validateSSN,
		Tier:        Tier2,
		DefaultMask: "[MASKED_SSN]",
	},
	BrazilianCNPJ: {
		Pattern:     regexp.MustCompile(`\b\d{2}\.?\d{3}\.?\d{3}/?\.?\d{4}-?\d{2}\b`),
		Validate:    validateBrazilianCNPJ,
		Tier:        Tier2,
		DefaultMask: "[MASKED_BR_CNPJ]",
	},
	BrazilianCPF: {
		Pattern:     regexp.MustCompile(`\b\d{3}[./]?\d{3}[./]?\d{3}[-./]?\d{2}\b`),
		Validate:    validateBrazilianCPF,
		Tier:        Tier2,
		DefaultMask: "[MASKED_BR_CPF]",
	},
	CreditCard: {
		Pattern:     regexp.MustCompile(`\b(?:4(?:[\s-]?\d){12}(?:(?:[\s-]?\d){3})?|(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)(?:[\s-]?\d){12}|3[47](?:[\s-]?\d){13}|3(?:0[0-5]|[68]\d)(?:[\s-]?\d){11}|6(?:011|5\d{2})(?:[\s-]?\d){12}|(?:2131|1800|35\d{3})(?:[\s-]?\d){11})\b`),
		Validate:    validateLuhn,
		Tier:        Tier2,
		DefaultMask: "[MASKED_CC]",
	},
	SpanishDNI: {
		Pattern:     regexp.MustCompile(`(?i)\b\d{2}\.?\d{3}\.?\d{3}[-.\s]?[A-HJ-NP-TV-Z]\b`),
		Validate:    validateSpanishDNI,
		Tier:        Tier2,
		DefaultMask: "[MASKED_DNI]",
	},
	SpanishNIE: {
		Pattern:     regexp.MustCompile(`(?i)\b[XYZ][-.\s]?\d{7}[-.\s]?[A-HJ-NP-TV-Z]\b`),
		Validate:    validateSpanishNIE,
		Tier:        Tier2,
		DefaultMask: "[MASKED_NIE]",
	},
	SpanishCIF: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-HJNPQRSUVW][-.\s]?\d{7}[-.\s]?[A-J0-9]\b`),
		Tier:        Tier2,
		DefaultMask: "[MASKED_CIF]",
	},
	SpanishNSS: {
		Pattern:     regexp.MustCompile(`\b\d{2}[- ]?\d{8}[- ]?\d{2}\b`),
		Tier:        Tier2,
		DefaultMask: "[MASKED_NSS]",
	},
	SpanishPhone: {
		Pattern:     regexp.MustCompile(`(?:(?:\+34|0034)[.\s-]?[6-9]\d{2}[.\s-]?\d{3}[.\s-]?\d{3}|\b[6-9]\d{8})\b`),
		Tier:        Tier2,
		DefaultMask: "[MASKED_ES_PHONE]",
	},
	GermanID: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{2}\d[A-Z0-9]{6}[0-9]\b`),
		Tier:        Tier2,
		DefaultMask: "[MASKED_DE_ID]",
	},
	MexicanRFC: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{3,4}\d{6}[A-Z0-9]{3}\b`),
		Tier:        Tier2,
		DefaultMask: "[MASKED_MX_RFC]",
	},
	ChileanRUT: {
		Pattern:     regexp.MustCompile(`\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9K]\b`),
		Validate:    validateChileanRUT,
		Tier:        Tier2,
		DefaultMask: "[MASKED_CL_RUT]",
	},
	Date: {
		Pattern:     regexp.MustCompile(`\b(\d{4}[-/.]\d{2}[-/.]\d{2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4}|\d{1,2}\s(?:de\s)?[a-zA-Z]+\s(?:de\s)?\d{4}|\d{1,2}(?:st|nd|rd|th)?\s[a-zA-Z]+\s\d{4}|[a-zA-Z]+\s\d{1,2}(?:st|nd|rd|th)?\s\d{4})\b`),
		Tier:        Tier2,
		DefaultMask: "[MASKED_DATE]",
	},
	SwiftBIC: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`),
		Validate:    validateSwiftBIC,
		Tier:        Tier2,
		DefaultMask: "[MASKED_BIC]",
	},
	Address: {
		Pattern:     regexp.MustCompile(`\b\d+\s+[A-Za-z\s]+,\s+[A-Za-z\s]+,\s+[A-Z]{2}\s+\d{5}\b`),
		Tier:        Tier2,
		DefaultMask: "[MASKED_ADDRESS]",
	},

	// --- Tier 3: pure format patterns, high false positive rate ---
	DeviceIMEI: {
		Pattern:     regexp.MustCompile(`\b\d{15,17}\b`),
		Validate:    validateIMEI,
		Tier:        Tier3,
		DefaultMask: "[MASKED_IMEI]",
	},
	BankAccount: {
		Pattern:     regexp.MustCompile(`\b\d{8,20}\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_ACCOUNT]",
	},
	ColombianCC: {
		Pattern:     regexp.MustCompile(`\b\d{8,10}\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_CO_CC]",
	},
	TaxID: {
		Pattern:     regexp.MustCompile(`\b\d{2}[-\s]?\d{7}\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_TAX_ID]",
	},
	RoutingNumber: {
		Pattern:     regexp.MustCompile(`\b\d{9}\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_ROUTING]",
	},
	PeruvianDNI: {
		Pattern:     regexp.MustCompile(`\b\d{8}\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_PE_DNI]",
	},
	ArgentineDNI: {
		Pattern:     regexp.MustCompile(`\b\d{7,8}\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_AR_DNI]",
	},
	ZipCode: {
		Pattern:     regexp.MustCompile(`\b\d{5}(-\d{4})?\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_ZIP]",
	},
	PhoneNumber: {
		Pattern:     regexp.MustCompile(`(?:\+\d{1,4}[\s-]?|\(|\b)(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{2,4}[\s-]?\d{2,4}\b`),
		Validate:    validatePhoneNumber,
		Tier:        Tier3,
		DefaultMask: "[MASKED_PHONE]",
	},
	VehicleVIN: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-HJ-NPR-Z0-9]{17}\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_VIN]",
	},
	DriversLicense: {
		Pattern:     regexp.MustCompile(`(?i)\b([A-Z]{1,2}[-\s]?\d{5,7}|\d{9}|\d{3}[-\s]?\d{3}[-\s]?\d{3})\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_LICENSE]",
	},
	Passport: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{1,2}[0-9]{6,9}\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_PASSPORT]",
	},
	ISIN: {
		Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{2}[A-Z0-9]{9}\d\b`),
		Tier:        Tier3,
		DefaultMask: "[MASKED_ISIN]",
	},
}

// Tier ordering slices. Within each tier, superset patterns come before their
// subsets to ensure the more-specific match claims the byte range first.
var (
	tier1Entities = []Entity{
		Password, APIKey, AccessToken,
		Email, UUID, JWTToken, CryptoWallet, StripeKey,
		IPAddress, MACAddress, DeviceMAC, IPv6Address,
		ItalianCF, MexicanCURP, FrenchNIR, CVV,
	}
	tier2Entities = []Entity{
		SpanishIBAN, IBAN,
		USMedicareID, SSN,
		BrazilianCNPJ, BrazilianCPF,
		CreditCard,
		SpanishDNI, SpanishNIE, SpanishCIF, SpanishNSS, SpanishPhone,
		GermanID, MexicanRFC, ChileanRUT,
		Date, SwiftBIC, Address,
	}
	tier3Entities = []Entity{
		DeviceIMEI, BankAccount, ColombianCC, TaxID, RoutingNumber,
		PeruvianDNI, ArgentineDNI, ZipCode,
		PhoneNumber, VehicleVIN, Passport, DriversLicense, ISIN,
	}
	tierOrder = [][]Entity{tier1Entities, tier2Entities, tier3Entities}
)

// Backward-compatible computed views. These are populated by init() from the
// Entities registry and the tier ordering slices.
var (
	// Patterns maps each entity to its compiled regex.
	Patterns map[Entity]*regexp.Regexp

	// DefaultMasks maps each entity (and Default) to its mask string.
	// #nosec G101 -- These are PII mask placeholder strings, not hardcoded credentials
	DefaultMasks map[Entity]string

	// DetectionOrder is the flattened tier order. Deprecated: use DetectAll() instead.
	DetectionOrder []Entity

	// AllEntities contains all valid entity types for validation.
	AllEntities map[Entity]bool
)

func init() {
	Patterns = make(map[Entity]*regexp.Regexp, len(Entities))
	DefaultMasks = make(map[Entity]string, len(Entities)+1)
	AllEntities = make(map[Entity]bool, len(Entities))

	for entity, info := range Entities {
		Patterns[entity] = info.Pattern
		DefaultMasks[entity] = info.DefaultMask
		AllEntities[entity] = true
	}
	DefaultMasks[Default] = "*****"

	DetectionOrder = make([]Entity, 0, len(Entities))
	for _, tier := range tierOrder {
		DetectionOrder = append(DetectionOrder, tier...)
	}
}

// IsValid checks if an entity type is valid
func IsValid(entity string) bool {
	return AllEntities[Entity(entity)]
}

// GetPattern returns the regex pattern for an entity type
func GetPattern(entity Entity) *regexp.Regexp {
	return Patterns[entity]
}

// GetDefaultMask returns the default mask for an entity type
func GetDefaultMask(entity Entity) string {
	if mask, ok := DefaultMasks[entity]; ok {
		return mask
	}
	return DefaultMasks[Default]
}
