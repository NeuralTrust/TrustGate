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

// Patterns contains regex patterns for each entity type
var Patterns = map[Entity]*regexp.Regexp{
	CreditCard:     regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
	CVV:            regexp.MustCompile(`(?i)cvv[\s-]*\d{3}`),
	Email:          regexp.MustCompile(`\b[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\s*\.\s*[A-Za-z]{2,}\b`),
	SSN:            regexp.MustCompile(`\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`),
	IPAddress:      regexp.MustCompile(`\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	IPv6Address:    regexp.MustCompile(`\b(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}|\b(?:[a-fA-F0-9]{1,4}:){1,7}:\b`),
	BankAccount:    regexp.MustCompile(`\b\d{8,20}\b`),
	Password:       regexp.MustCompile(`(?i)password[\s]*[=:]\s*\S+`),
	APIKey:         regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?key)[\s]*[=:]\s*\S+`),
	AccessToken:    regexp.MustCompile(`(?i)(access[_-]?token|bearer)[\s]*[=:]\s*\S+`),
	IBAN:           regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`),
	SwiftBIC:       regexp.MustCompile(`\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`),
	PhoneNumber:    regexp.MustCompile(`\b(\+?\d{1,4}[\s-]?)?(\(?\d{2,4}\)?[\s-]?)?\d{2,4}[\s-]?\d{2,4}[\s-]?\d{2,4}\b`),
	CryptoWallet:   regexp.MustCompile(`\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}\b`),
	TaxID:          regexp.MustCompile(`\b\d{2}[-\s]?\d{7}\b`),
	RoutingNumber:  regexp.MustCompile(`\b\d{9}\b`),
	UUID:           regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
	JWTToken:       regexp.MustCompile(`\beyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b`),
	MACAddress:     regexp.MustCompile(`\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`),
	StripeKey:      regexp.MustCompile(`(?i)(sk|pk|rk|whsec)_(test|live)_[a-z0-9]{24}`),
	DriversLicense: regexp.MustCompile(`\b([A-Z]{1,2}[-\s]?\d{2,7}|\d{9}|\d{3}[-\s]?\d{3}[-\s]?\d{3})\b`),
	Passport:       regexp.MustCompile(`\b[A-Z]{1,2}[0-9]{6,9}\b`),
	Address:        regexp.MustCompile(`\b\d+\s+[A-Za-z\s]+,\s+[A-Za-z\s]+,\s+[A-Z]{2}\s+\d{5}\b`),
	ZipCode:        regexp.MustCompile(`\b\d{5}(-\d{4})?\b`),
	SpanishDNI:     regexp.MustCompile(`\b\d{8}[A-HJ-NP-TV-Z]\b`),
	SpanishNIE:     regexp.MustCompile(`\b[XYZ]\d{7}[A-HJ-NP-TV-Z]\b`),
	SpanishCIF:     regexp.MustCompile(`\b[A-HJNPQRSUVW]\d{7}[A-J0-9]\b`),
	SpanishNSS:     regexp.MustCompile(`\b\d{2}[- ]?\d{8}[- ]?\d{2}\b`),
	SpanishIBAN:    regexp.MustCompile(`\bES\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
	SpanishPhone:   regexp.MustCompile(`\b(?:\+34|0034)?[- ]?(?:6|7|8|9)\d{8}\b`),
	FrenchNIR:      regexp.MustCompile(`\b[1-2]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b`),
	ItalianCF:      regexp.MustCompile(`\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b`),
	GermanID:       regexp.MustCompile(`\b[A-Z]{2}[A-Z0-9]{7}[0-9]\b`),
	BrazilianCPF:   regexp.MustCompile(`\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b`),
	BrazilianCNPJ:  regexp.MustCompile(`\b\d{2}\.?\d{3}\.?\d{3}/?\.?\d{4}-?\d{2}\b`),
	MexicanCURP:    regexp.MustCompile(`\b[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d\b`),
	MexicanRFC:     regexp.MustCompile(`\b[A-Z]{3,4}\d{6}[A-Z0-9]{3}\b`),
	USMedicareID:   regexp.MustCompile(`\b[1-9]\d{2}-\d{2}-\d{4}[A-Z]\b`),
	ISIN:           regexp.MustCompile(`\b[A-Z]{2}[A-Z0-9]{9}\d\b`),
	VehicleVIN:     regexp.MustCompile(`\b[A-HJ-NPR-Z0-9]{17}\b`),
	DeviceIMEI:     regexp.MustCompile(`\b\d{15,17}\b`),
	DeviceMAC:      regexp.MustCompile(`\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b`),
	ArgentineDNI:   regexp.MustCompile(`\b\d{7,8}\b`),
	ChileanRUT:     regexp.MustCompile(`\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9K]\b`),
	ColombianCC:    regexp.MustCompile(`\b\d{8,10}\b`),
	PeruvianDNI:    regexp.MustCompile(`\b\d{8}\b`),
	Date:           regexp.MustCompile(`\b(\d{4}[-/]\d{2}[-/]\d{2}|\d{1,2}[-/]\d{1,2}[-/]\d{4}|\d{1,2}\s(?:de\s)?[a-zA-Z]+\s(?:de\s)?\d{4}|\d{1,2}(?:st|nd|rd|th)?\s[a-zA-Z]+\s\d{4}|[a-zA-Z]+\s\d{1,2}(?:st|nd|rd|th)?\s\d{4})\b`),
}

// DetectionOrder defines the order in which entities should be detected
// (more specific patterns first to avoid false positives)
var DetectionOrder = []Entity{
	IBAN,
	PhoneNumber,
	CreditCard,
	CVV,
	Email,
	SSN,
	IPAddress,
	IPv6Address,
	BankAccount,
	Password,
	APIKey,
	AccessToken,
	SwiftBIC,
	CryptoWallet,
	TaxID,
	RoutingNumber,
	UUID,
	JWTToken,
	MACAddress,
	StripeKey,
	DriversLicense,
	Passport,
	Address,
	ZipCode,
	SpanishDNI,
	SpanishNIE,
	SpanishCIF,
	SpanishNSS,
	SpanishIBAN,
	SpanishPhone,
	FrenchNIR,
	ItalianCF,
	GermanID,
	BrazilianCPF,
	BrazilianCNPJ,
	MexicanCURP,
	MexicanRFC,
	USMedicareID,
	ISIN,
	VehicleVIN,
	DeviceIMEI,
	DeviceMAC,
	ArgentineDNI,
	ChileanRUT,
	ColombianCC,
	PeruvianDNI,
	Date,
}

// DefaultMasks contains default mask values for each entity type
var DefaultMasks = map[Entity]string{
	Default:        "*****",
	CreditCard:     "[MASKED_CC]",
	CVV:            "[MASKED_CVV]",
	Email:          "[MASKED_EMAIL]",
	SSN:            "[MASKED_SSN]",
	IPAddress:      "[MASKED_IP]",
	IPv6Address:    "[MASKED_IP6]",
	BankAccount:    "[MASKED_ACCOUNT]",
	Password:       "[MASKED_PASSWORD]",
	APIKey:         "[MASKED_API_KEY]",
	AccessToken:    "[MASKED_TOKEN]",
	IBAN:           "[MASKED_IBAN]",
	PhoneNumber:    "[MASKED_PHONE]",
	SwiftBIC:       "[MASKED_BIC]",
	CryptoWallet:   "[MASKED_WALLET]",
	TaxID:          "[MASKED_TAX_ID]",
	RoutingNumber:  "[MASKED_ROUTING]",
	UUID:           "[MASKED_UUID]",
	JWTToken:       "[MASKED_JWT_TOKEN]",
	MACAddress:     "[MASKED_MAC]",
	StripeKey:      "[MASKED_API_KEY]",
	DriversLicense: "[MASKED_LICENSE]",
	Passport:       "[MASKED_PASSPORT]",
	Address:        "[MASKED_ADDRESS]",
	ZipCode:        "[MASKED_ZIP]",
	Date:           "[MASKED_DATE]",
	SpanishDNI:     "[MASKED_DNI]",
	SpanishNIE:     "[MASKED_NIE]",
	SpanishCIF:     "[MASKED_CIF]",
	SpanishNSS:     "[MASKED_NSS]",
	SpanishIBAN:    "[MASKED_ES_IBAN]",
	SpanishPhone:   "[MASKED_ES_PHONE]",
	FrenchNIR:      "[MASKED_FR_NIR]",
	ItalianCF:      "[MASKED_IT_CF]",
	GermanID:       "[MASKED_DE_ID]",
	BrazilianCPF:   "[MASKED_BR_CPF]",
	BrazilianCNPJ:  "[MASKED_BR_CNPJ]",
	MexicanCURP:    "[MASKED_MX_CURP]",
	MexicanRFC:     "[MASKED_MX_RFC]",
	USMedicareID:   "[MASKED_MEDICARE]",
	ISIN:           "[MASKED_ISIN]",
	VehicleVIN:     "[MASKED_VIN]",
	DeviceIMEI:     "[MASKED_IMEI]",
	DeviceMAC:      "[MASKED_MAC]",
	ArgentineDNI:   "[MASKED_AR_DNI]",
	ChileanRUT:     "[MASKED_CL_RUT]",
	ColombianCC:    "[MASKED_CO_CC]",
	PeruvianDNI:    "[MASKED_PE_DNI]",
}

// AllEntities contains all valid entity types for validation
var AllEntities = map[Entity]bool{
	CreditCard:     true,
	CVV:            true,
	Email:          true,
	PhoneNumber:    true,
	SSN:            true,
	IPAddress:      true,
	IPv6Address:    true,
	BankAccount:    true,
	Password:       true,
	APIKey:         true,
	AccessToken:    true,
	IBAN:           true,
	SwiftBIC:       true,
	CryptoWallet:   true,
	TaxID:          true,
	RoutingNumber:  true,
	UUID:           true,
	JWTToken:       true,
	MACAddress:     true,
	StripeKey:      true,
	DriversLicense: true,
	Passport:       true,
	Address:        true,
	ZipCode:        true,
	Date:           true,
	SpanishDNI:     true,
	SpanishNIE:     true,
	SpanishCIF:     true,
	SpanishNSS:     true,
	SpanishIBAN:    true,
	SpanishPhone:   true,
	FrenchNIR:      true,
	ItalianCF:      true,
	GermanID:       true,
	BrazilianCPF:   true,
	BrazilianCNPJ:  true,
	MexicanCURP:    true,
	MexicanRFC:     true,
	USMedicareID:   true,
	ISIN:           true,
	VehicleVIN:     true,
	DeviceIMEI:     true,
	DeviceMAC:      true,
	ArgentineDNI:   true,
	ChileanRUT:     true,
	ColombianCC:    true,
	PeruvianDNI:    true,
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
