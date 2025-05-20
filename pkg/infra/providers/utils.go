package providers

import "strings"

func FormatInstructions(instr []string) string {
	if len(instr) == 0 {
		return "[Instructions]\n"
	}

	var b strings.Builder
	b.WriteString("[Instructions]\n")
	for _, rule := range instr {
		if strings.TrimSpace(rule) == "" {
			continue
		}
		b.WriteString("- ")
		b.WriteString(rule)
		b.WriteByte('\n')
	}
	return b.String()
}
