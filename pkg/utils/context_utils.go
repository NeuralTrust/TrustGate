package utils

import (
	"fmt"
	"strings"

	"github.com/avct/uasurfer"
)

type UserAgentInfo struct {
	Device  string
	OS      string
	Browser string
	Locale  string
}

func LevenshteinDistance(s1, s2 string) int {
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	return matrix[len(s1)][len(s2)]
}

func ParseUserAgent(uaString string, acceptLanguage string) *UserAgentInfo {
	ua := uasurfer.Parse(uaString)

	device := "Unknown"
	switch ua.DeviceType {
	case uasurfer.DeviceComputer:
		device = "Computer"
	case uasurfer.DeviceTablet:
		device = "Tablet"
	case uasurfer.DevicePhone:
		device = "Phone"
	case uasurfer.DeviceConsole:
		device = "Console"
	case uasurfer.DeviceWearable:
		device = "Wearable"
	case uasurfer.DeviceTV:
		device = "TV"
	default:
		return nil
	}

	os := fmt.Sprintf("%s %d.%d", ua.OS.Name.String(), ua.OS.Version.Major, ua.OS.Version.Minor)

	browser := fmt.Sprintf("%s %d.%d", ua.Browser.Name.String(), ua.Browser.Version.Major, ua.Browser.Version.Minor)

	locale := ""
	if len(acceptLanguage) > 0 {
		for i := 0; i < len(acceptLanguage); i++ {
			if acceptLanguage[i] == ',' {
				locale = acceptLanguage[:i]
				break
			}
		}
		if locale == "" {
			locale = acceptLanguage
		}
	}

	return &UserAgentInfo{
		Device:  device,
		OS:      os,
		Browser: browser,
		Locale:  locale,
	}
}

func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}
