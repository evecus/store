package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// preprocessors is the ordered list of pre-processors.
var preprocessors = []struct {
	Name  string
	Test  func(raw string) bool
	Parse func(raw string) string
}{
	{Name: "HTML", Test: htmlPreprocessorTest, Parse: func(raw string) string { return "" }},
	{Name: "Clash", Test: clashPreprocessorTest, Parse: clashPreprocessorParse},
	{Name: "Base64Encoded", Test: base64PreprocessorTest, Parse: base64PreprocessorParse},
	{Name: "SSD", Test: ssdPreprocessorTest, Parse: ssdPreprocessorParse},
	{Name: "FullConfig", Test: fullConfigPreprocessorTest, Parse: fullConfigPreprocessorParse},
}

// Preprocess detects the subscription format and normalizes the raw text.
func Preprocess(raw string) string {
	for _, pp := range preprocessors {
		if pp.Test(raw) {
			return pp.Parse(raw)
		}
	}
	return raw
}

func htmlPreprocessorTest(raw string) bool {
	return strings.HasPrefix(raw, "<!DOCTYPE html>")
}

func clashPreprocessorTest(raw string) bool {
	if !strings.Contains(raw, "proxies") {
		return false
	}
	var content map[string]any
	if err := yaml.Unmarshal([]byte(raw), &content); err != nil {
		return false
	}
	_, hasProxies := content["proxies"].([]any)
	_, hasGroups := content["proxy-groups"].([]any)
	return hasProxies || hasGroups
}

func clashPreprocessorParse(raw string) string {
	var content map[string]any
	if err := yaml.Unmarshal([]byte(raw), &content); err != nil {
		return raw
	}
	proxies, _ := content["proxies"].([]any)
	lines := make([]string, 0, len(proxies))
	for _, p := range proxies {
		b, err := json.Marshal(p)
		if err != nil {
			continue
		}
		lines = append(lines, string(b))
	}
	return strings.Join(lines, "\n")
}

func base64PreprocessorTest(raw string) bool {
	if regexp.MustCompile(`^\w+://`).MatchString(raw) {
		return false
	}
	keys := []string{
		"dm1lc3M", "c3NyOi8v", "c29ja3M6Ly", "dHJvamFu", "c3M6Ly",
		"c3NkOi8v", "c2hhZG93", "aHR0c", "dmxlc3M=", "aHlzdGVyaWEy",
		"aHkyOi8v", "d2lyZWd1YXJkOi8v", "d2c6Ly8=", "dHVpYzovLw==",
	}
	for _, k := range keys {
		if strings.Contains(raw, k) {
			if _, err := Base64Decode(raw); err == nil {
				return true
			}
		}
	}
	return false
}

func base64PreprocessorParse(raw string) string {
	decoded, err := Base64Decode(raw)
	if err != nil {
		return raw
	}
	return decoded
}

func ssdPreprocessorTest(raw string) bool {
	return strings.HasPrefix(raw, "ssd://")
}

func ssdPreprocessorParse(raw string) string {
	payload := strings.TrimPrefix(raw, "ssd://")
	info, err := Base64Decode(payload)
	if err != nil {
		return raw
	}
	var doc struct {
		Port       int    `json:"port"`
		Encryption string `json:"encryption"`
		Password   string `json:"password"`
		Servers    []struct {
			Server       string `json:"server"`
			Port         int    `json:"port"`
			Encryption   string `json:"encryption"`
			Password     string `json:"password"`
			Remarks      string `json:"remarks"`
			Plugin       string `json:"plugin"`
			PluginOpts   string `json:"plugin_options"`
		} `json:"servers"`
	}
	if err := JSONUnmarshalLoose(info, &doc); err != nil {
		return raw
	}
	lines := []string{}
	for i, srv := range doc.Servers {
		method := doc.Encryption
		if srv.Encryption != "" {
			method = srv.Encryption
		}
		password := doc.Password
		if srv.Password != "" {
			password = srv.Password
		}
		port := doc.Port
		if srv.Port > 0 {
			port = srv.Port
		}
		tag := srv.Remarks
		if tag == "" {
			tag = fmt.Sprint(i)
		}
		userinfo := base64Std(method + ":" + password)
		plugin := ""
		if srv.PluginOpts != "" {
			plugin = "/?plugin=" + urlQueryEscape(srv.Plugin+";"+srv.PluginOpts)
		}
		lines = append(lines, "ss://"+userinfo+"@"+srv.Server+":"+fmt.Sprint(port)+plugin+"#"+tag)
	}
	return strings.Join(lines, "\n")
}

func fullConfigPreprocessorTest(raw string) bool {
	return regexp.MustCompile(`(?m)^(\[server_local\]|\[Proxy\])`).MatchString(raw)
}

func fullConfigPreprocessorParse(raw string) string {
	// Mirrors Sub-Store's FullConfig parse regex
	// /^\[server_local|Proxy\]([\s\S]+?)^\[.+?\](\r?\n|$)/im:
	// the alternation quirk means "Proxy]" can match mid-line while
	// "[server_local" must start a line; without a closing section
	// header the raw document is returned unchanged.
	re := regexp.MustCompile(`(?im)(?:^\[server_local|Proxy\])([\s\S]+?)^\[.+?\](\r?\n|$)`)
	m := re.FindStringSubmatch(raw)
	if len(m) > 1 {
		return m[1]
	}
	return raw
}
