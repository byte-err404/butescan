package scripts

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Engine runs built-in and custom scripts against open ports
type Engine struct {
	timeout time.Duration
	scripts map[string]ScriptFunc
}

// ScriptFunc is the type for script functions
type ScriptFunc func(host string, port int, service string) (string, error)

// New creates a new script engine with all built-in scripts registered
func New() *Engine {
	e := &Engine{
		timeout: 5 * time.Second,
		scripts: make(map[string]ScriptFunc),
	}

	// Register all built-in scripts
	e.scripts["http-headers"] = scriptHTTPHeaders
	e.scripts["http-title"] = scriptHTTPTitle
	e.scripts["http-methods"] = scriptHTTPMethods
	e.scripts["http-robots"] = scriptHTTPRobots
	e.scripts["ssh-auth-methods"] = scriptSSHAuthMethods
	e.scripts["ssh-hostkey"] = scriptSSHHostKey
	e.scripts["ftp-anon"] = scriptFTPAnon
	e.scripts["smtp-commands"] = scriptSMTPCommands
	e.scripts["smtp-open-relay"] = scriptSMTPOpenRelay
	e.scripts["mysql-info"] = scriptMySQLInfo
	e.scripts["redis-info"] = scriptRedisInfo
	e.scripts["redis-unauth"] = scriptRedisUnauth
	e.scripts["mongodb-info"] = scriptMongoDBInfo
	e.scripts["ssl-cert"] = scriptSSLCert
	e.scripts["ssl-heartbleed"] = scriptSSLHeartbleed
	e.scripts["dns-brute"] = scriptDNSBrute
	e.scripts["snmp-info"] = scriptSNMPInfo
	e.scripts["vnc-info"] = scriptVNCInfo
	e.scripts["telnet-ntlm-info"] = scriptTelnetInfo

	return e
}

// List returns all available script names
func (e *Engine) List() []string {
	names := make([]string, 0, len(e.scripts))
	for name := range e.scripts {
		names = append(names, name)
	}
	return names
}

// Run executes a script by name
func (e *Engine) Run(scriptName, host string, port int, service string) (string, error) {
	fn, ok := e.scripts[scriptName]
	if !ok {
		return "", fmt.Errorf("script '%s' not found", scriptName)
	}

	// Check if script applies to this service/port
	if !scriptApplies(scriptName, port, service) {
		return "", nil
	}

	result, err := fn(host, port, service)
	return result, err
}

// scriptApplies checks whether a script should run on a given port/service
func scriptApplies(script string, port int, service string) bool {
	svcLower := strings.ToLower(service)

	rules := map[string]func() bool{
		"http-headers":     func() bool { return isHTTP(port, svcLower) },
		"http-title":       func() bool { return isHTTP(port, svcLower) },
		"http-methods":     func() bool { return isHTTP(port, svcLower) },
		"http-robots":      func() bool { return isHTTP(port, svcLower) },
		"ssl-cert":         func() bool { return isHTTPS(port, svcLower) },
		"ssl-heartbleed":   func() bool { return isHTTPS(port, svcLower) },
		"ssh-auth-methods": func() bool { return svcLower == "ssh" || port == 22 },
		"ssh-hostkey":      func() bool { return svcLower == "ssh" || port == 22 },
		"ftp-anon":         func() bool { return svcLower == "ftp" || port == 21 },
		"smtp-commands":    func() bool { return svcLower == "smtp" || port == 25 || port == 587 },
		"smtp-open-relay":  func() bool { return svcLower == "smtp" || port == 25 },
		"mysql-info":       func() bool { return svcLower == "mysql" || port == 3306 },
		"redis-info":       func() bool { return svcLower == "redis" || port == 6379 },
		"redis-unauth":     func() bool { return svcLower == "redis" || port == 6379 },
		"mongodb-info":     func() bool { return svcLower == "mongodb" || port == 27017 },
		"dns-brute":        func() bool { return svcLower == "dns" || port == 53 },
		"snmp-info":        func() bool { return port == 161 },
		"vnc-info":         func() bool { return svcLower == "vnc" || port == 5900 },
		"telnet-ntlm-info": func() bool { return svcLower == "telnet" || port == 23 },
	}

	if rule, ok := rules[script]; ok {
		return rule()
	}
	return false
}

func isHTTP(port int, service string) bool {
	return port == 80 || port == 8080 || port == 8000 || port == 8888 ||
		strings.Contains(service, "http") && !strings.Contains(service, "https")
}

func isHTTPS(port int, service string) bool {
	return port == 443 || port == 8443 || strings.Contains(service, "https")
}

// (rest of file unchanged for brevity in canvas request)
