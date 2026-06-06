package panel

import (
	"strings"
	"testing"
)

func TestApplyNodeProtocolShadowTLSValid(t *testing.T) {
	tests := []struct {
		name    string
		version int
	}{
		{name: "v2", version: 2},
		{name: "v3", version: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &NodeInfo{}
			cm := &CommonNode{
				Protocol: "shadowsocks",
				Tls:      ShadowTLS,
				TlsSettings: TlsSettings{
					Plugin:            "shadow-tls",
					ShadowTLSVersion:  tt.version,
					ShadowTLSPassword: "secret-password",
					ShadowTLS:         "bing.com",
					WildcardSNI:       "off",
				},
			}

			if err := applyNodeProtocol(node, cm); err != nil {
				t.Fatalf("applyNodeProtocol() error = %v", err)
			}
			if node.Type != "shadowsocks" {
				t.Fatalf("node.Type = %q, want shadowsocks", node.Type)
			}
			if node.Security != ShadowTLS {
				t.Fatalf("node.Security = %d, want %d", node.Security, ShadowTLS)
			}
		})
	}
}

func TestApplyNodeProtocolOrdinaryShadowsocks(t *testing.T) {
	node := &NodeInfo{}
	cm := &CommonNode{
		Protocol: "shadowsocks",
		Tls:      None,
	}

	if err := applyNodeProtocol(node, cm); err != nil {
		t.Fatalf("applyNodeProtocol() error = %v", err)
	}
	if node.Type != "shadowsocks" {
		t.Fatalf("node.Type = %q, want shadowsocks", node.Type)
	}
	if node.Security != None {
		t.Fatalf("node.Security = %d, want %d", node.Security, None)
	}
}

func TestParseShadowTLSMappingOfficialSemantics(t *testing.T) {
	settings := TlsSettings{
		ShadowTLS: "your.domain:127.0.0.1:8443;captive.apple.com;www.feishu.cn",
	}

	mapping, err := settings.ParseShadowTLSMapping()
	if err != nil {
		t.Fatalf("ParseShadowTLSMapping() error = %v", err)
	}
	if mapping.Fallback.ServerName != "www.feishu.cn" {
		t.Fatalf("fallback server name = %q, want www.feishu.cn", mapping.Fallback.ServerName)
	}
	if mapping.Fallback.Host != "www.feishu.cn" {
		t.Fatalf("fallback host = %q, want www.feishu.cn", mapping.Fallback.Host)
	}
	if mapping.Fallback.Port != 443 {
		t.Fatalf("fallback port = %d, want 443", mapping.Fallback.Port)
	}

	yourDomain := mapping.HandshakeForServerName["your.domain"]
	if yourDomain.Host != "127.0.0.1" || yourDomain.Port != 8443 {
		t.Fatalf("your.domain mapping = %s:%d, want 127.0.0.1:8443", yourDomain.Host, yourDomain.Port)
	}
	apple := mapping.HandshakeForServerName["captive.apple.com"]
	if apple.Host != "captive.apple.com" || apple.Port != 443 {
		t.Fatalf("captive.apple.com mapping = %s:%d, want captive.apple.com:443", apple.Host, apple.Port)
	}
}

func TestParseShadowTLSMappingDefaultsHostAndPort(t *testing.T) {
	mapping, err := (TlsSettings{ShadowTLS: "example.com:8443"}).ParseShadowTLSMapping()
	if err != nil {
		t.Fatalf("ParseShadowTLSMapping() error = %v", err)
	}
	if mapping.Fallback.Host != "example.com" || mapping.Fallback.Port != 8443 {
		t.Fatalf("ServerName:Port fallback = %s:%d, want example.com:8443", mapping.Fallback.Host, mapping.Fallback.Port)
	}

	mapping, err = (TlsSettings{ShadowTLS: "fallback.example"}).ParseShadowTLSMapping()
	if err != nil {
		t.Fatalf("ParseShadowTLSMapping() error = %v", err)
	}
	if mapping.Fallback.Host != "fallback.example" || mapping.Fallback.Port != 443 {
		t.Fatalf("single-field fallback = %s:%d, want fallback.example:443", mapping.Fallback.Host, mapping.Fallback.Port)
	}
}

func TestParseShadowTLSMappingAcceptsBracketIPv6Host(t *testing.T) {
	mapping, err := (TlsSettings{ShadowTLS: "example.com:[2001:db8::1]:443"}).ParseShadowTLSMapping()
	if err != nil {
		t.Fatalf("ParseShadowTLSMapping() error = %v", err)
	}
	if mapping.Fallback.Host != "[2001:db8::1]" || mapping.Fallback.Port != 443 {
		t.Fatalf("bracket IPv6 fallback = %s:%d, want [2001:db8::1]:443", mapping.Fallback.Host, mapping.Fallback.Port)
	}
}

func TestShadowTLSWildcardSNIDefaultAndModes(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  string
	}{
		{input: "", want: "off"},
		{input: "off", want: "off"},
		{input: "authed", want: "authed"},
		{input: "all", want: "all"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			got, err := (TlsSettings{WildcardSNI: tt.input}).ShadowTLSWildcardSNI()
			if err != nil {
				t.Fatalf("ShadowTLSWildcardSNI() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ShadowTLSWildcardSNI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateShadowTLSInvalidSettings(t *testing.T) {
	const password = "super-secret-password"
	valid := TlsSettings{
		Plugin:            "shadow-tls",
		ShadowTLSVersion:  3,
		ShadowTLSPassword: password,
		ShadowTLS:         "bing.com",
		WildcardSNI:       "off",
	}

	tests := []struct {
		name   string
		mutate func(*TlsSettings)
	}{
		{
			name: "plugin",
			mutate: func(settings *TlsSettings) {
				settings.Plugin = "tls"
			},
		},
		{
			name: "version one",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLSVersion = 1
			},
		},
		{
			name: "version four",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLSVersion = 4
			},
		},
		{
			name: "password",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLSPassword = " "
			},
		},
		{
			name: "blank mapping",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLS = " "
			},
		},
		{
			name: "trailing semicolon",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLS = "bing.com;"
			},
		},
		{
			name: "raw ipv6 ambiguity",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLS = "example.com:2001:db8::1:443"
			},
		},
		{
			name: "port text",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLS = "bing.com:example.com:abc"
			},
		},
		{
			name: "port zero",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLS = "bing.com:example.com:0"
			},
		},
		{
			name: "port too large",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLS = "bing.com:example.com:65536"
			},
		},
		{
			name: "duplicate explicit sni",
			mutate: func(settings *TlsSettings) {
				settings.ShadowTLS = "a.com:x.com:443;a.com:y.com:443;fallback.com"
			},
		},
		{
			name: "wildcard",
			mutate: func(settings *TlsSettings) {
				settings.WildcardSNI = "maybe"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := valid
			tt.mutate(&settings)

			err := settings.ValidateShadowTLS()
			if err == nil {
				t.Fatalf("ValidateShadowTLS() error = nil, want error")
			}
			if strings.Contains(err.Error(), password) {
				t.Fatalf("ValidateShadowTLS() error leaked password: %v", err)
			}
		})
	}
}
