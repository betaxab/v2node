package core

import (
	"encoding/json"
	"strings"
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
	xrayCore "github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestBuildInboundRejectsDirectShadowTLSShadowsocks(t *testing.T) {
	const password = "super-secret-shadowtls-password"
	node := &panel.NodeInfo{
		Type:     "shadowsocks",
		Security: panel.ShadowTLS,
		Common: &panel.CommonNode{
			Protocol:   "shadowsocks",
			ListenIP:   "127.0.0.1",
			ServerPort: 12345,
			Cipher:     "aes-128-gcm",
			TlsSettings: panel.TlsSettings{
				ShadowTLSPassword: password,
			},
		},
	}

	inbound, err := buildInbound(node, "shadowtls-test")
	if err == nil {
		t.Fatalf("buildInbound() error = nil, want ShadowTLS unsupported error")
	}
	if inbound != nil {
		t.Fatalf("buildInbound() inbound = %v, want nil", inbound)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "shadowtls") {
		t.Fatalf("buildInbound() error = %q, want it to mention shadowtls", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "not implemented") {
		t.Fatalf("buildInbound() error = %q, want runtime-path guard instead of not-implemented guard", err)
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("buildInbound() error leaked ShadowTLS password: %v", err)
	}
}

func TestBuildShadowTLSBackendInboundBuildsOrdinaryLoopbackShadowsocks(t *testing.T) {
	original := &panel.NodeInfo{
		Type:     "shadowsocks",
		Security: panel.ShadowTLS,
		Common: &panel.CommonNode{
			Protocol:   "shadowsocks",
			ListenIP:   "0.0.0.0",
			ServerPort: 443,
			Cipher:     "aes-128-gcm",
			Tls:        panel.ShadowTLS,
			TlsSettings: panel.TlsSettings{
				Plugin:            "shadow-tls",
				ShadowTLSVersion:  2,
				ShadowTLSPassword: "super-secret-shadowtls-password",
				ShadowTLS:         "example.com",
			},
		},
	}

	backend, err := buildShadowTLSBackendNodeInfo(original, 23456)
	if err != nil {
		t.Fatalf("buildShadowTLSBackendNodeInfo() error = %v", err)
	}
	if backend.Security != panel.None {
		t.Fatalf("backend.Security = %d, want panel.None", backend.Security)
	}
	if backend.Common.ListenIP != "127.0.0.1" {
		t.Fatalf("backend listen IP = %q, want 127.0.0.1", backend.Common.ListenIP)
	}
	if backend.Common.ServerPort != 23456 {
		t.Fatalf("backend port = %d, want 23456", backend.Common.ServerPort)
	}
	if original.Security != panel.ShadowTLS {
		t.Fatalf("original.Security = %d, want unchanged ShadowTLS", original.Security)
	}
	if original.Common.ListenIP != "0.0.0.0" || original.Common.ServerPort != 443 {
		t.Fatalf("original public endpoint mutated to %s:%d", original.Common.ListenIP, original.Common.ServerPort)
	}

	inbound, err := buildInbound(backend, "shadowtls-backend")
	if err != nil {
		t.Fatalf("buildInbound(backend) error = %v", err)
	}
	if inbound == nil {
		t.Fatalf("buildInbound(backend) inbound = nil, want config")
	}
	if inbound.Tag != "shadowtls-backend" {
		t.Fatalf("inbound.Tag = %q, want original tag", inbound.Tag)
	}
}

func TestBuildInboundOrdinaryShadowsocksStillBuilds(t *testing.T) {
	const tag = "shadowsocks-test"
	node := ordinaryShadowsocksNodeInfo("aes-128-gcm")

	inbound, settings, _ := buildOrdinaryShadowsocksTestConfig(t, node, tag)
	if inbound.Tag != tag {
		t.Fatalf("inbound.Tag = %q, want %q", inbound.Tag, tag)
	}
	if settings.NetworkList == nil {
		t.Fatalf("settings.NetworkList = nil, want tcp+udp")
	}
	assertNetworkList(t, *settings.NetworkList, []string{"tcp", "udp"})
	if len(settings.Users) != 1 {
		t.Fatalf("settings.Users length = %d, want 1", len(settings.Users))
	}
	if settings.Users[0].Cipher != "aes-128-gcm" {
		t.Fatalf("default user cipher = %q, want aes-128-gcm", settings.Users[0].Cipher)
	}
}

func TestBuildInboundShadowsocks2022ServerKeyInvariants(t *testing.T) {
	const serverKey = "server-key-sentinel"
	node := ordinaryShadowsocksNodeInfo("2022-blake3-aes-128-gcm")
	node.Common.ServerKey = serverKey

	_, settings, _ := buildOrdinaryShadowsocksTestConfig(t, node, "ss2022-test")
	if settings.Password != serverKey {
		t.Fatalf("settings.Password = %q, want server key", settings.Password)
	}
	if len(settings.Users) != 1 {
		t.Fatalf("settings.Users length = %d, want 1", len(settings.Users))
	}
	user := settings.Users[0]
	if user.Cipher != "" {
		t.Fatalf("default user cipher = %q, want empty for server-key mode", user.Cipher)
	}
	if user.Password == "" {
		t.Fatalf("default user password is empty, want generated password")
	}
	if user.Password == serverKey {
		t.Fatalf("default user password equals server key, want generated password")
	}
}

func TestBuildInboundShadowsocksProxyProtocolOnly(t *testing.T) {
	node := ordinaryShadowsocksNodeInfo("aes-128-gcm")
	node.Common.NetworkSettings = json.RawMessage(`{"acceptProxyProtocol":true}`)

	_, settings, detour := buildOrdinaryShadowsocksTestConfig(t, node, "proxy-only-test")
	assertNetworkList(t, *settings.NetworkList, []string{"tcp", "udp"})
	tcp := requireTCPSettings(t, detour)
	if !tcp.AcceptProxyProtocol {
		t.Fatalf("TCPSettings.AcceptProxyProtocol = false, want true")
	}
	if len(tcp.HeaderConfig) != 0 {
		t.Fatalf("TCPSettings.HeaderConfig = %s, want empty for proxy-only", string(tcp.HeaderConfig))
	}
}

func TestBuildInboundShadowsocksHTTPObfsOnly(t *testing.T) {
	node := ordinaryShadowsocksNodeInfo("aes-128-gcm")
	node.Common.NetworkSettings = json.RawMessage(`{"path":"/obfs","Host":"example.com"}`)

	_, settings, detour := buildOrdinaryShadowsocksTestConfig(t, node, "obfs-only-test")
	assertNetworkList(t, *settings.NetworkList, []string{"tcp"})
	tcp := requireTCPSettings(t, detour)
	if tcp.AcceptProxyProtocol {
		t.Fatalf("TCPSettings.AcceptProxyProtocol = true, want false")
	}
	assertHTTPHeader(t, tcp.HeaderConfig, "/obfs", "example.com")
}

func TestBuildInboundShadowsocksHTTPObfsWithProxyProtocol(t *testing.T) {
	node := ordinaryShadowsocksNodeInfo("aes-128-gcm")
	node.Common.NetworkSettings = json.RawMessage(`{"acceptProxyProtocol":true,"path":"/obfs","Host":"example.com"}`)

	_, settings, detour := buildOrdinaryShadowsocksTestConfig(t, node, "obfs-proxy-test")
	assertNetworkList(t, *settings.NetworkList, []string{"tcp"})
	tcp := requireTCPSettings(t, detour)
	if !tcp.AcceptProxyProtocol {
		t.Fatalf("TCPSettings.AcceptProxyProtocol = false, want true")
	}
	assertHTTPHeader(t, tcp.HeaderConfig, "/obfs", "example.com")
}

func ordinaryShadowsocksNodeInfo(cipher string) *panel.NodeInfo {
	return &panel.NodeInfo{
		Type:     "shadowsocks",
		Security: panel.None,
		Common: &panel.CommonNode{
			Protocol:   "shadowsocks",
			ListenIP:   "127.0.0.1",
			ServerPort: 12345,
			Cipher:     cipher,
		},
	}
}

func buildOrdinaryShadowsocksTestConfig(t *testing.T, node *panel.NodeInfo, tag string) (*xrayCore.InboundHandlerConfig, *coreConf.ShadowsocksServerConfig, *coreConf.InboundDetourConfig) {
	t.Helper()
	inbound, err := buildInbound(node, tag)
	if err != nil {
		t.Fatalf("buildInbound() error = %v", err)
	}
	if inbound == nil {
		t.Fatalf("buildInbound() inbound = nil, want config")
	}

	detour := &coreConf.InboundDetourConfig{}
	if err := buildShadowsocks(node, detour); err != nil {
		t.Fatalf("buildShadowsocks() error = %v", err)
	}
	settings := decodeShadowsocksSettings(t, detour.Settings)
	return inbound, settings, detour
}

func decodeShadowsocksSettings(t *testing.T, raw *json.RawMessage) *coreConf.ShadowsocksServerConfig {
	t.Helper()
	if raw == nil {
		t.Fatalf("shadowsocks settings = nil, want config")
	}
	settings := &coreConf.ShadowsocksServerConfig{}
	if err := json.Unmarshal(*raw, settings); err != nil {
		t.Fatalf("decode shadowsocks settings: %v", err)
	}
	return settings
}

func assertNetworkList(t *testing.T, actual coreConf.NetworkList, want []string) {
	t.Helper()
	if len(actual) != len(want) {
		t.Fatalf("network list length = %d, want %d: %v", len(actual), len(want), actual)
	}
	for i, network := range want {
		if string(actual[i]) != network {
			t.Fatalf("network[%d] = %q, want %q", i, actual[i], network)
		}
	}
}

func requireTCPSettings(t *testing.T, detour *coreConf.InboundDetourConfig) *coreConf.TCPConfig {
	t.Helper()
	if detour.StreamSetting == nil {
		t.Fatalf("StreamSetting = nil, want tcp stream settings")
	}
	if detour.StreamSetting.Network == nil || string(*detour.StreamSetting.Network) != "tcp" {
		t.Fatalf("StreamSetting.Network = %v, want tcp", detour.StreamSetting.Network)
	}
	if detour.StreamSetting.TCPSettings == nil {
		t.Fatalf("TCPSettings = nil, want config")
	}
	return detour.StreamSetting.TCPSettings
}

func assertHTTPHeader(t *testing.T, raw json.RawMessage, wantPath string, wantHost string) {
	t.Helper()
	var header struct {
		Type    string `json:"type"`
		Request struct {
			Path    []string            `json:"path"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("decode TCP header config: %v", err)
	}
	if header.Type != "http" {
		t.Fatalf("header type = %q, want http", header.Type)
	}
	if len(header.Request.Path) != 1 || header.Request.Path[0] != wantPath {
		t.Fatalf("header path = %v, want [%s]", header.Request.Path, wantPath)
	}
	if got := header.Request.Headers["Host"]; len(got) != 1 || got[0] != wantHost {
		t.Fatalf("header Host = %v, want [%s]", got, wantHost)
	}
}
