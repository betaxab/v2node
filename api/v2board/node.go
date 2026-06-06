package panel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"encoding/json"
)

// Security type
const (
	None      = 0
	Tls       = 1
	Reality   = 2
	ShadowTLS = 3
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	Tag          string
	Common       *CommonNode
}

type CommonNode struct {
	Protocol   string      `json:"protocol"`
	ListenIP   string      `json:"listen_ip"`
	ServerPort int         `json:"server_port"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
	//vless vmess trojan
	Tls                int         `json:"tls"`
	TlsSettings        TlsSettings `json:"tls_settings"`
	CertInfo           *CertInfo
	Network            string          `json:"network"`
	NetworkSettings    json.RawMessage `json:"network_settings"`
	Encryption         string          `json:"encryption"`
	EncryptionSettings EncSettings     `json:"encryption_settings"`
	ServerName         string          `json:"server_name"`
	Flow               string          `json:"flow"`
	//shadowsocks
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
	//tuic
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
	//anytls
	PaddingScheme []string `json:"padding_scheme,omitempty"`
	//hysteria hysteria2
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	Obfs                    string `json:"obfs"`
	ObfsPassword            string `json:"obfs_password"`
	Ignore_Client_Bandwidth bool   `json:"ignore_client_bandwidth"`
}

type Route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue *string  `json:"action_value"`
}

type BaseConfig struct {
	PushInterval           any `json:"push_interval"`
	PullInterval           any `json:"pull_interval"`
	DeviceOnlineMinTraffic int `json:"device_online_min_traffic"`
	NodeReportMinTraffic   int `json:"node_report_min_traffic"`
}

type TlsSettings struct {
	ServerName        string   `json:"server_name"`
	ServerNames       []string `json:"server_names"`
	Dest              string   `json:"dest"`
	ServerPort        string   `json:"server_port"`
	ShortId           string   `json:"short_id"`
	ShortIds          []string `json:"short_ids"`
	PrivateKey        string   `json:"private_key"`
	Mldsa65Seed       string   `json:"mldsa65Seed"`
	Xver              uint64   `json:"xver,string"`
	CertMode          string   `json:"cert_mode"`
	CertFile          string   `json:"cert_file"`
	KeyFile           string   `json:"key_file"`
	Provider          string   `json:"provider"`
	DNSEnv            string   `json:"dns_env"`
	RejectUnknownSni  string   `json:"reject_unknown_sni"`
	Plugin            string   `json:"plugin"`
	ShadowTLS         string   `json:"shadow_tls"`
	ShadowTLSVersion  int      `json:"shadow_tls_version"`
	ShadowTLSPassword string   `json:"shadow_tls_password"`
	WildcardSNI       string   `json:"wildcard_sni"`
}

type ShadowTLSHandshake struct {
	ServerName string
	Host       string
	Port       uint16
}

type ShadowTLSMapping struct {
	Fallback               ShadowTLSHandshake
	HandshakeForServerName map[string]ShadowTLSHandshake
}

type CertInfo struct {
	CertMode         string
	CertFile         string
	KeyFile          string
	Email            string
	CertDomain       string
	DNSEnv           map[string]string
	Provider         string
	RejectUnknownSni bool
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

func (c *Client) GetNodeInfo(ctx context.Context) (node *NodeInfo, err error) {
	const path = "/api/v2/server/config"
	r, err := c.client.
		R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}

	if r.StatusCode() == 304 {
		return nil, nil
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")

	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("received nil response")
	}
	node = &NodeInfo{
		Id: c.NodeId,
	}
	// parse protocol params
	cm := &CommonNode{}
	err = json.Unmarshal(r.Body(), cm)
	if err != nil {
		return nil, fmt.Errorf("decode node params error: %s", err)
	}
	if err := applyNodeProtocol(node, cm); err != nil {
		return nil, err
	}
	node.Tag = fmt.Sprintf("[%s]-%s:%d", c.APIHost, node.Type, node.Id)
	cf := cm.TlsSettings.CertFile
	kf := cm.TlsSettings.KeyFile
	if cf == "" {
		cf = filepath.Join("/etc/v2node/", cm.Protocol+strconv.Itoa(c.NodeId)+".cer")
	}
	if kf == "" {
		kf = filepath.Join("/etc/v2node/", cm.Protocol+strconv.Itoa(c.NodeId)+".key")
	}
	cm.CertInfo = &CertInfo{
		CertMode:         cm.TlsSettings.CertMode,
		CertFile:         cf,
		KeyFile:          kf,
		Email:            "node@v2board.com",
		CertDomain:       cm.TlsSettings.PrimaryServerName(),
		DNSEnv:           make(map[string]string),
		Provider:         cm.TlsSettings.Provider,
		RejectUnknownSni: cm.TlsSettings.RejectUnknownSni == "1",
	}
	if cm.CertInfo.CertMode == "dns" && cm.TlsSettings.DNSEnv != "" {
		envs := strings.Split(cm.TlsSettings.DNSEnv, ",")
		for _, env := range envs {
			kv := strings.SplitN(env, "=", 2)
			if len(kv) == 2 {
				cm.CertInfo.DNSEnv[kv[0]] = kv[1]
			}
		}
	}

	// set interval
	node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
	node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)

	node.Common = cm

	return node, nil
}

func applyNodeProtocol(node *NodeInfo, cm *CommonNode) error {
	switch cm.Protocol {
	case "vmess", "trojan", "hysteria2", "tuic", "anytls", "vless":
		node.Type = cm.Protocol
		node.Security = cm.Tls
	case "shadowsocks":
		node.Type = cm.Protocol
		node.Security = None
		if cm.IsShadowTLS() {
			if err := cm.TlsSettings.ValidateShadowTLS(); err != nil {
				return err
			}
			node.Security = ShadowTLS
		}
	default:
		return fmt.Errorf("unsupport protocol: %s", cm.Protocol)
	}
	return nil
}

func (c *CommonNode) IsShadowTLS() bool {
	return c.Protocol == "shadowsocks" && c.Tls == ShadowTLS
}

func (t TlsSettings) ValidateShadowTLS() error {
	if strings.TrimSpace(t.Plugin) != "shadow-tls" {
		return fmt.Errorf("shadowtls plugin must be shadow-tls")
	}
	if t.ShadowTLSVersion != 2 && t.ShadowTLSVersion != 3 {
		return fmt.Errorf("shadowtls version must be 2 or 3")
	}
	if strings.TrimSpace(t.ShadowTLSPassword) == "" {
		return fmt.Errorf("shadowtls password must not be empty")
	}
	if _, err := t.ParseShadowTLSMapping(); err != nil {
		return err
	}
	if _, err := t.ShadowTLSWildcardSNI(); err != nil {
		return err
	}
	return nil
}

func (t TlsSettings) ParseShadowTLSMapping() (ShadowTLSMapping, error) {
	shadowTLS := strings.TrimSpace(t.ShadowTLS)
	if shadowTLS == "" {
		return ShadowTLSMapping{}, fmt.Errorf("shadowtls mapping must not be empty")
	}

	rawEntries := strings.Split(shadowTLS, ";")
	entries := make([]ShadowTLSHandshake, 0, len(rawEntries))
	for _, rawEntry := range rawEntries {
		entry, err := parseShadowTLSEntry(rawEntry)
		if err != nil {
			return ShadowTLSMapping{}, err
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return ShadowTLSMapping{}, fmt.Errorf("shadowtls mapping must not be empty")
	}

	mapping := ShadowTLSMapping{
		Fallback: entries[len(entries)-1],
	}
	if len(entries) > 1 {
		mapping.HandshakeForServerName = make(map[string]ShadowTLSHandshake, len(entries)-1)
		for _, entry := range entries[:len(entries)-1] {
			if _, exists := mapping.HandshakeForServerName[entry.ServerName]; exists {
				return ShadowTLSMapping{}, fmt.Errorf("shadowtls mapping server name must be unique")
			}
			mapping.HandshakeForServerName[entry.ServerName] = entry
		}
	}
	return mapping, nil
}

func (t TlsSettings) ShadowTLSWildcardSNI() (string, error) {
	mode := strings.TrimSpace(t.WildcardSNI)
	if mode == "" {
		mode = "off"
	}
	switch mode {
	case "off", "authed", "all":
		return mode, nil
	default:
		return "", fmt.Errorf("shadowtls wildcard_sni must be off, authed, or all")
	}
}

func parseShadowTLSEntry(rawEntry string) (ShadowTLSHandshake, error) {
	entry := strings.TrimSpace(rawEntry)
	if entry == "" {
		return ShadowTLSHandshake{}, fmt.Errorf("shadowtls mapping entry must not be empty")
	}
	fields, err := splitShadowTLSEntry(entry)
	if err != nil {
		return ShadowTLSHandshake{}, err
	}
	if len(fields) == 0 || len(fields) > 3 {
		return ShadowTLSHandshake{}, fmt.Errorf("shadowtls mapping entry must be ServerName[:Host[:Port]]")
	}

	serverName := strings.TrimSpace(fields[0])
	if serverName == "" || strings.HasPrefix(serverName, "[") || strings.Contains(serverName, ":") {
		return ShadowTLSHandshake{}, fmt.Errorf("shadowtls server name must be valid")
	}

	host := serverName
	portText := "443"
	switch len(fields) {
	case 2:
		second := strings.TrimSpace(fields[1])
		if second == "" {
			return ShadowTLSHandshake{}, fmt.Errorf("shadowtls host or port must not be empty")
		}
		if isPortText(second) {
			portText = second
		} else {
			host = second
		}
	case 3:
		host = strings.TrimSpace(fields[1])
		portText = strings.TrimSpace(fields[2])
	}
	if host == "" {
		return ShadowTLSHandshake{}, fmt.Errorf("shadowtls host must not be empty")
	}
	if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
		if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") || len(host) <= 2 {
			return ShadowTLSHandshake{}, fmt.Errorf("shadowtls bracket ipv6 host must be valid")
		}
	}
	if strings.Contains(host, ":") && !(strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]")) {
		return ShadowTLSHandshake{}, fmt.Errorf("shadowtls raw ipv6 host is ambiguous")
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return ShadowTLSHandshake{}, fmt.Errorf("shadowtls port must be a valid TCP port")
	}

	return ShadowTLSHandshake{
		ServerName: serverName,
		Host:       host,
		Port:       uint16(port),
	}, nil
}

func splitShadowTLSEntry(entry string) ([]string, error) {
	fields := []string{}
	start := 0
	inBracket := false
	for i, r := range entry {
		switch r {
		case '[':
			if inBracket {
				return nil, fmt.Errorf("shadowtls bracket ipv6 host must be valid")
			}
			inBracket = true
		case ']':
			if !inBracket {
				return nil, fmt.Errorf("shadowtls bracket ipv6 host must be valid")
			}
			inBracket = false
		case ':':
			if !inBracket {
				fields = append(fields, strings.TrimSpace(entry[start:i]))
				start = i + 1
			}
		}
	}
	if inBracket {
		return nil, fmt.Errorf("shadowtls bracket ipv6 host must be valid")
	}
	fields = append(fields, strings.TrimSpace(entry[start:]))
	return fields, nil
}

func isPortText(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func intervalToTime(i interface{}) time.Duration {
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int:
		return time.Duration(i.(int)) * time.Second
	case reflect.String:
		i, _ := strconv.Atoi(i.(string))
		return time.Duration(i) * time.Second
	case reflect.Float64:
		return time.Duration(i.(float64)) * time.Second
	default:
		return time.Duration(reflect.ValueOf(i).Int()) * time.Second
	}
}

func (t TlsSettings) EffectiveServerNames() []string {
	if len(t.ServerNames) > 0 {
		return t.ServerNames
	}
	if t.ServerName == "" {
		return nil
	}
	return []string{t.ServerName}
}

func (t TlsSettings) EffectiveShortIds() []string {
	if len(t.ShortIds) > 0 {
		return t.ShortIds
	}
	if t.ShortId == "" {
		return nil
	}
	return []string{t.ShortId}
}

func (t TlsSettings) PrimaryServerName() string {
	serverNames := t.EffectiveServerNames()
	if len(serverNames) == 0 {
		return ""
	}
	return serverNames[0]
}
