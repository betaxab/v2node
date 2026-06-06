package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	panel "github.com/wyx2685/v2node/api/v2board"
)

const shadowTLSBackendListenIP = "127.0.0.1"
const shadowTLSV3UserName = "node"

var shadowTLSBackendPortAllocator = allocateShadowTLSBackendPort
var shadowTLSRuntimeStarter = startShadowTLSRuntime

type shadowTLSBackendHandler struct {
	dialer  N.Dialer
	backend M.Socksaddr
}

type shadowTLSRuntime struct {
	listener net.Listener
	service  *shadowtls.Service
}

func (r *shadowTLSRuntime) Close() error {
	if r == nil || r.listener == nil {
		return nil
	}
	return r.listener.Close()
}

func (v *V2Core) hasShadowTLSRuntime(tag string) bool {
	v.shadowTLSMu.Lock()
	defer v.shadowTLSMu.Unlock()
	return v.shadowTLSRuntimes != nil && v.shadowTLSRuntimes[tag] != nil
}

func (v *V2Core) setShadowTLSRuntime(tag string, runtime *shadowTLSRuntime) error {
	if runtime == nil {
		return fmt.Errorf("shadowtls runtime is not configured")
	}
	v.shadowTLSMu.Lock()
	defer v.shadowTLSMu.Unlock()
	if v.shadowTLSRuntimes == nil {
		v.shadowTLSRuntimes = make(map[string]*shadowTLSRuntime)
	}
	if v.shadowTLSRuntimes[tag] != nil {
		return fmt.Errorf("shadowtls runtime already exists for tag %s", tag)
	}
	v.shadowTLSRuntimes[tag] = runtime
	return nil
}

func (v *V2Core) popShadowTLSRuntime(tag string) *shadowTLSRuntime {
	v.shadowTLSMu.Lock()
	defer v.shadowTLSMu.Unlock()
	if v.shadowTLSRuntimes == nil {
		return nil
	}
	runtime := v.shadowTLSRuntimes[tag]
	delete(v.shadowTLSRuntimes, tag)
	return runtime
}

func (v *V2Core) closeAllShadowTLSRuntimes() error {
	v.shadowTLSMu.Lock()
	runtimes := v.shadowTLSRuntimes
	v.shadowTLSRuntimes = make(map[string]*shadowTLSRuntime)
	v.shadowTLSMu.Unlock()

	var err error
	for tag, runtime := range runtimes {
		if closeErr := runtime.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close shadowtls runtime %s: %w", tag, closeErr))
		}
	}
	return err
}

func allocateShadowTLSBackendPort() (int, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(shadowTLSBackendListenIP, "0"))
	if err != nil {
		return 0, fmt.Errorf("allocate shadowtls backend port: %w", err)
	}
	defer listener.Close()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("allocate shadowtls backend port: unexpected listener address")
	}
	return addr.Port, nil
}

func buildShadowTLSBackendNodeInfo(nodeInfo *panel.NodeInfo, backendPort int) (*panel.NodeInfo, error) {
	if nodeInfo == nil || nodeInfo.Common == nil {
		return nil, fmt.Errorf("shadowtls node info is not valid")
	}
	if backendPort < 1 || backendPort > 65535 {
		return nil, fmt.Errorf("shadowtls backend port must be a valid TCP port")
	}
	backend := *nodeInfo
	common := *nodeInfo.Common
	backend.Common = &common
	backend.Security = panel.None
	backend.Common.Tls = panel.None
	backend.Common.ListenIP = shadowTLSBackendListenIP
	backend.Common.ServerPort = backendPort
	return &backend, nil
}

func startShadowTLSRuntime(nodeInfo *panel.NodeInfo, backendPort int) (*shadowTLSRuntime, error) {
	if nodeInfo == nil || nodeInfo.Common == nil {
		return nil, fmt.Errorf("shadowtls node info is not valid")
	}
	if backendPort < 1 || backendPort > 65535 {
		return nil, fmt.Errorf("shadowtls backend port must be a valid TCP port")
	}
	backend := M.ParseSocksaddrHostPort(shadowTLSBackendListenIP, uint16(backendPort))
	service, err := newShadowTLSService(nodeInfo, backend)
	if err != nil {
		return nil, err
	}

	listenAddress := buildShadowTLSPublicListenAddress(nodeInfo.Common.ListenIP, nodeInfo.Common.ServerPort)
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen shadowtls public endpoint: %w", err)
	}
	runtime := &shadowTLSRuntime{
		listener: listener,
		service:  service,
	}
	go runtime.acceptLoop()
	return runtime, nil
}

func buildShadowTLSPublicListenAddress(host string, port int) string {
	normalizedHost := strings.TrimSpace(host)
	if strings.HasPrefix(normalizedHost, "[") && strings.HasSuffix(normalizedHost, "]") {
		unwrappedHost := strings.TrimSuffix(strings.TrimPrefix(normalizedHost, "["), "]")
		if addr, err := netip.ParseAddr(unwrappedHost); err == nil {
			normalizedHost = addr.String()
		}
	}
	return net.JoinHostPort(normalizedHost, strconv.Itoa(port))
}

func (r *shadowTLSRuntime) acceptLoop() {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}
		go r.handleConnection(conn)
	}
}

func (r *shadowTLSRuntime) handleConnection(conn net.Conn) {
	err := r.service.NewConnection(
		context.Background(),
		conn,
		M.SocksaddrFromNet(conn.RemoteAddr()),
		M.SocksaddrFromNet(conn.LocalAddr()),
		func(error) {},
	)
	if err != nil {
		conn.Close()
	}
}

func newShadowTLSBackendHandler(backend M.Socksaddr) *shadowTLSBackendHandler {
	return &shadowTLSBackendHandler{
		dialer:  N.SystemDialer,
		backend: backend,
	}
}

func (h *shadowTLSBackendHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go h.handle(ctx, conn, onClose)
}

func (h *shadowTLSBackendHandler) handle(ctx context.Context, conn net.Conn, onClose N.CloseHandlerFunc) {
	var closeErr error
	defer func() {
		if onClose != nil {
			onClose(closeErr)
		}
	}()
	defer conn.Close()

	backendConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.backend)
	if err != nil {
		closeErr = fmt.Errorf("dial shadowtls backend: %w", err)
		return
	}
	defer backendConn.Close()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(backendConn, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, backendConn)
		errCh <- err
	}()
	closeErr = <-errCh
}

func buildShadowTLSServiceConfig(nodeInfo *panel.NodeInfo, handler N.TCPConnectionHandlerEx) (shadowtls.ServiceConfig, error) {
	if nodeInfo == nil || nodeInfo.Common == nil {
		return shadowtls.ServiceConfig{}, fmt.Errorf("shadowtls node info is not valid")
	}
	settings := nodeInfo.Common.TlsSettings
	if err := settings.ValidateShadowTLS(); err != nil {
		return shadowtls.ServiceConfig{}, err
	}
	if handler == nil {
		return shadowtls.ServiceConfig{}, fmt.Errorf("shadowtls backend handler is not configured")
	}
	mapping, err := settings.ParseShadowTLSMapping()
	if err != nil {
		return shadowtls.ServiceConfig{}, err
	}
	wildcardMode, err := settings.ShadowTLSWildcardSNI()
	if err != nil {
		return shadowtls.ServiceConfig{}, err
	}
	wildcardSNI, err := shadowTLSWildcardSNI(wildcardMode)
	if err != nil {
		return shadowtls.ServiceConfig{}, err
	}

	config := shadowtls.ServiceConfig{
		Version:                settings.ShadowTLSVersion,
		Handshake:              buildShadowTLSHandshakeConfig(mapping.Fallback),
		HandshakeForServerName: buildShadowTLSHandshakeForServerName(mapping.HandshakeForServerName),
		Handler:                handler,
		Logger:                 logger.NOP(),
		WildcardSNI:            wildcardSNI,
	}
	switch settings.ShadowTLSVersion {
	case 2:
		config.Password = settings.ShadowTLSPassword
	case 3:
		config.Users = []shadowtls.User{
			{Name: shadowTLSV3UserName, Password: settings.ShadowTLSPassword},
		}
	default:
		return shadowtls.ServiceConfig{}, fmt.Errorf("shadowtls version must be 2 or 3")
	}
	return config, nil
}

func buildShadowTLSHandshakeConfig(handshake panel.ShadowTLSHandshake) shadowtls.HandshakeConfig {
	return shadowtls.HandshakeConfig{
		Server: M.ParseSocksaddrHostPort(handshake.Host, handshake.Port),
		Dialer: N.SystemDialer,
	}
}

func buildShadowTLSHandshakeForServerName(mapping map[string]panel.ShadowTLSHandshake) map[string]shadowtls.HandshakeConfig {
	if len(mapping) == 0 {
		return nil
	}
	handshakes := make(map[string]shadowtls.HandshakeConfig, len(mapping))
	for serverName, handshake := range mapping {
		handshakes[serverName] = buildShadowTLSHandshakeConfig(handshake)
	}
	return handshakes
}

func shadowTLSWildcardSNI(mode string) (shadowtls.WildcardSNI, error) {
	switch mode {
	case "off":
		return shadowtls.WildcardSNIOff, nil
	case "authed":
		return shadowtls.WildcardSNIAuthed, nil
	case "all":
		return shadowtls.WildcardSNIAll, nil
	default:
		return 0, fmt.Errorf("shadowtls wildcard_sni must be off, authed, or all")
	}
}

func newShadowTLSService(nodeInfo *panel.NodeInfo, backend M.Socksaddr) (*shadowtls.Service, error) {
	config, err := buildShadowTLSServiceConfig(nodeInfo, newShadowTLSBackendHandler(backend))
	if err != nil {
		return nil, err
	}
	service, err := shadowtls.NewService(config)
	if err != nil {
		return nil, fmt.Errorf("create shadowtls service: %w", err)
	}
	return service, nil
}
