package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	panel "github.com/wyx2685/v2node/api/v2board"
	xrayCore "github.com/xtls/xray-core/core"
)

func TestBuildShadowTLSServiceConfigVersion2UsesPassword(t *testing.T) {
	const password = "sentinel-shadowtls-password"
	node := shadowTLSNodeInfo(2, password)
	handler := newShadowTLSBackendHandler(M.ParseSocksaddrHostPort("127.0.0.1", 12000))

	config, err := buildShadowTLSServiceConfig(node, handler)
	if err != nil {
		t.Fatalf("buildShadowTLSServiceConfig() error = %v", err)
	}

	if config.Version != 2 {
		t.Fatalf("config.Version = %d, want 2", config.Version)
	}
	if config.Password != password {
		t.Fatalf("config.Password = %q, want configured password", config.Password)
	}
	if len(config.Users) != 0 {
		t.Fatalf("config.Users length = %d, want 0 for v2", len(config.Users))
	}
	assertShadowTLSHandshake(t, config.Handshake.Server, "example.com", 443)
	if config.Handler == nil {
		t.Fatalf("config.Handler = nil, want handler")
	}
	if config.Logger == nil {
		t.Fatalf("config.Logger = nil, want logger")
	}
	if config.WildcardSNI != 0 {
		t.Fatalf("config.WildcardSNI = %d, want off", config.WildcardSNI)
	}
}

func TestBuildShadowTLSServiceConfigVersion3UsesSingleUser(t *testing.T) {
	const password = "sentinel-shadowtls-password"
	node := shadowTLSNodeInfo(3, password)
	node.Common.TlsSettings.ShadowTLS = "custom.example:backend.example:8443;fallback.example:8443"
	handler := newShadowTLSBackendHandler(M.ParseSocksaddrHostPort("127.0.0.1", 12000))

	config, err := buildShadowTLSServiceConfig(node, handler)
	if err != nil {
		t.Fatalf("buildShadowTLSServiceConfig() error = %v", err)
	}

	if config.Version != 3 {
		t.Fatalf("config.Version = %d, want 3", config.Version)
	}
	if config.Password != "" {
		t.Fatalf("config.Password = %q, want empty for v3", config.Password)
	}
	if len(config.Users) != 1 {
		t.Fatalf("config.Users length = %d, want 1", len(config.Users))
	}
	if config.Users[0].Name != shadowTLSV3UserName {
		t.Fatalf("config.Users[0].Name = %q, want %q", config.Users[0].Name, shadowTLSV3UserName)
	}
	if config.Users[0].Password != password {
		t.Fatalf("config.Users[0].Password = %q, want configured password", config.Users[0].Password)
	}
	assertShadowTLSHandshake(t, config.Handshake.Server, "fallback.example", 8443)
}

func TestBuildShadowTLSServiceConfigMapsExplicitServerNameHandshakes(t *testing.T) {
	const password = "sentinel-shadowtls-password"
	node := shadowTLSNodeInfo(2, password)
	node.Common.TlsSettings.ShadowTLS = "your.domain:127.0.0.1:8443;captive.apple.com;www.feishu.cn"
	handler := newShadowTLSBackendHandler(M.ParseSocksaddrHostPort("127.0.0.1", 12000))

	config, err := buildShadowTLSServiceConfig(node, handler)
	if err != nil {
		t.Fatalf("buildShadowTLSServiceConfig() error = %v", err)
	}

	assertShadowTLSHandshake(t, config.Handshake.Server, "www.feishu.cn", 443)
	if len(config.HandshakeForServerName) != 2 {
		t.Fatalf("HandshakeForServerName length = %d, want 2", len(config.HandshakeForServerName))
	}
	assertShadowTLSHandshake(t, config.HandshakeForServerName["your.domain"].Server, "127.0.0.1", 8443)
	assertShadowTLSHandshake(t, config.HandshakeForServerName["captive.apple.com"].Server, "captive.apple.com", 443)
}

func TestBuildShadowTLSServiceConfigMapsWildcardSNI(t *testing.T) {
	const password = "sentinel-shadowtls-password"
	tests := []struct {
		name string
		mode string
		want int
	}{
		{name: "default off", mode: "", want: int(shadowtls.WildcardSNIOff)},
		{name: "explicit off", mode: "off", want: int(shadowtls.WildcardSNIOff)},
		{name: "authed", mode: "authed", want: int(shadowtls.WildcardSNIAuthed)},
		{name: "all", mode: "all", want: int(shadowtls.WildcardSNIAll)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := shadowTLSNodeInfo(2, password)
			node.Common.TlsSettings.WildcardSNI = tt.mode
			handler := newShadowTLSBackendHandler(M.ParseSocksaddrHostPort("127.0.0.1", 12000))

			config, err := buildShadowTLSServiceConfig(node, handler)
			if err != nil {
				t.Fatalf("buildShadowTLSServiceConfig() error = %v", err)
			}
			if int(config.WildcardSNI) != tt.want {
				t.Fatalf("config.WildcardSNI = %d, want %d", config.WildcardSNI, tt.want)
			}
		})
	}
}

func TestBuildShadowTLSServiceConfigRejectsBadConfigWithoutPasswordLeak(t *testing.T) {
	const password = "sentinel-shadowtls-password"
	node := shadowTLSNodeInfo(4, password)
	handler := newShadowTLSBackendHandler(M.ParseSocksaddrHostPort("127.0.0.1", 12000))

	_, err := buildShadowTLSServiceConfig(node, handler)
	if err == nil {
		t.Fatalf("buildShadowTLSServiceConfig() error = nil, want error")
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("buildShadowTLSServiceConfig() error leaked password: %v", err)
	}
}

func TestBuildShadowTLSServiceConfigRejectsNilHandler(t *testing.T) {
	const password = "sentinel-shadowtls-password"
	node := shadowTLSNodeInfo(2, password)

	_, err := buildShadowTLSServiceConfig(node, nil)
	if err == nil {
		t.Fatalf("buildShadowTLSServiceConfig() error = nil, want error")
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("buildShadowTLSServiceConfig() error leaked password: %v", err)
	}
}

func TestShadowTLSBackendHandlerImplementsTCPConnectionHandlerEx(t *testing.T) {
	var _ N.TCPConnectionHandlerEx = newShadowTLSBackendHandler(M.ParseSocksaddrHostPort("127.0.0.1", 12000))
}

func TestShadowTLSBackendHandlerPreservesHalfCloseDuringLargeBidirectionalTransfer(t *testing.T) {
	const payloadSize = 4 << 20
	deadline := time.Now().Add(10 * time.Second)

	clientListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen for authenticated client: %v", err)
	}
	defer clientListener.Close()
	if err := clientListener.SetDeadline(deadline); err != nil {
		t.Fatalf("set authenticated client listener deadline: %v", err)
	}

	clientConn, err := net.DialTCP("tcp", nil, clientListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial authenticated client connection: %v", err)
	}
	defer clientConn.Close()
	relayConn, err := clientListener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept authenticated client connection: %v", err)
	}
	defer relayConn.Close()
	for name, conn := range map[string]*net.TCPConn{
		"client": clientConn,
		"relay":  relayConn,
	} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set %s connection deadline: %v", name, err)
		}
	}

	backendListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen for shadowtls backend: %v", err)
	}
	defer backendListener.Close()
	if err := backendListener.SetDeadline(deadline); err != nil {
		t.Fatalf("set shadowtls backend listener deadline: %v", err)
	}
	backendAddr := backendListener.Addr().(*net.TCPAddr)
	handler := newShadowTLSBackendHandler(M.ParseSocksaddrHostPort(backendAddr.IP.String(), uint16(backendAddr.Port)))
	onClose := make(chan error, 2)
	handler.NewConnectionEx(context.Background(), relayConn, M.Socksaddr{}, M.Socksaddr{}, func(err error) {
		onClose <- err
	})

	backendConn, err := backendListener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept shadowtls backend connection: %v", err)
	}
	defer backendConn.Close()
	if err := backendConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set shadowtls backend connection deadline: %v", err)
	}

	requestPattern := []byte("shadowtls-request-0123456789")
	request := bytes.Repeat(requestPattern, payloadSize/len(requestPattern)+1)[:payloadSize]
	responsePattern := []byte("shadowtls-response-9876543210")
	response := bytes.Repeat(responsePattern, payloadSize/len(responsePattern)+1)[:payloadSize]

	type backendResult struct {
		request       []byte
		readErr       error
		responseBytes int64
		writeErr      error
		closeWriteErr error
	}
	backendDone := make(chan backendResult, 1)
	go func() {
		gotRequest, readErr := io.ReadAll(backendConn)
		var responseBytes int64
		var writeErr error
		var closeWriteErr error
		if readErr == nil {
			responseBytes, writeErr = io.Copy(backendConn, bytes.NewReader(response))
			if writeErr == nil {
				closeWriteErr = backendConn.CloseWrite()
			}
		}
		backendDone <- backendResult{
			request:       gotRequest,
			readErr:       readErr,
			responseBytes: responseBytes,
			writeErr:      writeErr,
			closeWriteErr: closeWriteErr,
		}
	}()

	requestBytes, requestWriteErr := io.Copy(clientConn, bytes.NewReader(request))
	clientCloseWriteErr := clientConn.CloseWrite()
	gotResponse, responseReadErr := io.ReadAll(clientConn)
	result := <-backendDone

	var closeErr error
	select {
	case closeErr = <-onClose:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for shadowtls backend handler onClose callback")
	}

	if requestWriteErr != nil {
		t.Fatalf("client request write failed after %d bytes: %v", requestBytes, requestWriteErr)
	}
	if requestBytes != int64(len(request)) {
		t.Fatalf("client request bytes = %d, want %d", requestBytes, len(request))
	}
	if clientCloseWriteErr != nil {
		t.Fatalf("client CloseWrite() error = %v", clientCloseWriteErr)
	}
	if result.readErr != nil {
		t.Fatalf("backend request read error = %v", result.readErr)
	}
	if !bytes.Equal(result.request, request) {
		t.Fatalf("backend request mismatch: got %d bytes, want %d", len(result.request), len(request))
	}
	if result.writeErr != nil {
		t.Fatalf("backend response write failed after request EOF at %d/%d bytes: %v", result.responseBytes, len(response), result.writeErr)
	}
	if result.responseBytes != int64(len(response)) {
		t.Fatalf("backend response bytes = %d, want %d", result.responseBytes, len(response))
	}
	if result.closeWriteErr != nil {
		t.Fatalf("backend CloseWrite() error = %v", result.closeWriteErr)
	}
	if responseReadErr != nil {
		t.Fatalf("client response read error after %d/%d bytes: %v", len(gotResponse), len(response), responseReadErr)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("client response mismatch: got %d bytes, want %d", len(gotResponse), len(response))
	}
	if closeErr != nil {
		t.Fatalf("onClose error = %v, want nil", closeErr)
	}
	select {
	case secondErr := <-onClose:
		t.Fatalf("onClose called more than once; second error = %v", secondErr)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestShadowTLSV3SustainsLargeDownloadThroughAuthenticatedService(t *testing.T) {
	const (
		password    = "sentinel-shadowtls-password"
		payloadSize = 4 << 20
	)
	deadline := time.Now().Add(15 * time.Second)

	handshakeServer := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	handshakeServer.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	handshakeServer.StartTLS()
	defer handshakeServer.Close()

	backendListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen for shadowtls backend: %v", err)
	}
	defer backendListener.Close()
	if err := backendListener.SetDeadline(deadline); err != nil {
		t.Fatalf("set shadowtls backend listener deadline: %v", err)
	}
	backendAddr := backendListener.Addr().(*net.TCPAddr)

	service, err := shadowtls.NewService(shadowtls.ServiceConfig{
		Version: 3,
		Users: []shadowtls.User{{
			Name:     shadowTLSV3UserName,
			Password: password,
		}},
		Handshake: shadowtls.HandshakeConfig{
			Server: M.SocksaddrFromNet(handshakeServer.Listener.Addr()),
			Dialer: N.SystemDialer,
		},
		Handler: newShadowTLSBackendHandler(
			M.ParseSocksaddrHostPort(backendAddr.IP.String(), uint16(backendAddr.Port)),
		),
		Logger: logger.NOP(),
	})
	if err != nil {
		t.Fatalf("create shadowtls service: %v", err)
	}

	shadowListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen for shadowtls client: %v", err)
	}
	defer shadowListener.Close()
	if err := shadowListener.SetDeadline(deadline); err != nil {
		t.Fatalf("set shadowtls listener deadline: %v", err)
	}

	serviceResult := make(chan error, 1)
	go func() {
		conn, acceptErr := shadowListener.AcceptTCP()
		if acceptErr != nil {
			serviceResult <- acceptErr
			return
		}
		_ = conn.SetDeadline(deadline)
		serviceResult <- service.NewConnection(
			context.Background(),
			conn,
			M.SocksaddrFromNet(conn.RemoteAddr()),
			M.SocksaddrFromNet(conn.LocalAddr()),
			func(error) {},
		)
	}()

	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:  3,
		Password: password,
		Server:   M.SocksaddrFromNet(shadowListener.Addr()),
		Dialer:   N.SystemDialer,
		TLSHandshake: shadowtls.DefaultTLSHandshakeFunc(password, &tls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}),
		Logger: logger.NOP(),
	})
	if err != nil {
		t.Fatalf("create shadowtls client: %v", err)
	}
	clientConn, err := client.DialContext(context.Background())
	if err != nil {
		t.Fatalf("dial shadowtls service: %v", err)
	}
	defer clientConn.Close()
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set shadowtls client deadline: %v", err)
	}

	request := []byte("start-download")
	if _, err := clientConn.Write(request); err != nil {
		t.Fatalf("write authenticated request: %v", err)
	}

	backendConn, err := backendListener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept shadowtls backend connection: %v", err)
	}
	defer backendConn.Close()
	if err := backendConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set shadowtls backend connection deadline: %v", err)
	}
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(backendConn, gotRequest); err != nil {
		t.Fatalf("read authenticated request at backend: %v", err)
	}
	if !bytes.Equal(gotRequest, request) {
		t.Fatalf("backend request = %q, want %q", gotRequest, request)
	}

	payloadPattern := []byte("shadowtls-v3-download-0123456789")
	payload := bytes.Repeat(payloadPattern, payloadSize/len(payloadPattern)+1)[:payloadSize]
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := io.Copy(backendConn, bytes.NewReader(payload))
		writeResult <- writeErr
	}()

	gotPayload := make([]byte, len(payload))
	readBytes, readErr := io.ReadFull(clientConn, gotPayload)
	if readErr != nil {
		t.Fatalf("read shadowtls v3 download failed at %d/%d bytes: %v", readBytes, len(payload), readErr)
	}
	if writeErr := <-writeResult; writeErr != nil {
		t.Fatalf("write shadowtls v3 backend response: %v", writeErr)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("shadowtls v3 response mismatch: got %d bytes, want %d", len(gotPayload), len(payload))
	}

	select {
	case err := <-serviceResult:
		if err != nil {
			t.Fatalf("shadowtls service connection error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shadowtls service did not finish authentication")
	}
}

func TestAddNodeShadowTLSUsesRuntimePath(t *testing.T) {
	const (
		tag         = "shadowtls-node"
		backendPort = 23456
	)
	node := shadowTLSNodeInfo(2, "sentinel-shadowtls-password")
	node.Common.ListenIP = "0.0.0.0"
	node.Common.ServerPort = 443

	var addedTag string
	var startedInfo *panel.NodeInfo
	var startedPort int
	var removedTag string
	runtime := &shadowTLSRuntime{}
	restore := installShadowTLSTestHooks(
		t,
		func() (int, error) { return backendPort, nil },
		func(v *V2Core, config *xrayCore.InboundHandlerConfig) error {
			addedTag = config.Tag
			return nil
		},
		func(v *V2Core, tag string) error {
			removedTag = tag
			return nil
		},
		func(info *panel.NodeInfo, port int) (*shadowTLSRuntime, error) {
			startedInfo = info
			startedPort = port
			return runtime, nil
		},
	)
	defer restore()

	v := New(nil)
	if err := v.AddNode(tag, node); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	if stored := v.popShadowTLSRuntime(tag); stored != runtime {
		t.Fatalf("stored runtime = %p, want %p", stored, runtime)
	}
	if addedTag != tag {
		t.Fatalf("added tag = %q, want %q", addedTag, tag)
	}
	if startedInfo != node {
		t.Fatalf("startedInfo = %p, want original node %p", startedInfo, node)
	}
	if startedPort != backendPort {
		t.Fatalf("started backend port = %d, want %d", startedPort, backendPort)
	}
	if removedTag != "" {
		t.Fatalf("removed tag = %q, want no rollback", removedTag)
	}
	if node.Common.ListenIP != "0.0.0.0" || node.Common.ServerPort != 443 {
		t.Fatalf("original endpoint mutated to %s:%d", node.Common.ListenIP, node.Common.ServerPort)
	}
}

func TestBuildShadowTLSPublicListenAddressUnwrapsBracketedIPv6(t *testing.T) {
	address := buildShadowTLSPublicListenAddress("[::]", 6443)
	if address != "[::]:6443" {
		t.Fatalf("listen address = %q, want [::]:6443", address)
	}
}

func TestAddNodeShadowTLSSidecarFailureRollsBackBackend(t *testing.T) {
	const password = "sentinel-shadowtls-password"
	const tag = "shadowtls-node"
	node := shadowTLSNodeInfo(2, password)
	var addedTag string
	var removedTag string
	restore := installShadowTLSTestHooks(
		t,
		func() (int, error) { return 23456, nil },
		func(v *V2Core, config *xrayCore.InboundHandlerConfig) error {
			addedTag = config.Tag
			return nil
		},
		func(v *V2Core, tag string) error {
			removedTag = tag
			return nil
		},
		func(info *panel.NodeInfo, port int) (*shadowTLSRuntime, error) {
			return nil, errors.New("bind failed")
		},
	)
	defer restore()

	err := (&V2Core{}).AddNode(tag, node)
	if err == nil {
		t.Fatalf("AddNode() error = nil, want sidecar startup error")
	}
	if addedTag != tag {
		t.Fatalf("added tag = %q, want %q", addedTag, tag)
	}
	if removedTag != tag {
		t.Fatalf("removed tag = %q, want rollback tag %q", removedTag, tag)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "start shadowtls runtime") {
		t.Fatalf("AddNode() error = %q, want runtime startup context", err)
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("AddNode() error leaked password: %v", err)
	}
}

func TestDelNodeShadowTLSClosesRuntimeBeforeBackendInbound(t *testing.T) {
	const tag = "shadowtls-node"
	v := New(nil)
	events := []string{}
	if err := v.setShadowTLSRuntime(tag, &shadowTLSRuntime{
		listener: &fakeShadowTLSListener{
			onClose: func() { events = append(events, "close") },
		},
	}); err != nil {
		t.Fatalf("setShadowTLSRuntime() error = %v", err)
	}
	originalRemoveInbound := removeInboundForNode
	removeInboundForNode = func(v *V2Core, tag string) error {
		events = append(events, "remove")
		return nil
	}
	defer func() { removeInboundForNode = originalRemoveInbound }()

	if err := v.DelNode(tag); err != nil {
		t.Fatalf("DelNode() error = %v", err)
	}
	if strings.Join(events, ",") != "close,remove" {
		t.Fatalf("events = %v, want close before remove", events)
	}
	if runtime := v.popShadowTLSRuntime(tag); runtime != nil {
		t.Fatalf("runtime remained after DelNode(): %p", runtime)
	}
}

func TestDelNodeShadowTLSTriesBackendRemovalWhenRuntimeCloseFails(t *testing.T) {
	const tag = "shadowtls-node"
	const password = "sentinel-shadowtls-password"
	v := New(nil)
	if err := v.setShadowTLSRuntime(tag, &shadowTLSRuntime{
		listener: &fakeShadowTLSListener{closeErr: errors.New("listener close failed")},
	}); err != nil {
		t.Fatalf("setShadowTLSRuntime() error = %v", err)
	}
	var removed bool
	originalRemoveInbound := removeInboundForNode
	removeInboundForNode = func(v *V2Core, tag string) error {
		removed = true
		return errors.New("backend remove failed")
	}
	defer func() { removeInboundForNode = originalRemoveInbound }()

	err := v.DelNode(tag)
	if err == nil {
		t.Fatalf("DelNode() error = nil, want combined error")
	}
	if !removed {
		t.Fatalf("backend inbound removal was not attempted")
	}
	for _, want := range []string{"close shadowtls runtime", "listener close failed", "remove in", "backend remove failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("DelNode() error = %q, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("DelNode() error leaked password: %v", err)
	}
}

func TestCloseAllShadowTLSRuntimesClosesResidualListeners(t *testing.T) {
	v := New(nil)
	var closed []string
	for _, tag := range []string{"shadowtls-one", "shadowtls-two"} {
		tag := tag
		if err := v.setShadowTLSRuntime(tag, &shadowTLSRuntime{
			listener: &fakeShadowTLSListener{
				onClose: func() { closed = append(closed, tag) },
			},
		}); err != nil {
			t.Fatalf("setShadowTLSRuntime(%q) error = %v", tag, err)
		}
	}

	if err := v.closeAllShadowTLSRuntimes(); err != nil {
		t.Fatalf("closeAllShadowTLSRuntimes() error = %v", err)
	}
	if strings.Join(closed, ",") != "shadowtls-one,shadowtls-two" && strings.Join(closed, ",") != "shadowtls-two,shadowtls-one" {
		t.Fatalf("closed listeners = %v, want both residual runtimes closed", closed)
	}
	for _, tag := range []string{"shadowtls-one", "shadowtls-two"} {
		if runtime := v.popShadowTLSRuntime(tag); runtime != nil {
			t.Fatalf("runtime %q remained after closeAllShadowTLSRuntimes(): %p", tag, runtime)
		}
	}
}

func TestCloseAllShadowTLSRuntimesErrorDoesNotLeakPassword(t *testing.T) {
	const password = "sentinel-shadowtls-password"
	v := New(nil)
	if err := v.setShadowTLSRuntime("shadowtls-node", &shadowTLSRuntime{
		listener: &fakeShadowTLSListener{closeErr: errors.New("listener close failed")},
	}); err != nil {
		t.Fatalf("setShadowTLSRuntime() error = %v", err)
	}

	err := v.closeAllShadowTLSRuntimes()
	if err == nil {
		t.Fatalf("closeAllShadowTLSRuntimes() error = nil, want listener close error")
	}
	for _, want := range []string{"close shadowtls runtime", "shadowtls-node", "listener close failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("closeAllShadowTLSRuntimes() error = %q, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("closeAllShadowTLSRuntimes() error leaked password: %v", err)
	}
}

func TestDelNodeOrdinaryUsesExistingInboundPath(t *testing.T) {
	const tag = "ordinary-shadowsocks"
	v := New(nil)
	var removedTag string
	originalRemoveInbound := removeInboundForNode
	removeInboundForNode = func(v *V2Core, tag string) error {
		removedTag = tag
		return nil
	}
	defer func() { removeInboundForNode = originalRemoveInbound }()

	if err := v.DelNode(tag); err != nil {
		t.Fatalf("DelNode() error = %v", err)
	}
	if removedTag != tag {
		t.Fatalf("removed tag = %q, want %q", removedTag, tag)
	}
}

func TestDelNodeOrdinaryDoesNotCloseShadowTLSListenerWithoutMatchingRuntime(t *testing.T) {
	const (
		tag          = "ordinary-shadowsocks"
		shadowTLSTag = "shadowtls-node"
	)
	v := New(nil)
	var closeCount int
	if err := v.setShadowTLSRuntime(shadowTLSTag, &shadowTLSRuntime{
		listener: &fakeShadowTLSListener{onClose: func() { closeCount++ }},
	}); err != nil {
		t.Fatalf("setShadowTLSRuntime() error = %v", err)
	}
	var removedTag string
	originalRemoveInbound := removeInboundForNode
	removeInboundForNode = func(v *V2Core, tag string) error {
		removedTag = tag
		return nil
	}
	defer func() {
		removeInboundForNode = originalRemoveInbound
		if runtime := v.popShadowTLSRuntime(shadowTLSTag); runtime != nil {
			_ = runtime.Close()
		}
	}()

	if err := v.DelNode(tag); err != nil {
		t.Fatalf("DelNode() error = %v", err)
	}
	if removedTag != tag {
		t.Fatalf("removed tag = %q, want %q", removedTag, tag)
	}
	if closeCount != 0 {
		t.Fatalf("ShadowTLS listener close count = %d, want 0 for ordinary tag", closeCount)
	}
	if !v.hasShadowTLSRuntime(shadowTLSTag) {
		t.Fatalf("unrelated ShadowTLS runtime was removed")
	}
}

func TestAddNodeOrdinaryShadowsocksUsesExistingInboundPath(t *testing.T) {
	const tag = "ordinary-shadowsocks"
	node := &panel.NodeInfo{
		Type:     "shadowsocks",
		Security: panel.None,
		Common: &panel.CommonNode{
			Protocol:   "shadowsocks",
			ListenIP:   "127.0.0.1",
			ServerPort: 12345,
			Cipher:     "aes-128-gcm",
		},
	}
	var addedTag string
	var runtimeStarted bool
	restore := installShadowTLSTestHooks(
		t,
		func() (int, error) {
			t.Fatalf("ShadowTLS backend allocator called for ordinary Shadowsocks")
			return 0, nil
		},
		func(v *V2Core, config *xrayCore.InboundHandlerConfig) error {
			addedTag = config.Tag
			return nil
		},
		func(v *V2Core, tag string) error { return nil },
		func(info *panel.NodeInfo, port int) (*shadowTLSRuntime, error) {
			runtimeStarted = true
			return &shadowTLSRuntime{}, nil
		},
	)
	defer restore()

	if err := (&V2Core{}).AddNode(tag, node); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	if addedTag != tag {
		t.Fatalf("added tag = %q, want %q", addedTag, tag)
	}
	if runtimeStarted {
		t.Fatalf("ShadowTLS runtime started for ordinary Shadowsocks")
	}
}

func shadowTLSNodeInfo(version int, password string) *panel.NodeInfo {
	return &panel.NodeInfo{
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
				ShadowTLSVersion:  version,
				ShadowTLSPassword: password,
				ShadowTLS:         "example.com",
			},
		},
	}
}

func installShadowTLSTestHooks(
	t *testing.T,
	allocator func() (int, error),
	addInbound func(*V2Core, *xrayCore.InboundHandlerConfig) error,
	removeInbound func(*V2Core, string) error,
	startRuntime func(*panel.NodeInfo, int) (*shadowTLSRuntime, error),
) func() {
	t.Helper()
	originalAllocator := shadowTLSBackendPortAllocator
	originalAddInbound := addInboundForNode
	originalRemoveInbound := removeInboundForNode
	originalRuntimeStarter := shadowTLSRuntimeStarter
	shadowTLSBackendPortAllocator = allocator
	addInboundForNode = addInbound
	removeInboundForNode = removeInbound
	shadowTLSRuntimeStarter = startRuntime
	return func() {
		shadowTLSBackendPortAllocator = originalAllocator
		addInboundForNode = originalAddInbound
		removeInboundForNode = originalRemoveInbound
		shadowTLSRuntimeStarter = originalRuntimeStarter
	}
}

type fakeShadowTLSListener struct {
	closeErr error
	onClose  func()
}

func (l *fakeShadowTLSListener) Accept() (net.Conn, error) {
	return nil, errors.New("accept is not used")
}

func (l *fakeShadowTLSListener) Close() error {
	if l.onClose != nil {
		l.onClose()
	}
	return l.closeErr
}

func (l *fakeShadowTLSListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func assertShadowTLSHandshake(t *testing.T, actual M.Socksaddr, host string, port uint16) {
	t.Helper()
	if actual.AddrString() != host {
		t.Fatalf("handshake host = %q, want %q", actual.AddrString(), host)
	}
	if actual.Port != port {
		t.Fatalf("handshake port = %d, want %d", actual.Port, port)
	}
}
