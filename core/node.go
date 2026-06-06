package core

import (
	"errors"
	"fmt"

	panel "github.com/wyx2685/v2node/api/v2board"
	xrayCore "github.com/xtls/xray-core/core"
)

var addInboundForNode = func(v *V2Core, config *xrayCore.InboundHandlerConfig) error {
	return v.addInbound(config)
}

var removeInboundForNode = func(v *V2Core, tag string) error {
	return v.removeInbound(tag)
}

func (v *V2Core) AddNode(tag string, info *panel.NodeInfo) error {
	if info != nil && info.Security == panel.ShadowTLS {
		return v.addShadowTLSNode(tag, info)
	}
	inBoundConfig, err := buildInbound(info, tag)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = addInboundForNode(v, inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (v *V2Core) addShadowTLSNode(tag string, info *panel.NodeInfo) error {
	if v.hasShadowTLSRuntime(tag) {
		return fmt.Errorf("shadowtls runtime already exists for tag %s", tag)
	}
	backendPort, err := shadowTLSBackendPortAllocator()
	if err != nil {
		return err
	}
	backendInfo, err := buildShadowTLSBackendNodeInfo(info, backendPort)
	if err != nil {
		return err
	}
	inBoundConfig, err := buildInbound(backendInfo, tag)
	if err != nil {
		return fmt.Errorf("build shadowtls backend inbound error: %s", err)
	}
	if err := addInboundForNode(v, inBoundConfig); err != nil {
		return fmt.Errorf("add shadowtls backend inbound error: %s", err)
	}
	runtime, err := shadowTLSRuntimeStarter(info, backendPort)
	if err != nil {
		if removeErr := removeInboundForNode(v, tag); removeErr != nil {
			return fmt.Errorf("start shadowtls runtime error: %s; rollback backend inbound error: %s", err, removeErr)
		}
		return fmt.Errorf("start shadowtls runtime error: %s", err)
	}
	if err := v.setShadowTLSRuntime(tag, runtime); err != nil {
		closeErr := runtime.Close()
		removeErr := removeInboundForNode(v, tag)
		return errors.Join(
			fmt.Errorf("store shadowtls runtime error: %w", err),
			wrapShadowTLSCloseErr(closeErr),
			wrapRemoveInboundErr(removeErr),
		)
	}
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	var closeErr error
	if runtime := v.popShadowTLSRuntime(tag); runtime != nil {
		closeErr = runtime.Close()
	}
	removeErr := removeInboundForNode(v, tag)
	return errors.Join(wrapShadowTLSCloseErr(closeErr), wrapRemoveInboundErr(removeErr))
}

func wrapShadowTLSCloseErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close shadowtls runtime error: %w", err)
}

func wrapRemoveInboundErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("remove in error: %w", err)
}
