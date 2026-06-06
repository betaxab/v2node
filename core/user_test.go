package core

import (
	"context"
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/counter"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/core/app/dispatcher"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
)

func TestShadowTLSAddUsersUsesOriginalTagUserManager(t *testing.T) {
	const tag = "shadowtls-node"
	user := panel.UserInfo{Id: 1001, Uuid: "11111111-1111-1111-1111-111111111111"}
	expectedEmail := format.UserTag(tag, user.Uuid)
	manager := newFakeUserManager()
	restore := installUserManagerSeam(t, func(v *V2Core, requestedTag string) (proxy.UserManager, error) {
		if requestedTag != tag {
			t.Fatalf("GetUserManager tag = %q, want %q", requestedTag, tag)
		}
		return manager, nil
	})
	defer restore()

	v := newUserLifecycleTestCore()
	added, err := v.AddUsers(&AddUsersParams{
		Tag:      tag,
		Users:    []panel.UserInfo{user},
		NodeInfo: shadowTLSUserNodeInfo(),
	})
	if err != nil {
		t.Fatalf("AddUsers() error = %v", err)
	}
	if added != 1 {
		t.Fatalf("AddUsers() added = %d, want 1", added)
	}
	if len(manager.added) != 1 || manager.added[0] != expectedEmail {
		t.Fatalf("added users = %v, want [%s]", manager.added, expectedEmail)
	}
	if uid := v.users.uidMap[expectedEmail]; uid != user.Id {
		t.Fatalf("uidMap[%q] = %d, want %d", expectedEmail, uid, user.Id)
	}
}

func TestShadowTLSDelUsersUsesOriginalTagAndDeletesCounters(t *testing.T) {
	const tag = "shadowtls-node"
	user := panel.UserInfo{Id: 1002, Uuid: "22222222-2222-2222-2222-222222222222"}
	expectedEmail := format.UserTag(tag, user.Uuid)
	manager := newFakeUserManager()
	restore := installUserManagerSeam(t, func(v *V2Core, requestedTag string) (proxy.UserManager, error) {
		if requestedTag != tag {
			t.Fatalf("GetUserManager tag = %q, want %q", requestedTag, tag)
		}
		return manager, nil
	})
	defer restore()

	v := newUserLifecycleTestCore()
	v.users.uidMap[expectedEmail] = user.Id
	tc := counter.NewTrafficCounter()
	tc.Tx(expectedEmail, 1234)
	tc.Rx(expectedEmail, 5678)
	v.dispatcher.Counter.Store(tag, tc)

	if err := v.DelUsers([]panel.UserInfo{user}, tag, shadowTLSUserNodeInfo()); err != nil {
		t.Fatalf("DelUsers() error = %v", err)
	}
	if len(manager.removed) != 1 || manager.removed[0] != expectedEmail {
		t.Fatalf("removed users = %v, want [%s]", manager.removed, expectedEmail)
	}
	if _, ok := v.users.uidMap[expectedEmail]; ok {
		t.Fatalf("uidMap still contains %q", expectedEmail)
	}
	if _, ok := tc.Counters.Load(expectedEmail); ok {
		t.Fatalf("traffic counter still contains %q", expectedEmail)
	}
}

func TestShadowTLSGetUserTrafficSliceUsesOriginalTagCounters(t *testing.T) {
	const tag = "shadowtls-node"
	user := panel.UserInfo{Id: 1003, Uuid: "33333333-3333-3333-3333-333333333333"}
	email := format.UserTag(tag, user.Uuid)
	unknownEmail := format.UserTag(tag, "unknown-user")
	v := newUserLifecycleTestCore()
	v.users.uidMap[email] = user.Id
	tc := counter.NewTrafficCounter()
	tc.Tx(email, 2000)
	tc.Rx(email, 3000)
	tc.Tx(unknownEmail, 4000)
	v.dispatcher.Counter.Store(tag, tc)

	traffic, err := v.GetUserTrafficSlice(tag, 1)
	if err != nil {
		t.Fatalf("GetUserTrafficSlice() error = %v", err)
	}
	if len(traffic) != 1 {
		t.Fatalf("traffic length = %d, want 1: %#v", len(traffic), traffic)
	}
	if traffic[0].UID != user.Id {
		t.Fatalf("traffic UID = %d, want %d", traffic[0].UID, user.Id)
	}
	if traffic[0].Upload != 2000 || traffic[0].Download != 3000 {
		t.Fatalf("traffic = upload %d download %d, want 2000/3000", traffic[0].Upload, traffic[0].Download)
	}
	if up := tc.GetUpCount(email); up != 0 {
		t.Fatalf("up counter after report = %d, want 0", up)
	}
	if down := tc.GetDownCount(email); down != 0 {
		t.Fatalf("down counter after report = %d, want 0", down)
	}
	if _, ok := tc.Counters.Load(unknownEmail); ok {
		t.Fatalf("unknown traffic counter still contains %q", unknownEmail)
	}
}

func newUserLifecycleTestCore() *V2Core {
	v := New(nil)
	v.dispatcher = &dispatcher.DefaultDispatcher{}
	return v
}

func shadowTLSUserNodeInfo() *panel.NodeInfo {
	return &panel.NodeInfo{
		Type:     "shadowsocks",
		Security: panel.ShadowTLS,
		Common: &panel.CommonNode{
			Protocol: "shadowsocks",
			Cipher:   "aes-128-gcm",
		},
	}
}

func installUserManagerSeam(
	t *testing.T,
	getter func(*V2Core, string) (proxy.UserManager, error),
) func() {
	t.Helper()
	original := getUserManagerForCore
	getUserManagerForCore = getter
	return func() {
		getUserManagerForCore = original
	}
}

type fakeUserManager struct {
	users   map[string]*protocol.MemoryUser
	added   []string
	removed []string
}

func newFakeUserManager() *fakeUserManager {
	return &fakeUserManager{users: make(map[string]*protocol.MemoryUser)}
}

func (m *fakeUserManager) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	m.added = append(m.added, user.Email)
	m.users[user.Email] = user
	return nil
}

func (m *fakeUserManager) RemoveUser(_ context.Context, email string) error {
	m.removed = append(m.removed, email)
	delete(m.users, email)
	return nil
}

func (m *fakeUserManager) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	return m.users[email]
}

func (m *fakeUserManager) GetUsers(context.Context) []*protocol.MemoryUser {
	users := make([]*protocol.MemoryUser, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}
	return users
}

func (m *fakeUserManager) GetUsersCount(context.Context) int64 {
	return int64(len(m.users))
}
