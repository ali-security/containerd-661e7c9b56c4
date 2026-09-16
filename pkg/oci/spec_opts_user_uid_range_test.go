//go:build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package oci

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CVE-2026-46680: WithUser parsed the image's USER value with strconv.Atoi and,
// on any error — including strconv.ErrRange for a value that does not fit an
// int — fell through to a username lookup against the image's own /etc/passwd.
// An image shipping a passwd entry whose *name* is that out-of-range numeric
// string therefore had it resolve to uid 0, escaping the int32 bounds check and
// running as root.
//
// The table in spec_opts_linux_test.go asserts the new error strings but cannot
// catch this: its assertion is guarded by `if err != nil`, and the vulnerable
// path returns no error at all — it silently yields uid 0, which is also the
// zero value the table compares against. The rootfs below therefore ships the
// hostile passwd/group entries the advisory describes, and every hostile case
// requires an error.

// hostileUserFiles maps each out-of-range numeric string to uid/gid 0, which is
// what makes the pre-patch fallthrough a privilege escalation rather than a
// lookup failure.
const (
	hostileUserPasswd = `root:x:0:0:root:/root:/bin/ash
2147483648:x:0:0:int32 overflow:/root:/bin/ash
4294967296:x:0:0:uint32 wrap:/root:/bin/ash
999999999999999999999999999999999999:x:0:0:unparseable:/root:/bin/ash
guest:x:405:100:guest:/dev/null:/sbin/nologin
`
	hostileUserGroup = `root:x:0:root
2147483648:x:0:root
4294967296:x:0:root
guest:x:100:guest
`
)

func hostileRootfs(t *testing.T) string {
	t.Helper()

	td := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(td, "etc"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(td, "etc", "passwd"), []byte(hostileUserPasswd), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(td, "etc", "group"), []byte(hostileUserGroup), 0o644))
	return td
}

func specForRootfs(rootfs string) *Spec {
	return &Spec{
		Version: specs.Version,
		Root:    &specs.Root{Path: rootfs},
		Linux:   &specs.Linux{},
	}
}

// TestWithUserRejectsOutOfRangeIDsBackedByPasswdEntries is the CVE regression:
// each USER value below is out of range *and* resolvable as a username to uid 0
// in the image's own user database. WithUser must reject it outright rather
// than fall through to the lookup.
func TestWithUserRejectsOutOfRangeIDsBackedByPasswdEntries(t *testing.T) {
	t.Parallel()

	rootfs := hostileRootfs(t)
	c := containers.Container{ID: t.Name()}

	for _, tc := range []struct {
		user string
		want string
	}{
		{user: "2147483648", want: `invalid USER value "2147483648": uid out of range`},
		{user: "4294967296", want: `invalid USER value "4294967296": uid out of range`},
		{
			user: "999999999999999999999999999999999999",
			want: `invalid USER value "999999999999999999999999999999999999": uid out of range`,
		},
		{user: "-1000", want: `invalid USER value "-1000": uid out of range`},
		{user: "2147483648:0", want: `invalid USER value "2147483648:0": uid out of range`},
		{user: "0:2147483648", want: `invalid USER value "0:2147483648": gid out of range`},
		{user: "0:4294967296", want: `invalid USER value "0:4294967296": gid out of range`},
	} {
		t.Run(tc.user, func(t *testing.T) {
			t.Parallel()

			s := specForRootfs(rootfs)
			err := WithUser(tc.user)(context.Background(), nil, &c, s)

			// require, not assert: pre-patch this returns nil and resolves the
			// hostile passwd entry to uid 0, so a missing error IS the CVE.
			require.Error(t, err, "out-of-range USER %q was accepted", tc.user)
			assert.EqualError(t, err, tc.want)
		})
	}
}

// TestWithUserStillResolvesInRangeUsers is the positive control: rejecting
// out-of-range values must not cost the ordinary name and uid:gid lookups, so a
// future over-broad tightening of this path fails here.
func TestWithUserStillResolvesInRangeUsers(t *testing.T) {
	t.Parallel()

	rootfs := hostileRootfs(t)
	c := containers.Container{ID: t.Name()}

	for _, tc := range []struct {
		user string
		uid  uint32
		gid  uint32
	}{
		{user: "guest", uid: 405, gid: 100},
		{user: "guest:guest", uid: 405, gid: 100},
		{user: "405:100", uid: 405, gid: 100},
		{user: "0", uid: 0, gid: 0},
		{user: "2147483647", uid: 2147483647, gid: 0},
	} {
		t.Run(tc.user, func(t *testing.T) {
			t.Parallel()

			s := specForRootfs(rootfs)
			require.NoError(t, WithUser(tc.user)(context.Background(), nil, &c, s))
			assert.Equal(t, tc.uid, s.Process.User.UID)
			assert.Equal(t, tc.gid, s.Process.User.GID)
		})
	}
}
