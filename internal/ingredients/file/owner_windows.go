//go:build windows

package file

// ownedBy reports false: Windows files have no uid or gid to compare, so
// a requested chown is always attempted (os.Chown fails there).
func ownedBy(name string, uid, gid int) bool {
	return false
}
