//go:build windows

package selfupdate

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows Installer API, from msi.dll in System32 (never a copy found
// on the DLL search path), called directly: no CGO, no PowerShell.
var (
	modMSI                   = windows.NewLazySystemDLL("msi.dll")
	procMsiOpenDatabaseW     = modMSI.NewProc("MsiOpenDatabaseW")
	procMsiDatabaseOpenViewW = modMSI.NewProc("MsiDatabaseOpenViewW")
	procMsiViewExecute       = modMSI.NewProc("MsiViewExecute")
	procMsiViewFetch         = modMSI.NewProc("MsiViewFetch")
	procMsiRecordGetStringW  = modMSI.NewProc("MsiRecordGetStringW")
	procMsiCloseHandle       = modMSI.NewProc("MsiCloseHandle")
)

const (
	// msidbOpenReadOnly is MSIDBOPEN_READONLY, ((LPCTSTR)0).
	msidbOpenReadOnly = 0
	errorMoreData     = 234
	errorNoMoreItems  = 259
	// maxMSIProperty bounds one property value read.
	maxMSIProperty = 4096
)

type msiHandle uint32

func msiClose(h msiHandle) {
	if h != 0 {
		procMsiCloseHandle.Call(uintptr(h))
	}
}

func msiErr(fn string, r uintptr) error {
	return fmt.Errorf("%s: %w", fn, syscall.Errno(r))
}

// readMSIProperties opens the MSI database at file read-only and returns
// the named rows of its Property table. A property the table lacks is
// absent from the map. names must be constant identifiers: they are
// quoted into the query.
func readMSIProperties(file string, names []string) (map[string]string, error) {
	if err := modMSI.Load(); err != nil {
		return nil, err
	}
	path, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return nil, err
	}
	var db msiHandle
	if r, _, _ := procMsiOpenDatabaseW.Call(uintptr(unsafe.Pointer(path)), msidbOpenReadOnly, uintptr(unsafe.Pointer(&db))); r != 0 {
		return nil, msiErr("MsiOpenDatabase", r)
	}
	defer msiClose(db)
	out := make(map[string]string, len(names))
	for _, name := range names {
		v, ok, err := msiProperty(db, name)
		if err != nil {
			return nil, fmt.Errorf("property %s: %w", name, err)
		}
		if ok {
			out[name] = v
		}
	}
	return out, nil
}

func msiProperty(db msiHandle, name string) (string, bool, error) {
	for _, r := range name {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return "", false, errors.New("not an identifier")
		}
	}
	q, err := windows.UTF16PtrFromString("SELECT `Value` FROM `Property` WHERE `Property` = '" + name + "'")
	if err != nil {
		return "", false, err
	}
	var view msiHandle
	if r, _, _ := procMsiDatabaseOpenViewW.Call(uintptr(db), uintptr(unsafe.Pointer(q)), uintptr(unsafe.Pointer(&view))); r != 0 {
		return "", false, msiErr("MsiDatabaseOpenView", r)
	}
	defer msiClose(view)
	if r, _, _ := procMsiViewExecute.Call(uintptr(view), 0); r != 0 {
		return "", false, msiErr("MsiViewExecute", r)
	}
	var rec msiHandle
	switch r, _, _ := procMsiViewFetch.Call(uintptr(view), uintptr(unsafe.Pointer(&rec))); r {
	case 0:
	case errorNoMoreItems:
		return "", false, nil
	default:
		return "", false, msiErr("MsiViewFetch", r)
	}
	defer msiClose(rec)
	// First ask for the length (in characters, without the terminator),
	// then read into a buffer one longer.
	var n uint32
	var empty uint16
	r, _, _ := procMsiRecordGetStringW.Call(uintptr(rec), 1, uintptr(unsafe.Pointer(&empty)), uintptr(unsafe.Pointer(&n)))
	if r != 0 && r != errorMoreData {
		return "", false, msiErr("MsiRecordGetString", r)
	}
	if n > maxMSIProperty {
		return "", false, fmt.Errorf("value longer than %d characters", maxMSIProperty)
	}
	buf := make([]uint16, n+1)
	n++
	if r, _, _ := procMsiRecordGetStringW.Call(uintptr(rec), 1, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r != 0 {
		return "", false, msiErr("MsiRecordGetString", r)
	}
	return windows.UTF16ToString(buf[:n]), true, nil
}
