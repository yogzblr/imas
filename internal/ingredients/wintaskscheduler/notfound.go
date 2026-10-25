package wintaskscheduler

import (
	"errors"
	"fmt"
	"strings"

	ole "github.com/go-ole/go-ole"

	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

// ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND, the HRESULTs
// GetFolder/GetTask/DeleteTask surface when the folder or task doesn't
// exist.
const (
	hrFileNotFound = 0x80070002
	hrPathNotFound = 0x80070003
)

// isNotFoundErr reports whether err is Task Scheduler saying the folder or
// task doesn't exist. Called through IDispatch, as this package does, a
// failing method returns DISP_E_EXCEPTION and puts its own HRESULT in the
// EXCEPINFO's scode, which go-ole keeps as the OleError's SubError; only a
// direct call returns the HRESULT itself. Checking only the outer code
// missed every not-found, so present failed for any new task, test mode
// included (UAT I.win_task.present).
//
// It has no build constraint so it is unit-tested on every platform.
func isNotFoundErr(err error) bool {
	var oleErr *ole.OleError
	if !errors.As(err, &oleErr) {
		return false
	}
	if isNotFoundCode(uint32(oleErr.Code())) {
		return true
	}
	// ole.EXCEPINFO has a value receiver for SCODE; match on the method so
	// tests can stand in for it (its fields are unexported).
	if sc, ok := oleErr.SubError().(interface{ SCODE() uint32 }); ok {
		return isNotFoundCode(sc.SCODE())
	}
	return false
}

func isNotFoundCode(hr uint32) bool {
	return hr == hrFileNotFound || hr == hrPathNotFound
}

// maxXMLQuote bounds how much of the task's XML a registration error
// quotes.
const maxXMLQuote = 2048

// registerError is RegisterTaskDefinition's failure: the task, the
// principal it was registered for, the HRESULTs (winexec.COMError: through
// IDispatch the reason is the EXCEPINFO scode, which "Exception occurred."
// alone does not name) and the definition's XML, which is what Task
// Scheduler validated.
func registerError(path, userID string, logonType int, err error, xml string) error {
	err = winexec.COMError(fmt.Sprintf("wintaskscheduler: RegisterTaskDefinition(%q) as %s, logon type %d", path, userID, logonType), err)
	xml = strings.TrimSpace(xml)
	if xml == "" {
		return err
	}
	if len(xml) > maxXMLQuote {
		xml = xml[:maxXMLQuote] + "..."
	}
	return fmt.Errorf("%w; task XML: %s", err, xml)
}
