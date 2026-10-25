package winexec

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	ole "github.com/go-ole/go-ole"
)

// excepInfo stands in for ole.EXCEPINFO, whose fields are unexported.
type excepInfo struct {
	scode uint32
	text  string
}

func (e excepInfo) SCODE() uint32 { return e.scode }
func (e excepInfo) Error() string { return e.text }

func TestCOMErrorNamesTheEXCEPINFOScode(t *testing.T) {
	// UAT I.win_task.present, Run 2 on rc.21: "call
	// RegisterTaskDefinition: Exception occurred." with no HRESULT.
	inner := fmt.Errorf("call RegisterTaskDefinition: %w",
		ole.NewErrorWithSubError(dispEException, "", excepInfo{scode: 0x80070005, text: "Access is denied."}))
	err := COMError(`RegisterTaskDefinition(\imas-uat\uat-x)`, inner)
	for _, want := range []string{"HRESULT 0x80020009", "scode 0x80070005", "Access is denied.", "DISP_E_EXCEPTION"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	var oleErr *ole.OleError
	if !errors.As(err, &oleErr) {
		t.Error("the OleError must stay in the chain")
	}
	if hr, ok := COMHRESULT(err); !ok || hr != 0x80070005 {
		t.Errorf("COMHRESULT = %#x, %v; want 0x80070005, true", hr, ok)
	}
}

func TestCOMErrorDirectHRESULT(t *testing.T) {
	err := COMError("GetFolder", ole.NewError(0x80070002))
	if !strings.Contains(err.Error(), "HRESULT 0x80070002") {
		t.Errorf("got %q", err)
	}
	if hr, ok := COMHRESULT(err); !ok || hr != 0x80070002 {
		t.Errorf("COMHRESULT = %#x, %v", hr, ok)
	}
}

func TestCOMErrorPlainError(t *testing.T) {
	err := COMError("Save", errors.New("boom"))
	if err.Error() != "Save: boom" {
		t.Errorf("got %q", err)
	}
	if _, ok := COMHRESULT(err); ok {
		t.Error("a plain error has no HRESULT")
	}
	if COMError("x", nil) != nil {
		t.Error("nil stays nil")
	}
}
