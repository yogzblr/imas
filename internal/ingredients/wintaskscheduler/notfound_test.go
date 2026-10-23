package wintaskscheduler

import (
	"errors"
	"fmt"
	"testing"

	ole "github.com/go-ole/go-ole"
)

// excepInfo stands in for ole.EXCEPINFO, whose fields are unexported.
type excepInfo struct{ scode uint32 }

func (e excepInfo) SCODE() uint32 { return e.scode }
func (e excepInfo) Error() string { return fmt.Sprintf("scode %#x", e.scode) }

const dispEException = 0x80020009 // DISP_E_EXCEPTION

func TestIsNotFoundErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"direct file not found", ole.NewError(hrFileNotFound), true},
		{"direct path not found", ole.NewError(hrPathNotFound), true},
		{"IDispatch exception, folder missing", ole.NewErrorWithSubError(dispEException, "The system cannot find the file specified.", excepInfo{hrFileNotFound}), true},
		{"IDispatch exception, path missing", ole.NewErrorWithSubError(dispEException, "", excepInfo{hrPathNotFound}), true},
		{"wrapped IDispatch exception", fmt.Errorf("wintaskscheduler: GetFolder: %w", ole.NewErrorWithSubError(dispEException, "", excepInfo{hrFileNotFound})), true},
		{"IDispatch exception, access denied", ole.NewErrorWithSubError(dispEException, "", excepInfo{0x80070005}), false},
		{"IDispatch exception, no EXCEPINFO", ole.NewError(dispEException), false},
		{"not an OLE error", errors.New("file not found"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotFoundErr(tt.err); got != tt.want {
				t.Fatalf("isNotFoundErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
