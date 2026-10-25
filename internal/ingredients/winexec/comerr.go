package winexec

import (
	"errors"
	"fmt"

	ole "github.com/go-ole/go-ole"
)

// dispEException is DISP_E_EXCEPTION: the HRESULT IDispatch::Invoke
// returns when the called method failed, with the method's own HRESULT
// in the EXCEPINFO's scode.
const dispEException = 0x80020009

// COMHRESULT returns the HRESULT that says why a COM call failed: the
// EXCEPINFO scode when the call went through IDispatch and failed with
// DISP_E_EXCEPTION (go-ole keeps the EXCEPINFO as the OleError's
// SubError), else the call's own HRESULT. ok is false when err holds no
// *ole.OleError.
func COMHRESULT(err error) (hr uint32, ok bool) {
	var oleErr *ole.OleError
	if !errors.As(err, &oleErr) {
		return 0, false
	}
	hr = uint32(oleErr.Code())
	// ole.EXCEPINFO has a value receiver for SCODE; match on the method so
	// tests can stand in for it (its fields are unexported).
	if sc, ok := oleErr.SubError().(interface{ SCODE() uint32 }); ok && sc.SCODE() != 0 {
		return sc.SCODE(), true
	}
	return hr, true
}

// COMError wraps err, from the COM call op, with the HRESULTs it
// carries: "op: <err> (HRESULT 0x80020009, scode 0x80070005: Access is
// denied.)". A failure through IDispatch otherwise reads only "Exception
// occurred.", which names no cause (UAT I.win_task.present, Run 2 on
// rc.21). The description is the EXCEPINFO's, when the server gave one.
// err stays in the chain (errors.Is/As still see it). A nil err gives
// nil; an err with no *ole.OleError is wrapped with op alone.
func COMError(op string, err error) error {
	if err == nil {
		return nil
	}
	var oleErr *ole.OleError
	if !errors.As(err, &oleErr) {
		return fmt.Errorf("%s: %w", op, err)
	}
	outer := uint32(oleErr.Code())
	detail := fmt.Sprintf("HRESULT 0x%08X", outer)
	if sub := oleErr.SubError(); sub != nil {
		if sc, ok := sub.(interface{ SCODE() uint32 }); ok {
			detail += fmt.Sprintf(", scode 0x%08X", sc.SCODE())
		}
		if text := sub.Error(); text != "" && text != "<nil>" {
			detail += ": " + text
		}
	} else if d := oleErr.Description(); d != "" {
		detail += ": " + d
	}
	if outer == dispEException {
		detail += " (DISP_E_EXCEPTION: the method failed; the scode is its HRESULT)"
	}
	return fmt.Errorf("%s: %w (%s)", op, err, detail)
}
