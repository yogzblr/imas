package wintaskscheduler

import (
	"context"
	"errors"
	"strings"
	"testing"

	ole "github.com/go-ole/go-ole"
)

const dispEMemberNotFound = 0x80020003 // DISP_E_MEMBERNOTFOUND

// UAT I.win_task.absent, Run 2 on rc.21: the test-mode cook of a task the
// setup made failed with "wintaskscheduler: call Item: Member not found"
// while reading the task's definition. absent asks only whether the task
// exists, so a definition it cannot read no longer stops it.
func TestTaskAbsentDoesNotReadTheDefinition(t *testing.T) {
	fb := installFakeBackend(t)
	name := `\imas-uat\uat-abc`
	fb.states[name] = taskState{Command: `C:\Windows\System32\cmd.exe`}
	fb.loadErr = errors.New("wintaskscheduler: call Item: Member not found")

	res, err := newTask(methodAbsent, map[string]interface{}{"name": name}).Test(context.Background())
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("test mode: res=%+v err=%v", res, err)
	}
	if len(fb.deleted) != 0 {
		t.Fatal("test mode deleted the task")
	}
	res, err = newTask(methodAbsent, map[string]interface{}{"name": name}).Apply(context.Background())
	if err != nil || !res.Changed || len(fb.deleted) != 1 {
		t.Fatalf("real: res=%+v err=%v deleted=%v", res, err, fb.deleted)
	}
	res, err = newTask(methodAbsent, map[string]interface{}{"name": name}).Apply(context.Background())
	if err != nil || res.Changed {
		t.Fatalf("second real cook must be no change: res=%+v err=%v", res, err)
	}
}

// A missing folder or task is absent; any other failure to look it up is
// an error that names it.
func TestTaskAbsentLookupErrorIsAnError(t *testing.T) {
	fb := installFakeBackend(t)
	fb.existsErr = errors.New("wintaskscheduler: call GetFolder: Access is denied.")
	res, err := newTask(methodAbsent, map[string]interface{}{"name": `\x\y`}).Test(context.Background())
	if err == nil || !res.Failed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestPrincipalForSystemSprout(t *testing.T) {
	tests := []struct {
		user, password string
		wantUser       string
		wantPW         interface{}
		wantLogon      int
	}{
		{"", "", "SYSTEM", nil, logonServiceAccount},
		{"SYSTEM", "", "SYSTEM", nil, logonServiceAccount},
		{`NT AUTHORITY\SYSTEM`, "", "SYSTEM", nil, logonServiceAccount},
		{"S-1-5-18", "ignored", "SYSTEM", nil, logonServiceAccount},
		{`HOST\svc`, "secret", `HOST\svc`, "secret", logonPassword},
		{`HOST\svc`, "", `HOST\svc`, nil, logonS4U},
	}
	for _, tt := range tests {
		user, pw, logon := principalFor(tt.user, tt.password)
		if user != tt.wantUser || pw != tt.wantPW || logon != tt.wantLogon {
			t.Errorf("principalFor(%q, %q) = %q, %v, %d; want %q, %v, %d",
				tt.user, tt.password, user, pw, logon, tt.wantUser, tt.wantPW, tt.wantLogon)
		}
	}
	// The service-account logon must get no password at all: a nil
	// (VT_NULL), never an empty string (VT_BSTR).
	if _, pw, _ := principalFor("", ""); pw != nil {
		t.Errorf("SYSTEM's password = %#v, want nil", pw)
	}
}

// excepInfoMsg stands in for ole.EXCEPINFO with a description.
type excepInfoMsg struct {
	scode uint32
	text  string
}

func (e excepInfoMsg) SCODE() uint32 { return e.scode }
func (e excepInfoMsg) Error() string { return e.text }

// UAT I.win_task.present, Run 2 on rc.21: "RegisterTaskDefinition(...):
// call RegisterTaskDefinition: Exception occurred." with no HRESULT. The
// error names the HRESULTs and the principal, never the task's XML (its
// command line may hold a secret).
func TestRegisterErrorNamesHRESULT(t *testing.T) {
	inner := ole.NewErrorWithSubError(dispEException, "", excepInfoMsg{scode: 0x80070057, text: "The parameter is incorrect."})
	err := registerError(`\imas-uat\uat-abc`, "SYSTEM", logonServiceAccount, inner)
	for _, want := range []string{`RegisterTaskDefinition("\\imas-uat\\uat-abc") as SYSTEM, logon type 5`, "HRESULT 0x80020009", "scode 0x80070057", "The parameter is incorrect."} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "XML") || strings.Contains(err.Error(), "<Task") {
		t.Errorf("the error quotes the task: %q", err)
	}
}

// "Member not found" is not read as absent: it means a property was
// called as a method (fixed in itemAt), not that the task is missing, and
// reading it as absent would let absent leave a task in place.
func TestMemberNotFoundIsNotNotFound(t *testing.T) {
	err := ole.NewErrorWithSubError(dispEException, "", excepInfo{dispEMemberNotFound})
	if isNotFoundErr(err) || isNotFoundErr(ole.NewError(dispEMemberNotFound)) {
		t.Error("DISP_E_MEMBERNOTFOUND must not read as a missing task")
	}
}
