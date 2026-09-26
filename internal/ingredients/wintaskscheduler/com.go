//go:build windows

package wintaskscheduler

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// Task Scheduler 2.0 COM constants (taskschd.idl).
const (
	taskActionExec = 0 // TASK_ACTION_EXEC

	taskCreateOrUpdate = 6 // TASK_CREATE_OR_UPDATE

	logonServiceAccount = 5 // TASK_LOGON_SERVICE_ACCOUNT
	logonPassword       = 1 // TASK_LOGON_PASSWORD
	logonS4U            = 2 // TASK_LOGON_S4U

	runLevelHighestConst = 1 // TASK_RUNLEVEL_HIGHEST
)

// ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND, the HRESULTs
// GetFolder/GetTask/DeleteTask surface when the folder or task doesn't
// exist.
const (
	hrFileNotFound = 0x80070002
	hrPathNotFound = 0x80070003
)

func isNotFoundErr(err error) bool {
	var oleErr *ole.OleError
	if errors.As(err, &oleErr) {
		switch oleErr.Code() {
		case hrFileNotFound, hrPathNotFound:
			return true
		}
	}
	return false
}

// oleTaskBackend implements taskBackend against the real Task
// Scheduler 2.0 COM service (Schedule.Service), the same object Salt's
// win_task module drives via
// win32com.client.Dispatch("Schedule.Service"). It follows the COM
// lifecycle pattern winshortcut/com.go established: lock the calling
// goroutine to one OS thread for the apartment's lifetime, initialize
// a single-threaded apartment, and release every acquired
// IUnknown/IDispatch (Clear-ing every VARIANT that doesn't own one)
// before CoUninitialize.
//
// One rule that's easy to get backwards, and worth stating explicitly
// since it's the exact "missed Release" failure mode COM lifecycle
// bugs take: a VARIANT of type VT_DISPATCH and the *ole.IDispatch its
// ToIDispatch() extracts are the SAME underlying COM reference --
// VariantClear releases VT_DISPATCH/VT_UNKNOWN contents per the Win32
// API contract, exactly like IDispatch.Release() does. Calling both on
// the same value over-releases the object. dispatchResult below is the
// single chokepoint every VT_DISPATCH-typed VARIANT in this file goes
// through, specifically so that rule only has to be reasoned about
// once: it transfers ownership of the reference to the returned
// *ole.IDispatch (the caller Release()s it) and only calls Clear()
// itself on the branch where no ownership is transferred.
type oleTaskBackend struct{}

// withService initializes a single-threaded COM apartment, connects to
// the local Task Scheduler service, and runs fn against it. Every COM
// reference withService itself acquires is released before it returns,
// regardless of what fn returns.
func withService(fn func(service *ole.IDispatch) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		return fmt.Errorf("wintaskscheduler: CoInitializeEx: %w", err)
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("wintaskscheduler: create Schedule.Service: %w", err)
	}
	defer unknown.Release()

	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("wintaskscheduler: Schedule.Service has no IDispatch: %w", err)
	}
	defer service.Release()

	if err := callVoid(service, "Connect"); err != nil {
		return fmt.Errorf("wintaskscheduler: Connect: %w", err)
	}

	return fn(service)
}

// dispatchResult extracts the IDispatch a CallMethod/GetProperty result
// VARIANT holds, transferring the VARIANT's COM reference to the
// returned IDispatch. The caller must Release() it and must NOT also
// Clear() the source VARIANT -- see the oleTaskBackend doc comment.
func dispatchResult(v *ole.VARIANT, err error, context string) (*ole.IDispatch, error) {
	if err != nil {
		return nil, fmt.Errorf("wintaskscheduler: %s: %w", context, err)
	}
	d := v.ToIDispatch()
	if d == nil {
		v.Clear()
		return nil, fmt.Errorf("wintaskscheduler: %s: expected an object result", context)
	}
	return d, nil
}

func getDispatchProp(disp *ole.IDispatch, name string) (*ole.IDispatch, error) {
	v, err := oleutil.GetProperty(disp, name)
	return dispatchResult(v, err, "get "+name)
}

func callDispatch(disp *ole.IDispatch, method string, args ...interface{}) (*ole.IDispatch, error) {
	v, err := oleutil.CallMethod(disp, method, args...)
	return dispatchResult(v, err, "call "+method)
}

// callVoid invokes a method whose result carries no ownership this
// package needs to keep (a bare HRESULT-style call): it Clears the
// result VARIANT itself since no IDispatch is extracted from it.
func callVoid(disp *ole.IDispatch, method string, args ...interface{}) error {
	v, err := oleutil.CallMethod(disp, method, args...)
	if err != nil {
		return err
	}
	v.Clear()
	return nil
}

func getStringProp(disp *ole.IDispatch, name string) (string, error) {
	v, err := oleutil.GetProperty(disp, name)
	if err != nil {
		return "", fmt.Errorf("wintaskscheduler: get %s: %w", name, err)
	}
	defer v.Clear()
	s, _ := v.Value().(string)
	return s, nil
}

func getIntProp(disp *ole.IDispatch, name string) (int, error) {
	v, err := oleutil.GetProperty(disp, name)
	if err != nil {
		return 0, fmt.Errorf("wintaskscheduler: get %s: %w", name, err)
	}
	defer v.Clear()
	switch n := v.Value().(type) {
	case int32:
		return int(n), nil
	case int64:
		return int(n), nil
	case int:
		return n, nil
	default:
		return 0, nil
	}
}

func getBoolProp(disp *ole.IDispatch, name string) (bool, error) {
	v, err := oleutil.GetProperty(disp, name)
	if err != nil {
		return false, fmt.Errorf("wintaskscheduler: get %s: %w", name, err)
	}
	defer v.Clear()
	b, _ := v.Value().(bool)
	return b, nil
}

func setStringProp(disp *ole.IDispatch, name, value string) error {
	v, err := oleutil.PutProperty(disp, name, value)
	if err != nil {
		return fmt.Errorf("wintaskscheduler: set %s: %w", name, err)
	}
	defer v.Clear()
	return nil
}

func setIntProp(disp *ole.IDispatch, name string, value int) error {
	v, err := oleutil.PutProperty(disp, name, int32(value))
	if err != nil {
		return fmt.Errorf("wintaskscheduler: set %s: %w", name, err)
	}
	defer v.Clear()
	return nil
}

func setBoolProp(disp *ole.IDispatch, name string, value bool) error {
	v, err := oleutil.PutProperty(disp, name, value)
	if err != nil {
		return fmt.Errorf("wintaskscheduler: set %s: %w", name, err)
	}
	defer v.Clear()
	return nil
}

// splitTaskPath splits a Task Scheduler path like `\imas\backup` into
// its containing folder (`\imas`) and task name (`backup`).
func splitTaskPath(path string) (folder, name string) {
	idx := strings.LastIndex(path, `\`)
	if idx < 0 {
		return `\`, path
	}
	folder = path[:idx]
	if folder == "" {
		folder = `\`
	}
	return folder, path[idx+1:]
}

// ensureFolder returns the ITaskFolder at folderPath, creating any
// missing segments along the way one level at a time (ITaskFolder's
// CreateFolder, like GetFolder, only operates on an immediate child of
// the folder it's called on).
func ensureFolder(service *ole.IDispatch, folderPath string) (*ole.IDispatch, error) {
	current, err := callDispatch(service, "GetFolder", `\`)
	if err != nil {
		return nil, err
	}
	for _, seg := range strings.Split(strings.Trim(folderPath, `\`), `\`) {
		if seg == "" {
			continue
		}
		next, err := callDispatch(current, "GetFolder", seg)
		if err != nil {
			next, err = callDispatch(current, "CreateFolder", seg)
			if err != nil {
				current.Release()
				return nil, fmt.Errorf("wintaskscheduler: create folder %q: %w", seg, err)
			}
		}
		current.Release()
		current = next
	}
	return current, nil
}

func (oleTaskBackend) Load(path string) (taskState, error) {
	var state taskState
	folderPath, taskName := splitTaskPath(path)

	err := withService(func(service *ole.IDispatch) error {
		folder, err := callDispatch(service, "GetFolder", folderPath)
		if err != nil {
			if isNotFoundErr(err) {
				return ErrTaskNotFound
			}
			return err
		}
		defer folder.Release()

		registeredTask, err := callDispatch(folder, "GetTask", taskName)
		if err != nil {
			if isNotFoundErr(err) {
				return ErrTaskNotFound
			}
			return err
		}
		defer registeredTask.Release()

		taskDef, err := getDispatchProp(registeredTask, "Definition")
		if err != nil {
			return err
		}
		defer taskDef.Release()

		regInfo, err := getDispatchProp(taskDef, "RegistrationInfo")
		if err != nil {
			return err
		}
		defer regInfo.Release()
		if state.Description, err = getStringProp(regInfo, "Description"); err != nil {
			return err
		}

		principal, err := getDispatchProp(taskDef, "Principal")
		if err != nil {
			return err
		}
		defer principal.Release()
		if state.UserName, err = getStringProp(principal, "UserId"); err != nil {
			return err
		}
		if strings.EqualFold(state.UserName, "SYSTEM") || strings.EqualFold(state.UserName, `NT AUTHORITY\SYSTEM`) {
			state.UserName = ""
		}
		runLevel, err := getIntProp(principal, "RunLevel")
		if err != nil {
			return err
		}
		state.RunLevel = "limited"
		if runLevel == runLevelHighestConst {
			state.RunLevel = "highest"
		}

		settings, err := getDispatchProp(taskDef, "Settings")
		if err != nil {
			return err
		}
		defer settings.Release()
		if state.Enabled, err = getBoolProp(settings, "Enabled"); err != nil {
			return err
		}
		if state.Hidden, err = getBoolProp(settings, "Hidden"); err != nil {
			return err
		}

		// Actions and Triggers are ITaskFolder-style collections, which
		// (unlike WUA's IUpdateCollection) are 1-based: Item(1) is the
		// first element.
		actions, err := getDispatchProp(taskDef, "Actions")
		if err != nil {
			return err
		}
		defer actions.Release()
		actionCount, err := getIntProp(actions, "Count")
		if err != nil {
			return err
		}
		if actionCount > 0 {
			action, err := callDispatch(actions, "Item", 1)
			if err != nil {
				return err
			}
			defer action.Release()
			if state.Command, err = getStringProp(action, "Path"); err != nil {
				return err
			}
			if state.Arguments, err = getStringProp(action, "Arguments"); err != nil {
				return err
			}
			if state.WorkingDir, err = getStringProp(action, "WorkingDirectory"); err != nil {
				return err
			}
		}

		triggers, err := getDispatchProp(taskDef, "Triggers")
		if err != nil {
			return err
		}
		defer triggers.Release()
		triggerCount, err := getIntProp(triggers, "Count")
		if err != nil {
			return err
		}
		if triggerCount > 0 {
			trigger, err := callDispatch(triggers, "Item", 1)
			if err != nil {
				return err
			}
			defer trigger.Release()

			triggerType, err := getIntProp(trigger, "Type")
			if err != nil {
				return err
			}
			state.TriggerType = triggerTypeName(triggerType)

			switch triggerType {
			case triggerOnce:
				if state.StartBoundary, err = getStringProp(trigger, "StartBoundary"); err != nil {
					return err
				}
			case triggerDaily:
				if state.StartBoundary, err = getStringProp(trigger, "StartBoundary"); err != nil {
					return err
				}
				if state.DaysInterval, err = getIntProp(trigger, "DaysInterval"); err != nil {
					return err
				}
			case triggerWeekly:
				if state.StartBoundary, err = getStringProp(trigger, "StartBoundary"); err != nil {
					return err
				}
				if state.WeeksInterval, err = getIntProp(trigger, "WeeksInterval"); err != nil {
					return err
				}
				mask, err := getIntProp(trigger, "DaysOfWeek")
				if err != nil {
					return err
				}
				state.DaysOfWeek = maskToDaysOfWeek(mask)
			}
		}

		return nil
	})
	if err != nil {
		return taskState{}, err
	}
	return state, nil
}

func (oleTaskBackend) Save(path string, state taskState, password string) error {
	folderPath, taskName := splitTaskPath(path)

	return withService(func(service *ole.IDispatch) error {
		folder, err := ensureFolder(service, folderPath)
		if err != nil {
			return err
		}
		defer folder.Release()

		taskDef, err := callDispatch(service, "NewTask", 0)
		if err != nil {
			return err
		}
		defer taskDef.Release()

		regInfo, err := getDispatchProp(taskDef, "RegistrationInfo")
		if err != nil {
			return err
		}
		defer regInfo.Release()
		if err := setStringProp(regInfo, "Description", state.Description); err != nil {
			return err
		}

		principal, err := getDispatchProp(taskDef, "Principal")
		if err != nil {
			return err
		}
		defer principal.Release()

		runLevelConst := 0
		if state.RunLevel == "highest" {
			runLevelConst = runLevelHighestConst
		}
		if err := setIntProp(principal, "RunLevel", runLevelConst); err != nil {
			return err
		}

		userID := state.UserName
		var logonType int
		switch {
		case state.UserName == "":
			userID = "SYSTEM"
			logonType = logonServiceAccount
		case password != "":
			logonType = logonPassword
		default:
			logonType = logonS4U
		}
		if err := setStringProp(principal, "UserId", userID); err != nil {
			return err
		}
		if err := setIntProp(principal, "LogonType", logonType); err != nil {
			return err
		}

		settings, err := getDispatchProp(taskDef, "Settings")
		if err != nil {
			return err
		}
		defer settings.Release()
		if err := setBoolProp(settings, "Enabled", state.Enabled); err != nil {
			return err
		}
		if err := setBoolProp(settings, "Hidden", state.Hidden); err != nil {
			return err
		}

		actions, err := getDispatchProp(taskDef, "Actions")
		if err != nil {
			return err
		}
		defer actions.Release()
		action, err := callDispatch(actions, "Create", taskActionExec)
		if err != nil {
			return err
		}
		defer action.Release()
		if err := setStringProp(action, "Path", state.Command); err != nil {
			return err
		}
		if state.Arguments != "" {
			if err := setStringProp(action, "Arguments", state.Arguments); err != nil {
				return err
			}
		}
		if state.WorkingDir != "" {
			if err := setStringProp(action, "WorkingDirectory", state.WorkingDir); err != nil {
				return err
			}
		}

		triggers, err := getDispatchProp(taskDef, "Triggers")
		if err != nil {
			return err
		}
		defer triggers.Release()
		triggerConst, ok := triggerTypes[state.TriggerType]
		if !ok {
			return fmt.Errorf("wintaskscheduler: %w: %q", ErrInvalidTriggerType, state.TriggerType)
		}
		trigger, err := callDispatch(triggers, "Create", triggerConst)
		if err != nil {
			return err
		}
		defer trigger.Release()

		switch state.TriggerType {
		case "once":
			if err := setStringProp(trigger, "StartBoundary", state.StartBoundary); err != nil {
				return err
			}
		case "daily":
			if err := setStringProp(trigger, "StartBoundary", state.StartBoundary); err != nil {
				return err
			}
			if err := setIntProp(trigger, "DaysInterval", state.DaysInterval); err != nil {
				return err
			}
		case "weekly":
			if err := setStringProp(trigger, "StartBoundary", state.StartBoundary); err != nil {
				return err
			}
			if err := setIntProp(trigger, "WeeksInterval", state.WeeksInterval); err != nil {
				return err
			}
			if err := setIntProp(trigger, "DaysOfWeek", daysOfWeekMask(state.DaysOfWeek)); err != nil {
				return err
			}
		}

		registered, err := callDispatch(folder, "RegisterTaskDefinition",
			taskName, taskDef, taskCreateOrUpdate, userID, password, logonType)
		if err != nil {
			return fmt.Errorf("wintaskscheduler: RegisterTaskDefinition(%q): %w", path, err)
		}
		registered.Release()

		return nil
	})
}

func (oleTaskBackend) Delete(path string) error {
	folderPath, taskName := splitTaskPath(path)
	return withService(func(service *ole.IDispatch) error {
		folder, err := callDispatch(service, "GetFolder", folderPath)
		if err != nil {
			if isNotFoundErr(err) {
				return nil
			}
			return err
		}
		defer folder.Release()

		if err := callVoid(folder, "DeleteTask", taskName, 0); err != nil {
			if isNotFoundErr(err) {
				return nil
			}
			return fmt.Errorf("wintaskscheduler: DeleteTask(%q): %w", path, err)
		}
		return nil
	})
}
