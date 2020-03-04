// +build darwin

package audit

import (
	"github.com/spf13/viper"

	/*
		#cgo CFLAGS: -x objective-c -Wimplicit-function-declaration
		#cgo LDFLAGS: -framework Foundation -lEndpointSecurity
		#import "audit_darwin.h"
	*/
	"C"
	"fmt"
	"unsafe"

	"github.com/livingstonetech/providence/transformer"
)

// Sorry but I had to go global.
var transChan chan transformer.ESMessage

//Auditor : Entrypoint to auditing
type Auditor struct {
	Config        *viper.Viper
	transformer   transformer.Transformer
	enableProcess bool
	enableFS      bool
}

//CreateAudit constructor for audit
func CreateAudit(config *viper.Viper) *Auditor {
	// var rules []map[string]interface{}
	rules := config.Get("rules").(map[string]interface{})

	fileSystemRules := rules["file_system"].(map[string]interface{})
	processRules := rules["process"].(map[string]interface{})

	// dispatchConfig := config.Get("dispatch").([]interface{})
	dispatchConfig := config.GetStringMap("dispatch")

	au := Auditor{
		Config: config,
	}

	if len(fileSystemRules) == 0 {
		au.enableFS = false
	} else {
		au.enableFS = true
	}
	if len(processRules) == 0 {
		au.enableProcess = false
	} else {
		au.enableProcess = true
	}

	au.transformer = transformer.CreateTransformer(processRules, fileSystemRules, dispatchConfig)

	return &au
}

//StartAudit : Starts Audit
func (au Auditor) StartAudit() {
	var status C.int
	go au.transformer.Listen(transChan)
	C.startMonitoring(&status)
	if status == C.STATUS_ERROR {
		// Panic here because without this succeeding, we can't do anything.
		// We expect that the main function shall recover.
		panic("Error initializing monitoring. Panicking...")
	}
}

//ConfigureAudit : Configures auditing
func (au Auditor) ConfigureAudit() {
	var status C.int
	if au.enableFS == true {
		fmt.Println("Enabling FS monitoring...")
		C.enableMonitoringType(C.AUDIT_MONITOR_FILE, &status)
		if status == C.STATUS_ERROR {
			fmt.Println("Error initializing monitoring")
		}
	}
	if au.enableProcess == true {
		fmt.Println("Enabling Process monitoring...")
		C.enableMonitoringType(C.AUDIT_MONITOR_PROCESS, &status)
		if status == C.STATUS_ERROR {
			fmt.Println("Error initializing monitoring")
		}
	}

	// Assigning global here.
	transChan = make(chan transformer.ESMessage)
}

//StopAudit : Stops audit?
func (au Auditor) StopAudit() {
	close(transChan)
}

func esEventTypeToStr(eventType C.es_event_type_t) string {
	switch eventType {
	case C.ES_EVENT_TYPE_NOTIFY_EXEC:
		return "ES_EVENT_TYPE_NOTIFY_EXEC"
	case C.ES_EVENT_TYPE_NOTIFY_EXIT:
		return "ES_EVENT_TYPE_NOTIFY_EXIT"
	case C.ES_EVENT_TYPE_NOTIFY_FORK:
		return "ES_EVENT_TYPE_NOTIFY_FORK"
	case C.ES_EVENT_TYPE_NOTIFY_SIGNAL:
		return "ES_EVENT_TYPE_NOTIFY_SIGNAL"
	case C.ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
		return "ES_EVENT_TYPE_NOTIFY_KEXTLOAD"
	case C.ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
		return "ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD"
	case C.ES_EVENT_TYPE_NOTIFY_OPEN:
		return "ES_EVENT_TYPE_NOTIFY_OPEN"
	case C.ES_EVENT_TYPE_NOTIFY_CLOSE:
		return "ES_EVENT_TYPE_NOTIFY_CLOSE"
	case C.ES_EVENT_TYPE_NOTIFY_CREATE:
		return "ES_EVENT_TYPE_NOTIFY_CREATE"
	case C.ES_EVENT_TYPE_NOTIFY_RENAME:
		return "ES_EVENT_TYPE_NOTIFY_RENAME"
	case C.ES_EVENT_TYPE_NOTIFY_LINK:
		return "ES_EVENT_TYPE_NOTIFY_LINK"
	case C.ES_EVENT_TYPE_NOTIFY_UNLINK:
		return "ES_EVENT_TYPE_NOTIFY_UNLINK"
	case C.ES_EVENT_TYPE_NOTIFY_SETMODE:
		return "ES_EVENT_TYPE_NOTIFY_SETMODE"
	case C.ES_EVENT_TYPE_NOTIFY_SETOWNER:
		return "ES_EVENT_TYPE_NOTIFY_SETOWNER"
	case C.ES_EVENT_TYPE_NOTIFY_WRITE:
		return "ES_EVENT_TYPE_NOTIFY_WRITE"
	case C.ES_EVENT_TYPE_NOTIFY_MOUNT:
		return "ES_EVENT_TYPE_NOTIFY_MOUNT"
	case C.ES_EVENT_TYPE_NOTIFY_UNMOUNT:
		return "ES_EVENT_TYPE_NOTIFY_UNMOUNT"
	default:
		return "UNKNOWN EVENT"
	}
}

func esCDHashToString(cdHashArray [20]C.uint8_t) string {
	cdHash := ""
	for i := 0; i < 20; i++ {
		cdHash += fmt.Sprintf("%x", cdHashArray[i])
	}
	return cdHash
}

//export goBridge
func goBridge(message *C.es_message_t) {
	var msgExecutable *C.es_file_t = message.process.executable
	esProcess := transformer.ESProcess{
		Ppid:           int(message.process.ppid),
		GroupID:        int(message.process.group_id),
		SigningID:      C.GoString(message.process.signing_id.data),
		TeamID:         C.GoString(message.process.team_id.data),
		CDHash:         esCDHashToString(message.process.cdhash),
		ExecutablePath: C.GoString(msgExecutable.path.data),
	}
	esMessage := transformer.ESMessage{
		MachTime:  uint64(message.mach_time),
		Process:   esProcess,
		EventType: esEventTypeToStr(message.event_type),
	}
	switch message.event_type {
	// Process events
	case C.ES_EVENT_TYPE_NOTIFY_EXEC:
		eventData := (*C.es_event_exec_t)(unsafe.Pointer(&message.event))
		var targetData *C.es_process_t = eventData.target
		esEventExec := transformer.ESEventExec{
			TargetPpid:      int(eventData.target.ppid),
			TargetGroupID:   int(eventData.target.group_id),
			TargetSigningID: C.GoString(targetData.signing_id.data),
			TargetTeamID:    C.GoString(targetData.team_id.data),
			TargetCDHash:    esCDHashToString(targetData.cdhash),
		}
		esMessage.EventData = esEventExec
		esMessage.EventCategory = "process"
		break
	case C.ES_EVENT_TYPE_NOTIFY_EXIT:
		eventData := (*C.es_event_exit_t)(unsafe.Pointer(&message.event))
		esEventExit := transformer.ESEventExit{
			Stat: int(eventData.stat),
		}
		esMessage.EventData = esEventExit
		esMessage.EventCategory = "process"
		break
	case C.ES_EVENT_TYPE_NOTIFY_FORK:
		eventData := (*C.es_event_fork_t)(unsafe.Pointer(&message.event))
		var childData *C.es_process_t = eventData.child
		esEventFork := transformer.ESEventFork{
			ChildPpid:      int(eventData.child.ppid),
			ChildGroupID:   int(eventData.child.group_id),
			ChildSigningID: C.GoString(childData.signing_id.data),
			ChildTeamID:    C.GoString(childData.team_id.data),
			ChildCDHash:    esCDHashToString(childData.cdhash),
		}
		esMessage.EventData = esEventFork
		esMessage.EventCategory = "process"
		break

	case C.ES_EVENT_TYPE_NOTIFY_SIGNAL:
		// eventData := (*C.es_event_signal_t)(unsafe.Pointer(&message.event))
		esMessage.EventCategory = "process"
		break

	case C.ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
		esMessage.EventCategory = "process"
		break

	case C.ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
		esMessage.EventCategory = "process"
		break

	// File system events
	case C.ES_EVENT_TYPE_NOTIFY_OPEN:
		eventData := (*C.es_event_open_t)(unsafe.Pointer(&message.event))
		var file *C.es_file_t = eventData.file
		esEventOpen := transformer.ESEventOpen{
			FilePath: C.GoString(file.path.data),
		}
		esMessage.EventData = esEventOpen
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_CLOSE:
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_CREATE:
		//TODO: Need to fix this. Right now the union is not casting properly.
		eventData := (*C.es_event_create_t)(unsafe.Pointer(&message.event))
		var esEventCreate transformer.ESEventCreate
		switch eventData.destination_type {
		case C.ES_DESTINATION_TYPE_EXISTING_FILE:
			destination := (*C.es_file_t)(unsafe.Pointer(&eventData.destination))
			// esEventCreate.FileDirectory = ""
			esEventCreate.FilePath = C.GoString(destination.path.data)
			break
		case C.ES_DESTINATION_TYPE_NEW_PATH:
			// destination := (*esCreateNewPath)(unsafe.Pointer(&eventData.destination))
			break
		default:
			// null?
			break
		}
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_RENAME:
		// TODO fix this. Same as Create event
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_LINK:
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_UNLINK:
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_SETMODE:
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_SETOWNER:
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_WRITE:
		esMessage.EventCategory = "file"
		break

	default:
		fmt.Println("Unknown Event ", message.event_type)
		break
	}
	transChan <- esMessage
}
