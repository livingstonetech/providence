// +build darwin

package audit

import (

	/*
		#cgo CFLAGS: -x objective-c
		#cgo LDFLAGS: -framework Foundation -lEndpointSecurity
		#import "audit_darwin.h"
	*/
	"C"
	"fmt"

	"github.com/livingstonetech/providence/transformer"
)
import "unsafe"

// Sorry but I had to go global.
var globalAu Auditor

//Auditor : Entrypoint to auditing
type Auditor struct {
	Name              string
	TransformerModule transformer.Transformer
}

//StartAudit : Starts Audit
func (au Auditor) StartAudit() {
	var status C.int
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
	C.enableMonitoringType(C.AUDIT_MONITOR_FILE, &status)
	if status == C.STATUS_ERROR {
		fmt.Println("Error initializing monitoring")
		return
	}
	C.enableMonitoringType(C.AUDIT_MONITOR_PROCESS, &status)
	if status == C.STATUS_ERROR {
		fmt.Println("Error initializing monitoring")
		return
	}
	// Assigning global here.
	globalAu = au
}

//StopAudit : Stops audit?
func (au Auditor) StopAudit() {

}

func esEventTypeToStr(eventType C.es_event_type_t) string {
	switch eventType {
	case C.ES_EVENT_TYPE_NOTIFY_EXEC:
		return "ES_EVENT_TYPE_NOTIFY_EXEC"
	case C.ES_EVENT_TYPE_NOTIFY_EXIT:
		return "ES_EVENT_TYPE_NOTIFY_EXIT"
	case C.ES_EVENT_TYPE_NOTIFY_FORK:
		return "ES_EVENT_TYPE_NOTIFY_FORK"
	case C.ES_EVENT_TYPE_NOTIFY_OPEN:
		return "ES_EVENT_TYPE_NOTIFY_OPEN"
	case C.ES_EVENT_TYPE_NOTIFY_CREATE:
		return "ES_EVENT_TYPE_NOTIFY_CREATE"
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
		break
	case C.ES_EVENT_TYPE_NOTIFY_EXIT:
		eventData := (*C.es_event_exit_t)(unsafe.Pointer(&message.event))
		esEventExit := transformer.ESEventExit{
			Stat: int(eventData.stat),
		}
		esMessage.EventData = esEventExit
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
		break
	// File system events
	case C.ES_EVENT_TYPE_NOTIFY_OPEN:
		eventData := (*C.es_event_open_t)(unsafe.Pointer(&message.event))
		var file *C.es_file_t = eventData.file
		esEventOpen := transformer.ESEventOpen{
			FilePath: C.GoString(file.path.data),
		}
		esMessage.EventData = esEventOpen
		break

	case C.ES_EVENT_TYPE_NOTIFY_CREATE:
		eventData := (*C.es_event_create_t)(unsafe.Pointer(&message.event))
		// var esEventCreate transformer.ESEventCreate
		switch eventData.destination_type {
		case C.ES_DESTINATION_TYPE_EXISTING_FILE:
			destination := (*C.es_file_t)(unsafe.Pointer(&eventData.destination))
			// esEventCreate.FileDirectory = ""
			// esEventCreate.FilePath = C.GoString(destination.existing_file.path.data)
			fmt.Printf("%+v\n", destination)
			break
		case C.ES_DESTINATION_TYPE_NEW_PATH:
			break
		default:
			// null?
			break
		}

		break
	default:
		fmt.Println("Unknown Event ", message.event_type)
		break
	}

	globalAu.TransformerModule.Transform(esMessage)
}
