// +build darwin

package audit

import (
	"github.com/spf13/viper"

	/*
		#cgo CFLAGS: -x objective-c -Wimplicit-function-declaration
		#cgo LDFLAGS: -framework Foundation -lEndpointSecurity -lbsm
		#import "audit_darwin.h"
		#import <bsm/libbsm.h>
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

func esGetIDsFromAuditToken(token C.audit_token_t) (int, int, int) {
	uid := int(C.audit_token_to_auid(token))
	gid := int(C.audit_token_to_rgid(token))
	pid := int(C.audit_token_to_pid(token))

	return uid, gid, pid
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
	uid, gid, pid := esGetIDsFromAuditToken(message.process.audit_token)
	esProcess := transformer.ESProcess{
		UID:            uid,
		GID:            gid,
		PID:            pid,
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
		targetUID, targetGID, targetPID := esGetIDsFromAuditToken(targetData.audit_token)
		esEventExec := transformer.ESEventExec{
			UID:             targetUID,
			GID:             targetGID,
			PID:             targetPID,
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
		childUID, childGID, childPID := esGetIDsFromAuditToken(childData.audit_token)
		esEventFork := transformer.ESEventFork{
			UID:            childUID,
			GID:            childGID,
			PID:            childPID,
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
		eventData := (*C.es_event_signal_t)(unsafe.Pointer(&message.event))
		var processData *C.es_process_t = eventData.target
		processUID, processGID, processPID := esGetIDsFromAuditToken(processData.audit_token)
		esEventSignal := transformer.ESEventSignal{
			UID:             processUID,
			GID:             processGID,
			PID:             processPID,
			Signal:          int(eventData.sig),
			TargetPpid:      int(eventData.target.ppid),
			TargetGroupID:   int(eventData.target.group_id),
			TargetSigningID: C.GoString(processData.signing_id.data),
			TargetTeamID:    C.GoString(processData.team_id.data),
			TargetCDHash:    esCDHashToString(processData.cdhash),
		}
		esMessage.EventData = esEventSignal
		esMessage.EventCategory = "process"
		break

	case C.ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
		eventData := (*C.es_event_kextload_t)(unsafe.Pointer(&message.event))
		esEventKextLoad := transformer.ESEventKextLoad{
			Identifier: C.GoString(eventData.identifier.data),
		}
		esMessage.EventData = esEventKextLoad
		esMessage.EventCategory = "process"
		break

	case C.ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
		eventData := (*C.es_event_kextunload_t)(unsafe.Pointer(&message.event))
		esEventKextUnoad := transformer.ESEventKextUnload{
			Identifier: C.GoString(eventData.identifier.data),
		}
		esMessage.EventData = esEventKextUnoad
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
		eventData := (*C.es_event_close_t)(unsafe.Pointer(&message.event))
		var file *C.es_file_t = eventData.target
		esEventClose := transformer.ESEventClose{
			Modified: bool(eventData.modified),
			FilePath: C.GoString(file.path.data),
		}
		esMessage.EventData = esEventClose
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
			esEventCreate.FilePath = ""
			break
		default:
			// null?
			break
		}
		esMessage.EventData = esEventCreate
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_RENAME:
		// TODO fix this. Same as Create event
		eventData := (*C.es_event_rename_t)(unsafe.Pointer(&message.event))
		var esEventRename transformer.ESEventRename
		switch eventData.destination_type {
		case C.ES_DESTINATION_TYPE_EXISTING_FILE:
			// destination := (*C.es_file_t)(unsafe.Pointer(&eventData.destination))
			// esEventCreate.FileDirectory = ""
			esEventRename.SourcePath = ""
			esEventRename.DestinationPath = ""
			break
		case C.ES_DESTINATION_TYPE_NEW_PATH:
			// destination := (*esCreateNewPath)(unsafe.Pointer(&eventData.destination))
			esEventRename.SourcePath = ""
			esEventRename.DestinationPath = ""
			break
		default:
			// null?
			break
		}
		esMessage.EventData = esEventRename
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_LINK:
		eventData := (*C.es_event_link_t)(unsafe.Pointer(&message.event))
		var source *C.es_file_t = eventData.source
		var targetDir *C.es_file_t = eventData.target_dir
		esEventLink := transformer.ESEventLink{
			SourcePath: C.GoString(source.path.data),
			TargetDir:  C.GoString(targetDir.path.data),
			TargetPath: C.GoString(eventData.target_filename.data),
		}
		esMessage.EventData = esEventLink
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_UNLINK:
		eventData := (*C.es_event_unlink_t)(unsafe.Pointer(&message.event))
		var target *C.es_file_t = eventData.target
		var parentDir *C.es_file_t = eventData.parent_dir
		esEventUnlink := transformer.ESEventUnlink{
			TargetPath:            C.GoString(target.path.data),
			TargetParentDirectory: C.GoString(parentDir.path.data),
		}
		esMessage.EventData = esEventUnlink
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_SETMODE:
		eventData := (*C.es_event_setmode_t)(unsafe.Pointer(&message.event))
		var target *C.es_file_t = eventData.target
		esEventSetMode := transformer.ESEventSetMode{
			NewMode:    uint16(eventData.mode),
			TargetPath: C.GoString(target.path.data),
		}
		esMessage.EventData = esEventSetMode
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_SETOWNER:
		eventData := (*C.es_event_setowner_t)(unsafe.Pointer(&message.event))
		var target *C.es_file_t = eventData.target
		esEventSetOwner := transformer.ESEventSetOwner{
			UID:        uint32(eventData.uid),
			GID:        uint32(eventData.gid),
			TargetPath: C.GoString(target.path.data),
		}
		esMessage.EventData = esEventSetOwner
		esMessage.EventCategory = "file"
		break

	case C.ES_EVENT_TYPE_NOTIFY_WRITE:
		eventData := (*C.es_event_setowner_t)(unsafe.Pointer(&message.event))
		var target *C.es_file_t = eventData.target
		esEventWrite := transformer.ESEventWrite{
			FilePath: C.GoString(target.path.data),
		}
		esMessage.EventData = esEventWrite
		esMessage.EventCategory = "file"
		break

	default:
		fmt.Println("Unknown Event ", message.event_type)
		break
	}
	transChan <- esMessage
}
