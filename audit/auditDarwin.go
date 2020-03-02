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

// Sorry but I had to go global.
var globalAu Auditor

//Audit : Entrypoint to auditing
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

//export goBridge
func goBridge(message *C.es_message_t) {
	// fmt.Printf("%+v\n", message)
	globalAu.TransformerModule.Hello("bois")
}
