// +build darwin

package audit

import (
	/*
		#cgo CFLAGS: -x objective-c
		#cgo LDFLAGS: -framework Foundation -lEndpointSecurity
		#import "audit_darwin.h"
	*/
	"C"
)
import (
	"fmt"
)

//StartAudit : Starts Audit
func StartAudit() {
	var status C.int
	C.startMonitoring(&status)
	if status == C.STATUS_ERROR {
		// Panic here because without this succeeding, we can't do anything.
		// We expect that the main function shall recover.
		panic("Error initializing monitoring. Panicking...")
	}
}

//ConfigureAudit : Configures auditing
func ConfigureAudit() {
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
}

//StopAudit : Stops audit?
func StopAudit() {

}

//export goBridge
func goBridge(message *C.es_message_t) {
	fmt.Printf("%v\n", message)
}
