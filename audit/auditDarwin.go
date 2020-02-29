// +build darwin

package audit

import (
	/*
		#cgo CFLAGS: -x objective-c
		#cgo LDFLAGS: -framework foundation
		#import "audit_darwin.h"
	*/
	"C"
)
import "fmt"

//StartAudit : Starts Audit
func StartAudit() {

}

//ConfigureAudit : Configures auditing
func ConfigureAudit() {
	status := C.int(1)
	C.enableMonitoringType(C.AUDIT_MONITOR_PROCESS, &status)
	fmt.Println(status)
}

//StopAudit : Stops audit?
func StopAudit() {

}
