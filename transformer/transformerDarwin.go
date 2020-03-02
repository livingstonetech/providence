//+build darwin

package transformer

import (
	/*
		#cgo CFLAGS: -x objective-c
		#cgo LDFLAGS: -lbsm -lEndpointSecurity
			#import <bsm/libbsm.h>
			#import <EndpointSecurity/EndpointSecurity.h>
	*/
	"C"
	"fmt"
)
import "encoding/json"

// ES Types

//ESMessage : Part of the Message type from Apple's Security framework
type ESMessage struct {
	MachTime  uint64
	Process   ESProcess
	EventType string
	EventData interface{} // Interface for dynamic data. This depends on EventType.
}

//ESProcess : Process struct of ESF
type ESProcess struct {
	Ppid           int
	GroupID        int
	SigningID      string
	TeamID         string
	CDHash         string
	ExecutablePath string // Get from `executable`
}

//ESEventExec for Exec events
type ESEventExec struct {
	TargetPpid      int
	TargetGroupID   int
	TargetSigningID string
	TargetTeamID    string
	TargetCDHash    string
}

//ESEventExit for Exit events
type ESEventExit struct {
	Stat int
}

//ESEventFork for Fork events
type ESEventFork struct {
	ChildPpid      int
	ChildGroupID   int
	ChildSigningID string
	ChildTeamID    string
	ChildCDHash    string
}

//ESEventOpen for Open events
type ESEventOpen struct {
	FilePath string
}

//ESEventCreate for Create events
type ESEventCreate struct {
	FileDirectory string // TODO: Figure this out when directory type is 0
	FilePath      string
}

//Transformer : This will eventually have a dispatcher and some rules
type Transformer struct {
}

//Transform : Transform it!
func (t Transformer) Transform(message ESMessage) {
	data, _ := json.Marshal(message)
	fmt.Println(string(data))
}
