//+build darwin

package transformer

//ESMessage : Part of the Message type from Apple's Security framework
type ESMessage struct {
	MachTime      uint64
	Process       ESProcess
	EventType     string
	EventCategory string
	EventData     interface{} // Interface for dynamic data. This depends on EventType.
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

//ESEventSignal for Signal events
type ESEventSignal struct {
	Signal          int // TODO: Need to map to actual signals
	TargetPpid      int
	TargetGroupID   int
	TargetSigningID string
	TargetTeamID    string
	TargetCDHash    string
}

//ESEventKextLoad for KEXT Load events
type ESEventKextLoad struct {
	Identifier string
}

//ESEventKextUnload for KEXT Load events
type ESEventKextUnload struct {
	Identifier string
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

//ESEventClose for Close events
type ESEventClose struct {
	Modified bool
	FilePath string
}

//ESEventRename for Rename events
type ESEventRename struct {
	SourcePath      string
	DestinationPath string // TODO: Figure the union out
}

//ESEventLink for Link events
type ESEventLink struct {
	SourcePath string
	TargetDir  string
	TargetPath string
}

//ESEventUnlink for Unlink events
type ESEventUnlink struct {
	TargetPath            string
	TargetParentDirectory string
}

//ESEventSetMode for Setmode events
type ESEventSetMode struct {
	NewMode    uint16
	TargetPath string
}

//ESEventSetOwner for Setowner events
type ESEventSetOwner struct {
	UID        uint32
	GID        uint32
	TargetPath string
}

//ESEventWrite for Write events
type ESEventWrite struct {
	FilePath string
}
