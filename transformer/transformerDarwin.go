//+build darwin

package transformer

import (
	"fmt"
	"reflect"

	"github.com/livingstonetech/providence/dispatcher"
)

//Transformer : This will eventually have a dispatcher and some rules
type Transformer struct {
	ProcessRules    map[string]interface{}
	FileSystemRules map[string]interface{}
	DispatchConfig  map[string]interface{}
	dispatchers     []*dispatcher.Dispatcher
}

//CreateTransformer initializes transformer
func CreateTransformer(processRules map[string]interface{},
	fileSystemRules map[string]interface{},
	dispatchConfig map[string]interface{}) Transformer {
	t := Transformer{
		ProcessRules:    processRules,
		FileSystemRules: fileSystemRules,
		DispatchConfig:  dispatchConfig,
		dispatchers:     make([]*dispatcher.Dispatcher, 0),
	}

	for _, v := range dispatchConfig {
		d := dispatcher.CreateDispatcher(v.(map[string]interface{}))
		t.dispatchers = append(t.dispatchers, d)
	}

	return t
}

//Listen causes transformer to listen for events to transform
func (t Transformer) Listen(inChan chan ESMessage) {
	for {
		msg := <-inChan
		go t.Transform(msg)
	}
}

//Transform : Transform it!
func (t Transformer) Transform(message ESMessage) {
	// Transformation code
	matched := false
	if message.EventCategory == "file" {
		for _, rule := range t.FileSystemRules {
			currentRule := rule.(map[string]interface{})
			switch message.EventType {
			case "ES_EVENT_TYPE_NOTIFY_OPEN":
				messageData := message.EventData.(ESEventOpen)
				if messageData.FilePath == currentRule["path"] {
					matched = true
				}
				break

			case "ES_EVENT_TYPE_NOTIFY_CLOSE":
				messageData := message.EventData.(ESEventClose)
				if messageData.FilePath == currentRule["path"] {
					matched = true
				}
				break

			case "ES_EVENT_TYPE_NOTIFY_CREATE":
				messageData := message.EventData.(ESEventCreate)
				if messageData.FilePath == currentRule["path"] {
					matched = true
				}
				break

			case "ES_EVENT_TYPE_NOTIFY_RENAME":
				messageData := message.EventData.(ESEventRename)
				if messageData.DestinationPath == currentRule["path"] || messageData.SourcePath == currentRule["path"] {
					matched = true
				}
				break

			case "ES_EVENT_TYPE_NOTIFY_LINK":
				messageData := message.EventData.(ESEventLink)
				if messageData.SourcePath == currentRule["path"] || messageData.TargetPath == currentRule["path"] {
					matched = true
				}
				break

			case "ES_EVENT_TYPE_NOTIFY_UNLINK":
				messageData := message.EventData.(ESEventUnlink)
				if messageData.TargetPath == currentRule["path"] {
					matched = true
				}
				break

			case "ES_EVENT_TYPE_NOTIFY_SETMODE":
				messageData := message.EventData.(ESEventSetMode)
				if messageData.TargetPath == currentRule["path"] {
					matched = true
				}
				break

			case "ES_EVENT_TYPE_NOTIFY_SETOWNER":
				messageData := message.EventData.(ESEventSetOwner)
				if messageData.TargetPath == currentRule["path"] {
					matched = true
				}
				break

			case "ES_EVENT_TYPE_NOTIFY_WRITE":
				messageData := message.EventData.(ESEventWrite)
				if messageData.FilePath == currentRule["path"] {
					matched = true
				}
				break
			}

			if matched == true {
				// We found our match <3
				break
			}
		}
	} else if message.EventCategory == "process" {
		for _, rule := range t.ProcessRules {
			currentRule := rule.(map[string]interface{})
			if message.Process.ExecutablePath == currentRule["name"] {
				matched = true
			}
		}
	}

	// we do not dispatch
	if matched == false {
		return
	}

	dispatchersLength := len(t.dispatchers)
	var chans = []chan error{}
	for i := 0; i < dispatchersLength; i++ {
		ch := make(chan error)
		chans = append(chans, ch)
		go t.dispatchers[i].Dispatch(message, ch)
	}

	cases := make([]reflect.SelectCase, len(chans))
	for i, ch := range chans {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
	}

	remaining := len(cases)
	for remaining > 0 {
		chosen, value, ok := reflect.Select(cases)
		if !ok {
			// The chosen channel has been closed, so zero out the channel to disable the case
			cases[chosen].Chan = reflect.ValueOf(nil)
			remaining--
			continue
		}

		fmt.Printf("Channel: %s", value.String())
	}
}
