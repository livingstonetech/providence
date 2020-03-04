//+build darwin

package transformer

import (
	"fmt"
	"reflect"

	"github.com/livingstonetech/providence/dispatcher"
)

// (transformer*)(*es_message_t)

//Bridge bridges between the golang callback and transformer
func Bridge(message interface{}) {
	fmt.Printf("%+v\n", message)
}

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
	if message.EventCategory == "file" {
		fmt.Println("File Event")
	} else if message.EventCategory == "process" {
		fmt.Println("Process Event")
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

		fmt.Printf("Read from channel %#v and received %s\n", chans[chosen], value.String())
	}
	fmt.Println("All channels closed")
}
