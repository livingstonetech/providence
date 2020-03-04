//+build darwin

package transformer

import (
	"fmt"
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
	DispatchConfig  []interface{}
}

//CreateTransformer initializes transformer
func CreateTransformer(processRules map[string]interface{},
	fileSystemRules map[string]interface{},
	dispatchConfig []interface{}) *Transformer {
	t := Transformer{
		ProcessRules:    processRules,
		FileSystemRules: fileSystemRules,
		DispatchConfig:  dispatchConfig,
	}

	return &t
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

	if message.EventCategory == "file" {
		fmt.Println("File Event")
	} else if message.EventCategory == "process" {
		fmt.Println("Process Event")
	}
}
