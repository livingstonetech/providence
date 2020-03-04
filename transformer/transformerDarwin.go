//+build darwin

package transformer

import (
	"encoding/json"
	"fmt"
)

// (transformer*)(*es_message_t)

//Bridge bridges between the golang callback and transformer
func Bridge(message interface{}) {
	fmt.Printf("%+v\n", message)
}

//Transformer : This will eventually have a dispatcher and some rules
type Transformer struct {
}

//CreateTransformer initializes transformer
func (t Transformer) CreateTransformer() {

}

//Listen causes transformer to listen for events to transform
func (t Transformer) Listen(inChan chan ESMessage) {
	for {
		msg, open := <-inChan
		if open != true {
			return
		}
		go t.Transform(msg)
	}
}

//Transform : Transform it!
func (t Transformer) Transform(message ESMessage) {
	data, _ := json.Marshal(message)
	fmt.Println(string(data))
}
