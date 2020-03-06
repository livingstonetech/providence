//+build linux

package transformer

import (
	"fmt"
	"github.com/livingstonetech/providence/dispatcher"
	"github.com/mozilla/libaudit-go"
	"reflect"

	"github.com/spf13/viper"
)

type Transformer struct {
	Config		*viper.Viper
	Dispatchers	[]*dispatcher.Dispatcher
}

func CreateTransformer(config *viper.Viper) *Transformer {
	t := Transformer{
		Config:      config,
		Dispatchers: make([]*dispatcher.Dispatcher, 0),
	}
	dispatchers := make([]*dispatcher.Dispatcher, 0)
	for k := range config.GetStringMap("dispatch") {
		d := dispatcher.CreateDispatcher(config.GetStringMap(fmt.Sprintf("dispatch.%v", k)))
		dispatchers = append(dispatchers, d)
	}
	t.Dispatchers = dispatchers
	return &t
}

//Listen causes transformer to listen for events to transform
func (t Transformer) Listen(event chan *libaudit.AuditEvent) {
	for {
		msg := <- event
		go t.Transform(msg)
	}

}

func (t Transformer) Transform(event *libaudit.AuditEvent) {
	dispatchersLength := len(t.Dispatchers)
	var chans []chan error
	for i := 0; i < dispatchersLength; i++ {
		ch := make(chan error)
		chans = append(chans, ch)
		go t.Dispatchers[i].Dispatch(event, ch)
	}

	cases := make([]reflect.SelectCase, len(chans))
	for i, ch := range chans {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
	}

	remaining := len(cases)
	for remaining > 0 {
		chosen, _, ok := reflect.Select(cases)
		if !ok {
			// The chosen channel has been closed, so zero out the channel to disable the case
			cases[chosen].Chan = reflect.ValueOf(nil)
			remaining--
			continue
		}
	}
}
