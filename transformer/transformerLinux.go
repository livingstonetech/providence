//+build linux

package transformer

import (
	"fmt"
	"github.com/livingstonetech/providence/dispatcher"
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
	for k, _ := range config.GetStringMap("dispatch") {
		d := dispatcher.CreateDispatcher(config.GetStringMap(fmt.Sprintf("dispatch.%v", k)))
		dispatchers = append(dispatchers, d)
	}
	t.Dispatchers = dispatchers
	return &t
}

func (t Transformer) filter(event interface{}) bool {
	return true
}

func (t Transformer) Transform(event interface{}) {
	errChan := make(chan error)
	for _, d := range t.Dispatchers {
		go d.Dispatch(event, errChan)
	}
}
