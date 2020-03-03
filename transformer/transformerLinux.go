//+build linux

package transformer

import (
	"github.com/livingstonetech/providence/dispatcher"
	"github.com/spf13/viper"
)

type Transformer struct {
	Config		*viper.Viper
	Dispatcher	*dispatcher.Dispatcher
}

func CreateTransformer(config *viper.Viper) *Transformer {
	return &Transformer{Config: config, Dispatcher: dispatcher.CreateDispatcher(config)}
}

func (t Transformer) filter() {

}

func (t Transformer) Transform() {
	
}
