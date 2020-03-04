package dispatcher

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/icza/dyno"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	"os"
)

// Dispatcher used to set required destination and parser
type Dispatcher struct {
	Config		*viper.Viper
}

func CreateDispatcher(config *viper.Viper) *Dispatcher {
	return &Dispatcher{Config: config}
}

func syslogDispatcher(config map[string]interface{}, body []byte){
	fmt.Printf("Yolo %v %v\n", config, string(body))
}


func fileDispatcher(config map[string]interface{}, body []byte){
	requiredKeys := []string{"path"}
	if !isValidConfig(requiredKeys, config) {
		return
	}
	f, err := os.OpenFile(config["path"].(string), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("Failed to open file: %v", err)
		return
	}
	if _, err := f.Write(append(body, 10)); err != nil {
		log.Errorf("Failed to write to file: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Errorf("Failed to close file: %v", err)
	}
}

func httpDispatcher(config map[string]interface{}, body []byte){
	requiredKeys := []string{"url", "port", "format"}
	if !isValidConfig(requiredKeys, config) {
		return
	}
	uri := config["url"].(string)
	port := config["port"].(int)
	if !isValidUrl(uri) {
		log.Errorf("url %v is invalid")
		return
	}
	contentType := fmt.Sprintf("application/%v", config["format"].(string))
	resp, err := http.Post(fmt.Sprintf("%v:%v", uri, port), contentType, bytes.NewReader(body))
	if err != nil{
		log.Errorf("HTTP Response Error %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Errorf("HTTP Response Error. Body: %v", ioutil.ReadAll(resp.Body))
	}
}

func dispatch(destination map[string]interface{}, event interface{}) {
	format := destination["format"].(string)
	dispatchType := destination["type"].(string)
	var body []byte

	switch format {
	case "json":
		bodyBytes, err := json.Marshal(event)
		if err != nil {
			log.Errorf("Error parsing JSON: %v", err)
		}
		body = bodyBytes
	case "xml":
		bodyBytes, err := xml.Marshal(event)
		if err != nil {
			log.Errorf("Error parsing JSON: %v", err)
		}
		body = bodyBytes
	default:
		log.Errorf("Invalid format %v", format)
	}
	switch dispatchType {
	case "http":
		httpDispatcher(destination, body)
	case "file":
		fileDispatcher(destination, body)
	case "stdout":
		fmt.Println(string(body))
	case "syslog":
		syslogDispatcher(destination, body)
	default:
		log.Errorf("Dispatcher type not implemented: %v", dispatchType)
	}
}

func (d Dispatcher) Dispatch(event interface{}) {
	destinations := d.Config.Get("dispatch")
	for _, destination := range destinations.([]interface {}) {
		dispatch(dyno.ConvertMapI2MapS(destination).(map[string]interface{}), event)
	}
}