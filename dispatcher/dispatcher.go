package dispatcher

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log/syslog"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
)

type errorMessage string

func (m errorMessage) Error() string {
	return fmt.Sprintf(string(m))
}

// Dispatcher used to set required destination and parser
type Dispatcher struct {
	ConfigBlock     map[string]interface{}
	hostName        string
	operatingSystem string
	syslogWriter    *syslog.Writer
}

type Event struct {
	HostName        string
	OperatingSystem string
	Data            interface{}
}

func CreateDispatcher(configBlock map[string]interface{}) *Dispatcher {
	d := Dispatcher{
		ConfigBlock:     configBlock,
		hostName:        getHostName(),
		operatingSystem: getOS(),
	}

	if configBlock["format"] == "syslog" {
		raddr := fmt.Sprintf("%s:%d", configBlock["url"].(string), configBlock["port"].(int))
		priority := getSyslogPriorityLevel(configBlock["priority"].(string))
		writer, err := syslog.Dial("udp", raddr, priority, "providence")
		if err != nil {
			// Need better error handling here. Could segfault if writer is nil.
			log.Errorf("Error initializing syslog")
			return &d
		}
		d.syslogWriter = writer
	}

	return &d
}

func (d *Dispatcher) syslogDispatcher(body []byte) error {
	if d.syslogWriter != nil {
		_, err := d.syslogWriter.Write(body)
		if err != nil {
			log.Errorf("Error writing to syslog")
			return err
		}
	}
	return nil
}

func (d *Dispatcher) fileDispatcher(body []byte) error {
	requiredKeys := []string{"path"}
	if !isValidConfig(requiredKeys, d.ConfigBlock) {
		return errorMessage("Invalid config block")
	}
	f, err := os.OpenFile(d.ConfigBlock["path"].(string), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("Failed to open file: %v", err)
		return err
	}
	if _, err := f.Write(append(body, 10)); err != nil {
		log.Errorf("Failed to write to file: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Errorf("Failed to close file: %v", err)
	}
	return nil
}

func (d *Dispatcher) httpDispatcher(body []byte) error {
	requiredKeys := []string{"url", "format"}
	if !isValidConfig(requiredKeys, d.ConfigBlock) {
		return errorMessage("Invalid config block")
	}
	uri := d.ConfigBlock["url"].(string)
	if !isValidUrl(uri) {
		log.Errorf("url %v is invalid", uri)
		return errorMessage(fmt.Sprintf("url %v is invalid", uri))
	}
	contentType := fmt.Sprintf("application/%v", d.ConfigBlock["format"].(string))
	resp, err := http.Post(fmt.Sprintf("%v", uri), contentType, bytes.NewReader(body))
	if err != nil {
		log.Errorf("HTTP Response Error %v", err)
		return err
	}
	// defer resp.Body.Close()
	if resp.StatusCode < 200 && resp.StatusCode > 299 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("Error while reading body from HTTP Response")
			return err
		}
		log.Errorf("HTTP Response Error. Body: %s", string(body))
	}
	return nil
}

func (d *Dispatcher) Dispatch(event interface{}, errChan chan error) {
	dispatchType := d.ConfigBlock["type"]
	format := d.ConfigBlock["format"]
	e := Event{
		HostName:        d.hostName,
		OperatingSystem: d.operatingSystem,
		Data:            event,
	}
	var body []byte

	switch format {
	case "json":
		bodyBytes, err := json.Marshal(e)
		if err != nil {
			log.Errorf("Error parsing JSON: %v", err)
			errChan <- err
		}
		body = bodyBytes
		break
	case "xml":
		bodyBytes, err := xml.Marshal(e)
		if err != nil {
			log.Errorf("Error parsing JSON: %v", err)
			errChan <- err
		}
		body = bodyBytes
		break
	case "syslog":
		break
	default:
		log.Errorf("Invalid format %v", format)
	}
	switch dispatchType {
	case "http":
		if err := d.httpDispatcher(body); err != nil {
			errChan <- err
		}
		break
	case "file":
		if err := d.fileDispatcher(body); err != nil {
			errChan <- err
		}
		break
	case "stdout":
		fmt.Println(string(body))
		break
	case "syslog":
		if err := d.syslogDispatcher(body); err != nil {
			errChan <- err
		}
		break
	default:
		log.Errorf("Dispatcher type not implemented: %v", dispatchType)
		errChan <- nil
	}
}
