package dispatcher

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

// Dispatcher used to set required destination and parser
type Dispatcher struct {
	Destination string
	Port        string
	Parser      string
}

func checkServer(destination, port string) error {
	_, err := net.Dial("tcp", fmt.Sprintf("%v:%v", destination, port))
	return err
}

func dispatchParsedData(parsedData []byte, parser, destination, port, destinationURL string) error {
	parserType := fmt.Sprintf(strings.ToLower(parser))

	if err := checkServer(destination, port); err != nil {
		return err
	}

	fmt.Println("Connected successfully to server:", destinationURL)
	fmt.Println("Sending parsed", parserType, "to server...")

	response, err := http.Post(destinationURL, fmt.Sprintf("application/%v", parserType), bytes.NewBuffer(parsedData))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	// Below code is to be modified according to expected response from Kibana
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(body))

	return nil
}

// DispatchMessage used to parse and dispatch parsed message to given destination
func (d Dispatcher) DispatchMessage(logs interface{}) {
	fmt.Println("Initiated", d.Parser, "parsing...")
	var parsedData []byte
	var parseError error
	destinationURL := fmt.Sprintf("http://%v:%v", d.Destination, d.Port)

	switch d.Parser {
	case "json":
		parsedData, parseError = ParseJSON(logs)
		if parseError != nil {
			fmt.Println(parseError)
			return
		}
	case "xml":
		parsedData, parseError = ParseXML(logs)
		if parseError != nil {
			fmt.Println(parseError)
			return
		}
	default:
		fmt.Println("Unknown parser", d.Parser)
		return
	}
	dispatchError := dispatchParsedData(parsedData, d.Parser, d.Destination, d.Port, destinationURL)
	if dispatchError != nil {
		fmt.Println(dispatchError)
		return
	}
	fmt.Println("Successfully sent parsed", d.Parser, "to", destinationURL)
	recordEventError := SaveEvent(parsedData, d.Parser)
	if recordEventError != nil {
		fmt.Println(recordEventError)
		return
	}
	fileName := fmt.Sprintf("logs/%vLogs.txt", strings.ToUpper(d.Parser))
	fmt.Println("Successfully recorded logs at", fileName)
}
