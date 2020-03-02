package dispatcher

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
)

type parseError string

func (p parseError) Error() string {
	return fmt.Sprintf(string(p))
}

// ParseJSON called by dispatcher to parse given struct to json and return error, if any
func ParseJSON(logs interface{}) ([]byte, error) {
	parsedData, err := json.Marshal(logs)
	if err != nil {
		_, ok := err.(*json.UnsupportedTypeError)
		if ok {
			return []byte{}, parseError("Tried to marshal invalid type")
		}
		return []byte{}, parseError("Couldn't parse into json!")
	}
	return parsedData, nil
}

// ParseXML called by dispatcher to parse given struct to XML and return error, if any
func ParseXML(logs interface{}) ([]byte, error) {
	parsedData, err := xml.Marshal(logs)
	if err != nil {
		_, ok := err.(*xml.UnsupportedTypeError)
		if ok {
			return []byte{}, parseError("Tried to marshal invalid type!")
		}
		return []byte{}, parseError("Couldn't parse into XML!")
	}
	return parsedData, nil
}
