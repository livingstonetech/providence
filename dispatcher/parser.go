package dispatcher

import (
	"encoding/json"
	"encoding/xml"
)

// ParseJSON called by dispatcher to parse given struct to json and return error, if any
func ParseJSON(logs interface{}) ([]byte, error) {
	parsedData, err := json.Marshal(logs)
	if err != nil {
		return []byte{}, err
	}
	return parsedData, nil
}

// ParseXML called by dispatcher to parse given struct to XML and return error, if any
func ParseXML(logs interface{}) ([]byte, error) {
	parsedData, err := xml.Marshal(logs)
	if err != nil {
		return []byte{}, err
	}
	return parsedData, nil
}
