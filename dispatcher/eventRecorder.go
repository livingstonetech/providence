package dispatcher

import (
	"fmt"
	"os"
	"strings"
)

// SaveEvent called by dispatcher to write event to a file
func SaveEvent(parsedData []byte, parser string) error {
	parsedDataString := string(parsedData) + "\n"
	filePath := "/var/log/providence/"
	fileName := fmt.Sprintf("%vLogs.txt", strings.ToUpper(parser))

	file, err := os.OpenFile(filePath+fileName, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if os.IsNotExist(err) {
		if _, err = os.Stat(filePath); os.IsNotExist(err) {
			err = os.MkdirAll(filePath, 0755)
			if err != nil {
				return err
			}
		}
		file, err = os.Create(filePath + fileName)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(parsedDataString)
	if err != nil {
		return err
	}
	return nil
}
