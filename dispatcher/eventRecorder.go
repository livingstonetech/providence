package dispatcher

import (
	"fmt"
	"os"
	"strings"
)

// SaveEvent called by dispatcher to write event to a file
func SaveEvent(parsedData []byte, parser string) error {
	parsedDataString := string(parsedData) + "\n"
	fileName := fmt.Sprintf("/var/log/providence/%vLogs.txt", strings.ToUpper(parser))
	file, fileOpenError := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	defer file.Close()

	if fileOpenError != nil {
		return fileOpenError
	}
	_, fileWriteError := file.WriteString(parsedDataString)
	if fileWriteError != nil {
		return fileWriteError
	}
	return nil
}
