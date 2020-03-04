package dispatcher

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/url"
	"os"
	"runtime"
)

func isValidConfig(keys []string, config map[string]interface{}) bool {
	for _, k := range keys {
		if _, ok  := config[k]; !ok {
			log.Errorf("Key %v does not exist in config but required", k)
			return false
		}
	}
	return true
}

func isValidUrl(u string) bool {
	_, err := url.ParseRequestURI(u)
	if err != nil {
		return false
	}
	val, err := url.Parse(u)
	if err != nil || val.Scheme == "" || val.Host == "" {
		return false
	}
	return true
}

func getHostName() string {
	hostName, err := os.Hostname()
	if err != nil {
		log.Errorf("Could not get hostname: %v", err)
		return ""
	}
	return hostName
}

func getOS() string {
	return fmt.Sprintf("%v-%v", runtime.GOOS, runtime.GOARCH)
}