package dispatcher

import (
	"fmt"
	"log/syslog"
	"net/url"
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func isValidConfig(keys []string, config map[string]interface{}) bool {
	for _, k := range keys {
		if _, ok := config[k]; !ok {
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

func getSyslogPriorityLevel(priority string) syslog.Priority {
	switch priority {
	case "emergency":
		return syslog.LOG_EMERG
	case "alert":
		return syslog.LOG_ALERT
	case "critical":
		return syslog.LOG_CRIT
	case "error":
		return syslog.LOG_ERR
	case "warning":
		return syslog.LOG_WARNING
	case "notice":
		return syslog.LOG_NOTICE
	case "info":
		return syslog.LOG_INFO
	case "debug":
		return syslog.LOG_DEBUG
	default:
		return syslog.LOG_ALERT
	}
}
