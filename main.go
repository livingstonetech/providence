package main

import (
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/livingstonetech/providence/audit"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	l := &lumberjack.Logger{
		Filename:   "/var/log/providence/providence.log",
		MaxSize:    50,
		MaxAge:     30,
		MaxBackups: 5,
		LocalTime:  false,
		Compress:   true,
	}
	mw := io.MultiWriter(os.Stdout, l)
	log.SetOutput(mw)
	log.SetFormatter(&log.JSONFormatter{})
	log.SetReportCaller(true)
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, syscall.SIGHUP)
	go func() {
		for {
			<-channel
			_ = l.Rotate()
		}
	}()
}

func loadConfig(configFile string) *viper.Viper {
	config := viper.New()
	config.SetConfigFile(configFile)
	if err := config.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
		log.Exit(1)
	}
	return config
}

func main() {
	if os.Getuid() != 0 {
		log.Fatal("Providence requires root")
		os.Exit(1)
	}
	configFile := flag.String("config", "", "Config file location")
	flag.Parse()
	if *configFile == "" {
		log.Error("A config file MUST be provided")
		flag.Usage()
		os.Exit(1)
	}
	c := loadConfig(*configFile)
	a := audit.CreateAudit(c)
	a.ConfigureAudit()
	a.StartAudit()
}
