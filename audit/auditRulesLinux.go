//+build linux

package audit

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mozilla/libaudit-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Rules struct {
	RawRules []interface{} `json:"audit_rules"`
}

func fileRule(ruleName string, config *viper.Viper) libaudit.AuditFileRule {
	fr := &libaudit.AuditFileRule{
		Path:            config.GetString(fmt.Sprintf("rules.file_system.%s.path", ruleName)),
		Key:             ruleName,
		Permission:      "rwa",
		StrictPathCheck: false,
	}
	return *fr
}

func processRule(ruleName string, config *viper.Viper) libaudit.AuditSyscallRule {
	type Field struct {
		Name  string      `json:"name"`
		Value interface{} `json:"value"`
		Op    string      `json:"op"`
	}
	processName := config.GetString(fmt.Sprintf("rules.process.%s.name", ruleName))
	processModes := config.GetStringSlice(fmt.Sprintf("rules.process.%s.modes", ruleName))
	var syscalls []string
	actions := []string{"always", "exit"}
	for _, mode := range processModes {
		switch mode {
		case "FORK":
			syscalls = append(syscalls, []string{"fork", "vfork"}...)
		case "EXEC":
			syscalls = append(syscalls, []string{"execve", "execveat"}...)
		case "EXIT":
			syscalls = append(syscalls, []string{"execve", "execveat"}...)
		default:
			log.Errorf("Invalid mode for process: %v", mode)
		}
	}
	pr := libaudit.AuditSyscallRule{
		Key: ruleName,
		Fields: make([]struct {
			Name  string      `json:"name"`
			Value interface{} `json:"value"`
			Op    string      `json:"op"`
		}, 0),
		Syscalls: syscalls,
		Actions:  actions,
	}
	pr.Fields = append(pr.Fields, Field{
		Name:  "path",
		Value: processName,
		Op:    "eq",
	})
	return pr
}

func (au *Auditor) GetRules() []byte {
	rs := Rules{RawRules: make([]interface{}, 0)}
	fileRules := au.Config.GetStringMap("rules.file_system")
	for ruleName := range fileRules {
		rs.RawRules = append(rs.RawRules, fileRule(ruleName, au.Config))
	}
	processRules := au.Config.GetStringMap("rules.process")
	for ruleName := range processRules {
		rs.RawRules = append(rs.RawRules, processRule(ruleName, au.Config))
	}
	buf, err := json.Marshal(rs)
	if err != nil {
		log.Error("Failed to marshal rules to JSON")
		os.Exit(1)
	}
	return buf
}
