// +build linux

package audit

import (
	"encoding/json"
	"fmt"
	"github.com/icza/dyno"
	"github.com/mozilla/libaudit-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"os/exec"
)

//Auditor : Entrypoint to auditing
type Auditor struct {
	Config			*viper.Viper
	//TransformerModule transformer.Transformer
	NetlinkSocket	*libaudit.NetlinkConnection
}

func CreateAudit(config *viper.Viper) *Auditor {
	log.Info("Create audit called")
	a := Auditor{Config:config}
	s, err := libaudit.NewNetlinkConnection()
	if err != nil {
		log.Error("Netlink connection could not be created %v", err)
		log.Exit(1)
	}
	a.NetlinkSocket = s

	err = libaudit.AuditSetEnabled(a.NetlinkSocket, true)
	if err != nil {
		log.Error("AuditSetEnabled: %v", err)
		log.Exit(1)
	}

	err = libaudit.AuditSetPID(a.NetlinkSocket, os.Getpid())
	if err != nil {
		log.Error("AuditSetPid: %v", err)
		log.Exit(1)
	}

	err = libaudit.AuditSetRateLimit(a.NetlinkSocket, 1000)
	if err != nil {
		log.Error("AuditSetRateLimit: %v", err)
		log.Exit(1)
	}

	err = libaudit.AuditSetBacklogLimit(a.NetlinkSocket, 250)
	if err != nil {
		log.Error("AuditSetBacklogLimit: %v", err)
		log.Exit(1)
	}
	return &a
}

func auditProc(e *libaudit.AuditEvent, err error) {
	if err != nil {
		// See if the error is libaudit.ErrorAuditParse, if so convert and also display
		// the audit record we could not parse
		if nerr, ok := err.(libaudit.ErrorAuditParse); ok {
			log.Error("parser error: %v: %v", nerr, nerr.Raw)
		} else {
			log.Error("callback received error: %v", err)
		}
		return
	}
	// Marshal the event to JSON and print
	buf, err := json.Marshal(e)
	if err != nil {
		fmt.Printf("callback was unable to marshal event: %v", err)
		return
	}
	fmt.Printf("%v\n", string(buf))
}

//StartAudit : Starts Audit
func (au Auditor) StartAudit() {
	doneCh := make(chan bool, 1)
	libaudit.GetAuditMessages(au.NetlinkSocket, auditProc, &doneCh)
}

func setRules(s *libaudit.NetlinkConnection, rules []interface{}) {
	auditJson := make(map[string]interface{})
	var auditRules []map[string]interface{}
	for _, rule := range rules {
		_ = dyno.Set(rule, "rwa", "permission")
		_ = dyno.Set(rule, false, "strict_path_check")
		r2 := dyno.ConvertMapI2MapS(rule).(map[string]interface{})
		auditRules = append(auditRules, r2)
	}
	auditJson["audit_rules"] = auditRules
	var ar libaudit.AuditRules
	buf, err := json.Marshal(auditJson)
	fmt.Printf("%v\n", string(buf))
	if err != nil {
		log.Error("Failed to marshal rules to JSON")
		os.Exit(1)
	}
	//// Make sure we can unmarshal the rules JSON to validate it is the correct format
	if  err := json.Unmarshal(buf, &ar); err != nil {
		log.Errorf("Unmarshaling rules JSON failed: %v", err)
		log.Exit(1)
	}
	warnings, err := libaudit.SetRules(s, buf)
	if err != nil {
		log.Errorf("SetRules: %v", err)
		log.Exit(1)
	}
	log.Info("rules set successfully")
	// Print any warnings we got back but still continue
	for _, x := range warnings {
		log.Warnf("ruleset warning: %v", x)
	}
}

//ConfigureAudit : Configures auditing
func (au Auditor) ConfigureAudit() {
	// Remove current rule set and send rules to the kernel
	cmd := exec.Command("auditctl", "-D")
	if err := cmd.Run(); err != nil {
		log.Fatalf("Could not delete rules %v", err)
		log.Exit(1)
	}
	setRules(au.NetlinkSocket, au.Config.Get("rules").([]interface {}))
}

//StopAudit : Stops audit?
func (au Auditor) StopAudit() {
	log.Info("Stopped Auditing")
}
