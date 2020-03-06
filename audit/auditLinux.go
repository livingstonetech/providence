// +build linux

package audit

import (
	"github.com/livingstonetech/providence/transformer"
	"github.com/mozilla/libaudit-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"os/exec"
)

//Auditor : Entrypoint to auditing
type Auditor struct {
	Config        *viper.Viper
	Transformer   *transformer.Transformer
	netlinkSocket *libaudit.NetlinkConnection
}

var transChan chan *libaudit.AuditEvent

func CreateAudit(config *viper.Viper) *Auditor {
	log.Info("Create audit called")
	a := Auditor{Config:config}
	a.Transformer = transformer.CreateTransformer(config)
	s, err := libaudit.NewNetlinkConnection()
	if err != nil {
		log.Error("Netlink connection could not be created %v", err)
		log.Exit(1)
	}
	a.netlinkSocket = s

	err = libaudit.AuditSetEnabled(a.netlinkSocket, true)
	if err != nil {
		log.Error("AuditSetEnabled: %v", err)
		log.Exit(1)
	}

	err = libaudit.AuditSetPID(a.netlinkSocket, os.Getpid())
	if err != nil {
		log.Error("AuditSetPid: %v", err)
		log.Exit(1)
	}

	err = libaudit.AuditSetRateLimit(a.netlinkSocket, 1000)
	if err != nil {
		log.Error("AuditSetRateLimit: %v", err)
		log.Exit(1)
	}

	err = libaudit.AuditSetBacklogLimit(a.netlinkSocket, 250)
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
	transChan <- e
}

//StartAudit : Starts Audit
func (au Auditor) StartAudit() {
	go au.Transformer.Listen(transChan)
	doneCh := make(chan bool, 1)
	libaudit.GetAuditMessages(au.netlinkSocket, auditProc, &doneCh)
}


func setRules(s *libaudit.NetlinkConnection, buf []byte) {
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
	rules := au.GetRules()
	setRules(au.netlinkSocket, rules)
	transChan = make(chan *libaudit.AuditEvent)
}

//StopAudit : Stops audit?
func (au Auditor) StopAudit() {
	log.Info("Stopped Auditing")
}
