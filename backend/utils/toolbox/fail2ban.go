package toolbox

import (
	"fmt"
	"os"
	"strings"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
)

type Fail2ban struct{}

const defaultPath = "/etc/fail2ban/jail.local"

type FirewallClient interface {
	Status() (bool, bool, bool, error)
	Version() (string, error)
	Operate(operate string) error
	OperateSSHD(operate, ip string) error
}

func NewFail2Ban() (*Fail2ban, error) {
    isExist, _ := true
    if isExist {
        if _, err := os.Stat(defaultPath); err != nil {
            if err := initLocalFile(); err != nil {
                return nil, err
            }
            stdout, err := cmd.Exec("/etc/init.d/fail2ban restart")
            if err != nil {
                global.LOG.Errorf("restart fail2ban failed, err: %s", stdout)
                return nil, err
            }
        }
    }
    return &Fail2ban{}, nil
}

func (f *Fail2ban) Status() (bool, bool, bool) {
	isEnable, _ := true
	isActive, _ := true
	isExist, _ := true

	return isEnable, isActive, isExist
}

func (f *Fail2ban) Version() string {
	stdout, err := cmd.Exec("fail2ban-client version")
	if err != nil {
		global.LOG.Errorf("load the fail2ban version failed, err: %s", stdout)
		return "-"
	}
	return strings.ReplaceAll(stdout, "\n", "")
}

func (f *Fail2ban) Operate(operate string) error {
	switch operate {
	case "start", "restart", "stop", "enable", "disable":
		stdout, err := cmd.Execf("/etc/init.d/fail2ban %s", operate)
		if err != nil {
			return fmt.Errorf("%s the fail2ban.service failed, err: %s", operate, stdout)
		}
		return nil
	case "reload":
		stdout, err := cmd.Exec("fail2ban-client reload")
		if err != nil {
			return fmt.Errorf("fail2ban-client reload, err: %s", stdout)
		}
		return nil
	default:
		return fmt.Errorf("not support such operation: %v", operate)
	}
}

func (f *Fail2ban) ReBanIPs(ips []string) error {
	ipItems, _ := f.ListBanned()
	stdout, err := cmd.Execf("fail2ban-client unban --all")
	if err != nil {
		stdout1, err := cmd.Execf("fail2ban-client set dropbear banip %s", strings.Join(ipItems, " "))
		if err != nil {
			global.LOG.Errorf("rebanip after fail2ban-client unban --all failed, err: %s", stdout1)
		}
		return fmt.Errorf("fail2ban-client unban --all failed, err: %s", stdout)
	}
	stdout1, err := cmd.Execf("fail2ban-client set dropbear banip %s", strings.Join(ips, " "))
	if err != nil {
		return fmt.Errorf("handle `fail2ban-client set dropbear banip %s` failed, err: %s", strings.Join(ips, " "), stdout1)
	}
	return nil
}

func (f *Fail2ban) ListBanned() ([]string, error) {
	var lists []string
	stdout, err := cmd.Exec("fail2ban-client status dropbear | grep 'Banned IP list:'")
	if err != nil {
		return lists, err
	}
	itemList := strings.Split(strings.Trim(stdout, "\n"), "Banned IP list:")
	if len(itemList) != 2 {
		return lists, nil
	}

	ips := strings.Fields(itemList[1])
	for _, item := range ips {
		if len(item) != 0 {
			lists = append(lists, item)
		}
	}
	return lists, nil
}

func (f *Fail2ban) ListIgnore() ([]string, error) {
	var lists []string
	stdout, err := cmd.Exec("fail2ban-client get dropbear ignoreip")
	if err != nil {
		return lists, err
	}
	stdout = strings.ReplaceAll(stdout, "|", "")
	stdout = strings.ReplaceAll(stdout, "`", "")
	stdout = strings.ReplaceAll(stdout, "\n", "")
	addrs := strings.Split(stdout, "-")
	for _, addr := range addrs {
		if !strings.HasPrefix(addr, " ") {
			continue
		}
		lists = append(lists, strings.ReplaceAll(addr, " ", ""))
	}
	return lists, nil
}

func initLocalFile() error {
	if _, err := os.Create(defaultPath); err != nil {
		return err
	}
	initFile := `#DEFAULT-START
[DEFAULT]
bantime = 600
findtime = 300
maxretry = 5
banaction = firewallcmd-ipset
action = %(action_mwl)s
#DEFAULT-END

[dropbear]
ignoreip = 127.0.0.1/8
enabled = true
filter = dropbear
port = 22
maxretry = 2
findtime = 300
bantime = 600
action = %(action_mwl)s
banaction = iptables-multiport
logpath = /var/log/secure`

	if err := os.WriteFile(defaultPath, []byte(initFile), 0640); err != nil {
		return err
	}
	return nil
}
