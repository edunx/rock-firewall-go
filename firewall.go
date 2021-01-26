package firewall

import (
	"bytes"
	"errors"
	"fmt"
	pub "github.com/edunx/rock-public-go"
	"os/exec"
	"strings"
)

type Iptables struct {
	Operation string // 操作,取值 append, insert, delete, list, flush
	Chain     string // INPUT, OUTPUT
	Interface string // 网络接口, eth0
	Protocol  string // tcp, udp
	Src       string // 来源地址
	Sport     string // 来源端口
	Dest      string // 目标地址
	Dport     string // 目的端口
	Jump      string // ACCEPT, DROP
}

type Firewalld struct {
	Operation string // list, add, delete,
	Zone      string
	Port      string
	Protocol  string
	Permanent string
}

type Config struct {
	iptables  Iptables
	firewalld Firewalld
}

type Firewall struct {
	C Config

	Res []byte
}

// 执行命令
func (f *Firewall) Execute(path string, args ...string) ([]byte, error) {

	cmd := exec.Command(path, args...)
	pub.Out.Debug("firewall [%s] config cmd: %s", path, cmd.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("This doesn't exist in IPTables :(")) {
			return out, nil
		}
		return nil, err
	}

	cmd = exec.Command("firewall-cmd", "--reload")
	if path == "iptables" {
		cmd = exec.Command("service", "iptables", "save")
	}
	err = cmd.Run()
	if err != nil {
		pub.Out.Err("firewall [%s] config save/reload error: %v", path, err)
	}

	pub.Out.Info("firewall [%s] config change success", path)
	return out, nil
}

// 处理防火墙配置的主函数
func (f *Firewall) Process(path string) error {
	var out []byte
	var err error
	var args []string

	switch path {
	case "iptables":
		args = f.C.iptables.ParseArgs()
	case "firewall-cmd":
		args = f.C.firewalld.ParseArgs()
	}

	if args == nil {
		return errors.New("firewall cmd args is nil")
	}

	if out, err = f.Execute(path, args...); err != nil {
		pub.Out.Err("config %s rule error: %v", path, err)
		return err
	}

	pub.Out.Debug("%s config result: %s", path, out)

	f.Res = out
	return nil
}

// 分析iptables 配置参数,校验合法性,拼接参数;
func (i *Iptables) ParseArgs() []string {
	var args []string

	// 必要参数
	switch i.Operation {
	case "flush":
		args = append(args, "-F")
		return args
	case "list":
		args = append(args, "-L")
		return args
	case "append":
		args = append(args, "-A")
	case "insert":
		args = append(args, "-I")
	case "delete":
		args = append(args, "-D")
	default:
		pub.Out.Err("invalid operation specified: %v", i.Operation)
		return nil
	}

	args = append(args, i.Chain)

	if i.Protocol == "" {
		pub.Out.Err("protocol must be specified, current value is nil")
		return nil
	}
	args = append(args, "-p", i.Protocol)

	// 非必要参数
	if i.Interface != "" {
		args = append(args, "-i", i.Interface)
	}

	if i.Src != "" {
		args = append(args, "-s", i.Src)
	}

	if i.Dest != "" {
		args = append(args, "-d", i.Dest)
	}

	// 多端口或单一端口
	var srcPorts []string
	var destPorts []string
	if i.Sport != "" {
		srcPorts = strings.Split(i.Sport, ",")
		if len(srcPorts) > 1 {
			args = append(args, "-m multiport --sports")
		} else {
			args = append(args, "--sport")
		}
		args = append(args, i.Sport)
	}

	if i.Dport != "" {
		destPorts = strings.Split(i.Dport, ",")
		if len(destPorts) > 1 {
			args = append(args, "-m multiport --dports")
		} else {
			args = append(args, "--dport")
		}
		args = append(args, i.Dport)
	}

	//iptables 当一条规则中存在多个源(目的)端口时,不允许指定目的(源)端口
	if len(srcPorts) > 1 && len(srcPorts) > 0 || len(srcPorts) > 0 && len(destPorts) > 1 {
		pub.Out.Err("ports config error: when the number of src(dest) port > 1, dest(src) port's  must =0")
		return nil
	}

	if i.Jump != "" {
		args = append(args, "-j", i.Jump)
	}

	return args
}

// 分析firewalld参数
func (fd *Firewalld) ParseArgs() []string {
	var args []string

	arg := fmt.Sprintf("--zone=%s", fd.Zone)
	args = append(args, arg)

	switch fd.Operation {
	case "list":
		args = append(args, "--list-ports")
		return args
	case "add":
		arg := fmt.Sprintf("--add-port=%s/%s", fd.Port, fd.Protocol)
		args = append(args, arg)
	case "delete":
		arg := fmt.Sprintf("--remove-port=%s/%s", fd.Port, fd.Protocol)
		args = append(args, arg)
	default:
		pub.Out.Err("invalid operation: %v specified", fd.Operation)
		return nil
	}

	if fd.Permanent == "true" {
		args = append(args, "--permanent")
	}

	return args
}
