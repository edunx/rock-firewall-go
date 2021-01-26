package firewall

import (
	lua "github.com/edunx/lua"
	pub "github.com/edunx/rock-public-go"
	netS "github.com/shirou/gopsutil/net"
	"github.com/spf13/cast"
	"net"
	"strings"
)

// 校验operation, chain, protocol, jump 等值,这些参数的值只能从固定一组中选择
// 如 operation 只能是 append, insert, delete, flush, list之一
// caps: 值是否需要大写,如DROP
func checkSelectValue(L *lua.LState, tb *lua.LTable, key string, caps int, args ...string) string {
	value := tb.RawGetString(key).String()
	value = strings.ToLower(value)
	if caps == 1 {
		value = strings.ToUpper(value)
	}

	for _, arg := range args {
		if value == arg {
			return value
		}
	}

	pub.Out.Err("invalid value: %v, allowed [%v]", value, args)
	L.RaiseError("invalid value: %v, allowed [%v]", value, args)
	return ""
}

func checkIP(L *lua.LState, tb *lua.LTable, key string) string {
	ip := tb.RawGetString(key).String()

	if ip == "nil" {
		return ""
	}

	ip = strings.Replace(ip, "\t", "", -1)
	ip = strings.Replace(ip, " ", "", -1)
	ips := strings.Split(ip, ",")

	for _, v := range ips {
		_, _, err := net.ParseCIDR(v)
		if err != nil && net.ParseIP(v) == nil {
			pub.Out.Err("invalid ip: %v", v)
			L.RaiseError("invalid ip: %v", v)
			return ""
		}
	}

	return ip
}

// port 允许多个
func checkPort(L *lua.LState, tb *lua.LTable, key string) string {
	port := tb.RawGetString(key).String()

	if port == "nil" {
		return ""
	}

	port = strings.Replace(port, "\t", "", -1)
	port = strings.Replace(port, " ", "", -1)
	ports := strings.Split(port, ",")

	for _, v := range ports {
		if cast.ToInt(v) < 0 || cast.ToInt(v) > 65535 {
			pub.Out.Err("invalid port: %v", v)
			L.RaiseError("invalid port: %v", v)
			return ""
		}
	}

	return port
}

// 如果设置的网卡名字非本地网卡,则报错,防止命令注入
// 实际上,golang的命令执行方式似乎有防止命令执行
func checkInterface(L *lua.LState, tb *lua.LTable) string {
	name := tb.RawGetString("interface").String()

	if name == "nil" {
		return ""
	}

	name = strings.Replace(name, "\t", "", -1)
	name = strings.Replace(name, " ", "", -1)
	names := strings.Split(name, ",")

	stats, err := netS.IOCounters(true)
	if err != nil {
		pub.Out.Err("get network counters error: %v, network interface check failed in firewall", err)
		L.RaiseError("firewall config interface check failed")
		return ""
	}

	netIfc := make(map[string]int)
	for id, stat := range stats {
		netIfc[stat.Name] = id
	}

	for _, v := range names {
		if _, ok := netIfc[v]; !ok {
			pub.Out.Err("invalid network interface: %v", v)
			L.RaiseError("invalid network interface: %v", v)
			return ""
		}
	}

	return name
}
