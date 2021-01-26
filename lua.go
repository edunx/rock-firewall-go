package firewall

import (
	lua "github.com/edunx/lua"
	pub "github.com/edunx/rock-public-go"
)

const (
	FirewalldMt string = "firewalld_mt"
	IptablesMt  string = "iptables_mt"
)

func LuaInjectApi(L *lua.LState, parent *lua.LTable) {
	mtF := L.NewTypeMetatable(FirewalldMt)
	mtI := L.NewTypeMetatable(IptablesMt)

	L.SetField(mtF, "__index", L.NewFunction(get))
	L.SetField(mtF, "__newindex", L.NewFunction(set))

	L.SetField(mtI, "__index", L.NewFunction(get))
	L.SetField(mtI, "__newindex", L.NewFunction(set))

	L.SetField(parent, "iptables", L.NewFunction(createIptablesUserData))
	L.SetField(parent, "firewalld", L.NewFunction(createFirewalldUserData))
}

func get(L *lua.LState) int {
	return 1
}

func set(L *lua.LState) int {
	return 0
}

func createFirewalldUserData(L *lua.LState) int {
	tb := L.CheckTable(1)

	mt := L.GetTypeMetatable(FirewalldMt)
	ud := L.NewUserData()

	firewalld := getFirewalldConfig(L, tb)
	pub.Out.Debug("firewalld config info: %v", firewalld)

	ud.Value = firewalld
	L.SetMetatable(ud, mt)
	L.Push(ud)

	firewall := Firewall{
		C: Config{
			iptables:  Iptables{},
			firewalld: *firewalld,
		},
	}

	if err := firewall.Process("firewall-cmd"); err != nil {
		pub.Out.Err("firewalld config error: %v", err)
	}

	return 1
}

func createIptablesUserData(L *lua.LState) int {
	tb := L.CheckTable(1)

	mt := L.GetTypeMetatable(IptablesMt)
	ud := L.NewUserData()

	iptables := getIptablesConfig(L, tb)
	pub.Out.Debug("iptables config info: %v", iptables)

	ud.Value = iptables
	L.SetMetatable(ud, mt)
	L.Push(ud)

	firewall := Firewall{
		C: Config{
			iptables:  *iptables,
			firewalld: Firewalld{},
		},
	}

	if err := firewall.Process("iptables"); err != nil {
		pub.Out.Err("iptables config error: %v", err)
	}

	return 1
}

func getFirewalldConfig(L *lua.LState, tb *lua.LTable) *Firewalld {

	return &Firewalld{
		Operation: checkSelectValue(L, tb, "operation", 0, "list", "add", "delete"),
		Zone:      tb.RawGetString("zone").String(),
		Port:      checkPort(L, tb, "port"),
		Protocol:  checkSelectValue(L, tb, "protocol", 0, "tcp", "udp"),
		Permanent: tb.RawGetString("permanent").String(),
	}
}

func getIptablesConfig(L *lua.LState, tb *lua.LTable) *Iptables {

	return &Iptables{
		Operation: checkSelectValue(L, tb, "operation", 0, "append", "insert", "delete", "flush", "list"),
		Chain:     checkSelectValue(L, tb, "chain", 1, "INPUT", "OUTPUT"),
		Interface: checkInterface(L, tb),
		Protocol:  checkSelectValue(L, tb, "protocol", 0, "tcp", "udp"),
		Src:       checkIP(L, tb, "src"),
		Sport:     checkPort(L, tb, "sport"),
		Dest:      checkIP(L, tb, "dest"),
		Dport:     checkPort(L, tb, "dport"),
		Jump:      checkSelectValue(L, tb, "jump", 1, "ACCEPT", "DROP"),
	}
}
