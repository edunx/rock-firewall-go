package firewall

import (
	"fmt"
	"os/exec"
	"testing"
)

func TestExecute(t *testing.T) {
	f := &Firewall{
		C:   Config{},
		Res: nil,
	}
	path := "/bin/sh"
	args := []string{"-c ls -a && ls -l"}
	res, err := f.Execute(path, args...)
	if err != nil {
		fmt.Println("error occurred: ", err)
		return
	}

	fmt.Println(string(res))
}

func delFile(param string) {
	cmd := exec.Command("/bin/sh", "-c", param)
	fmt.Println(cmd.String())
	err := cmd.Run()
	if err != nil {
		fmt.Println("delete file error.", err)
	}
}

func TestDel(t *testing.T) {
	delFile("ls -a && ls -l")
}
