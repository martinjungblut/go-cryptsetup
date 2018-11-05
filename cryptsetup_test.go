package cryptsetup

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

const PassKey string = "testPassKey"
const DevicePath string = "testDevice"

func setup() {
	exec.Command("/bin/dd", "if=/dev/zero", fmt.Sprintf("of=%s", DevicePath), "bs=4M", "count=1").Run()
}

func teardown() {
	exec.Command("/bin/rm", "-f", DevicePath).Run()
}

func TestMain(m *testing.M) {
	setup()
	result := m.Run()
	teardown()
	os.Exit(result)
}

func TestInitWorksIfDeviceIsFound(t *testing.T) {
	_, err := Init(DevicePath)

	if err != nil {
		t.Error(err)
	}
}

func TestInitFailsIfDeviceIsNotFound(t *testing.T) {
	_, err := Init("nonExistingDevicePath")

	if err == nil {
		t.Error("Init() did not raise an error, when it should have.")
	}
}

func TestFormatLUKS(t *testing.T) {
	device, err := Init(DevicePath)
	if err != nil {
		t.Error(err)
	}

	params := LUKSParams{Hash: "sha1", DataAlignment: 0, DataDevice: ""}

	err = device.FormatLUKS("aes", "xts-plain64", "", "", 256/8, params)
	if err != nil {
		t.Error(err)
	}
}
