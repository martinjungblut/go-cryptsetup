package test

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
)

const DevicePath string = "testDevice"
const PassKey string = "testPassKey"

func getFileMD5(filePath string, test *testing.T) string {
	fileHandle, error := os.Open(filePath)
	if error != nil {
		test.Error(error)
	}
	defer fileHandle.Close()

	hash := md5.New()
	_, error = io.Copy(hash, fileHandle)
	if error != nil {
		test.Error(error)
	}

	return hex.EncodeToString(hash.Sum(nil)[:16])
}

func setup() {
	exec.Command("/bin/dd", "if=/dev/zero", fmt.Sprintf("of=%s", DevicePath), "bs=8M", "count=1").Run()
}

func teardown() {
	exec.Command("/bin/rm", "-f", DevicePath).Run()
}

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Printf("This test suite requires root privileges, as libcrypsetup uses the kernel's device mapper.\n")
		os.Exit(1)
	}

	setup()
	result := m.Run()
	teardown()
	os.Exit(result)
}
