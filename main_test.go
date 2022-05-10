package cryptsetup

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
)

const DevicePath string = "testDevice"
const DeviceName string = "testDeviceName"
const PassKey string = "testPassKey"

type TestWrapper struct {
	test *testing.T
}

func (testWrapper TestWrapper) AssertError(err error) {
	if err == nil {
		testWrapper.test.Error("Operation should have failed, but didn't.")
	}
}

func (testWrapper TestWrapper) AssertNoError(err error) {
	if err != nil {
		testWrapper.test.Error(err)
	}
}

func (testWrapper TestWrapper) AssertErrorCodeEquals(err error, expectedErrorCode int) {
	actualErrorCode := err.(*Error).Code()

	if actualErrorCode != expectedErrorCode {
		testWrapper.test.Errorf("Error code should be '%d', but '%d' was returned instead.", expectedErrorCode, actualErrorCode)
	}
}

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

func generateKey(length int, test *testing.T) string {
	bytes := make([]byte, length)

	_, err := rand.Read(bytes)
	if err != nil {
		test.Error("Error while generating key.")
	}

	return string(bytes[:])
}

func setup(devicePath string) {
	exec.Command("/bin/dd", "if=/dev/zero", fmt.Sprintf("of=%s", devicePath), "bs=64M", "count=1").Run()
}

func teardown(devicePath string) {
	exec.Command("/bin/rm", "-f", devicePath).Run()
}

func resize(devicePath string) {
	exec.Command("/bin/dd", "if=/dev/zero", fmt.Sprintf("of=%s", devicePath), "bs=32M", "count=1", "oflag=append", "conv=notrunc").Run()
}

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Println("This test suite requires root privileges, as libcrypsetup uses the kernel's device mapper.")
		os.Exit(1)
	}

	setup(DevicePath)
	result := m.Run()
	teardown(DevicePath)
	os.Exit(result)
}
