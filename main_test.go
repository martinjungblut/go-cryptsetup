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

const (
	DevicePath string = "testDevice"
	DeviceName string = "testDeviceName"
	PassKey    string = "testPassKey"
)

type TestWrapper struct {
	test *testing.T
}

func (testWrapper TestWrapper) AssertError(err error) {
	testWrapper.test.Helper()
	if err == nil {
		testWrapper.test.Error("Operation should have failed, but didn't.")
	}
}

func (testWrapper TestWrapper) AssertNoError(err error) {
	testWrapper.test.Helper()
	if err != nil {
		testWrapper.test.Error(err)
	}
}

func (testWrapper TestWrapper) AssertErrorCodeEquals(err error, expectedErrorCode int) {
	testWrapper.test.Helper()
	actualErrorCode := err.(*Error).Code()

	if actualErrorCode != expectedErrorCode {
		testWrapper.test.Errorf("Error code should be '%d', but '%d' was returned instead.", expectedErrorCode, actualErrorCode)
	}
}

func getFileMD5(filePath string, test *testing.T) string {
	fileHandle, err := os.Open(filePath)
	if err != nil {
		test.Error(err)
	}
	defer fileHandle.Close()

	hash := md5.New()
	if _, err = io.Copy(hash, fileHandle); err != nil {
		test.Error(err)
	}

	return hex.EncodeToString(hash.Sum(nil)[:16])
}

func generateKey(length int, test *testing.T) string {
	bytes := make([]byte, length)

	if _, err := rand.Read(bytes); err != nil {
		test.Error("Error while generating key.")
	}

	return string(bytes[:])
}

func setup(devicePath string) {
	if err := exec.Command("/bin/dd", "if=/dev/zero", fmt.Sprintf("of=%s", devicePath), "bs=64M", "count=1").Run(); err != nil {
		panic(err)
	}
}

func teardown(devicePath string) {
	if err := exec.Command("/bin/rm", "-f", devicePath).Run(); err != nil {
		panic(err)
	}
}

func resize(devicePath string) {
	if err := exec.Command("/bin/dd", "if=/dev/zero", fmt.Sprintf("of=%s", devicePath), "bs=32M", "count=1", "oflag=append", "conv=notrunc").Run(); err != nil {
		panic(err)
	}
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
