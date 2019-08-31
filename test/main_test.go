package test

import (
	"crypto/md5"
	"crypto/rand"
	"cryptsetup"
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
	actualErrorCode := err.(*cryptsetup.Error).Code()

	if actualErrorCode != expectedErrorCode {
		testWrapper.test.Error(fmt.Sprintf("Error code should be '%d', but '%d' was returned instead.", expectedErrorCode, actualErrorCode))
	}
}

func (testWrapper TestWrapper) AssertUnsupportedError(err error) {
	expectedMessage := "Operation unsupported for this device type."

	if err.(*cryptsetup.Error).Error() != expectedMessage {
		testWrapper.test.Error("Operation should be unsupported, but wasn't reported as so.")
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

func setup() {
	exec.Command("/bin/dd", "if=/dev/zero", fmt.Sprintf("of=%s", DevicePath), "bs=64M", "count=1").Run()
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
