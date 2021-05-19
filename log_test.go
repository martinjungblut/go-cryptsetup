package cryptsetup

import (
	"testing"
)

func Test_Log(test *testing.T) {
	testWrapper := TestWrapper{test}

	messages := make([]string, 0)
	levels := make([]int, 0)

	SetDebugLevel(CRYPT_DEBUG_ALL)
	SetLogCallback(func(level int, message string) {
		levels = append(levels, level)
		messages = append(messages, message)
	})

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	for i := 0; i < 3; i++ {
		levelsPreviousLength, messagesPreviousLength := len(levels), len(messages)

		err = device.Deactivate(DevicePath)
		testWrapper.AssertError(err)

		if levelsPreviousLength >= len(levels) {
			test.Errorf("'levels' should have increased its length. Previous: %d Current: %d", levelsPreviousLength, len(levels))
		}

		if messagesPreviousLength >= len(messages) {
			test.Errorf("'messages' should have increased its length. Previous: %d Current: %d", messagesPreviousLength, len(messages))
		}
	}
}
