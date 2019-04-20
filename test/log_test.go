package test

import (
	"cryptsetup"
	"testing"
)

func Test_Log(test *testing.T) {
	testWrapper := TestWrapper{test}

	messages := make([]string, 0)
	levels := make([]int, 0)

	cryptsetup.SetLogCallback(func(level int, message string) {
		levels = append(levels, level)
		messages = append(messages, message)
	})

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	for i := 1; i <= 3; i++ {
		err = device.Deactivate(DevicePath)
		testWrapper.AssertError(err)

		if len(levels) != i {
			test.Errorf("Expected 'levels' length to be %d, but was %d.", i, len(levels))
		}

		if len(messages) != i {
			test.Errorf("Expected 'messages' length to be %d, but was %d.", i, len(messages))
		}
	}
}
