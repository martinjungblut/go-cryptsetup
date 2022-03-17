# Go bindings for libcryptsetup

[![run-tests](https://github.com/martinjungblut/go-cryptsetup/actions/workflows/run-tests.yml/badge.svg)](https://github.com/martinjungblut/go-cryptsetup/actions/workflows/run-tests.yml)

## Table of contents
1. [Rationale](#rationale)
2. [Compatibility](#compatibility)
3. [Installation](#installation)
4. [Currently supported device types/operating modes](#supported-modes)
5. [API reference](#api-reference)
	1. [Configuring logging](#configuring-logging)
	2. [Initializing devices](#initializing-devices)
	3. [Formatting devices](#formatting-devices)
	4. [Loading devices](#loading-devices)
	5. [Adding a keyslot by volume key](#adding-keyslot-volume-key)
	6. [Adding a keyslot by passphrase](#adding-keyslot-passphrase)
	7. [Changing a keyslot by passphrase](#changing-keyslot-passphrase)
	8. [Activating devices using the volume key](#activating-devices-volume-key)
	9. [Activating devices using a passphrase](#activating-devices-passphrase)
	10. [Deactivating devices](#deactivating-devices)


## Rationale <a name="rationale"></a>
A number of projects have been using Go's `os/exec` package to interface with the upstream [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup "cryptsetup upstream repository") tools.

Doing so poses some technical issues:

- Uses `fork()` to spawn subprocesses.
- More complicated error handling: requires monitoring the subprocesses' return codes.
- No direct access to cryptsetup's logging infrastructure.
- Programs now depend on the cryptsetup binaries being installed and available in `$PATH`.
- Couples programs to those binaries' command line interfaces.
- Potentially harder to control cryptsetup's finer grained options.

This project is a _pure Go interface for libcryptsetup_, providing a clean and polymorphic API that is both correct and easy to work with.


## Compatibility <a name="compatibility"></a>

These bindings have been tested using libcryptsetup >= 2.0.

GitHub Actions runs the test suite using the following version combinations:

| Ubuntu version | Go version | libcryptsetup version |
|----------------|------------|-----------------------|
| 20.04 LTS      | 1.18       | 2.2.2                 |
| 20.04 LTS      | 1.17       | 2.2.2                 |
| 18.04 LTS      | 1.16       | 2.0.2                 |

Locally, I also test on Fedora, using the latest version of libcryptsetup and Go.


## Installation <a name="installation"></a>

Run the following command to install the bindings:

`$ go get -u github.com/martinjungblut/go-cryptsetup`

Before using these bindings, you have to install the upstream shared objects and development headers.

On Debian/Ubuntu/Linux Mint:

`# apt install libcryptsetup12 libcryptset-dev`

On Arch Linux, everything is available under a single package, including the upstream binaries:

`# pacman -S cryptsetup`

On Fedora, CentOS and RHEL:

`# dnf install cryptsetup-devel cryptsetup-libs`

On openSUSE Tumbleweed and Leap:

`# zypper in libcryptsetup12 libcryptsetup-devel`

On Gentoo:

`# emerge sys-fs/cryptsetup`


## Currently supported device types/operating modes <a name="supported-modes"></a>

Cryptsetup supports different encryption operating modes to use with _dm-crypt_.
Some operations are only supported for some operating modes.

The following modes are currently supported by `go-cryptsetup`:

- Plain
- LUKS1
- LUKS2

Notice that support for the remaining operating modes is planned.


## API reference <a name="api-reference"></a>

Everything is available under the `cryptsetup` module.


### 1. Configuring logging <a name="configuring-logging"></a>

Cryptsetup's logging mechanism is incredibly useful when trying to use its library directly.
Thanks to Go's ABI compatibility with C, it's possible to specify a logging callback directly from Go.
This callback will be automatically called by libcryptsetup for loggable events.

Providing this callback is done by using the `cryptsetup.SetLogCallback()` function.

The provided callback must have the following parameters:

- `int`: the event's severity level.
- `string`: the actual event message.

**Example:**

```go
cryptsetup.SetLogCallback(func(level int, message string) {
	fmt.Srintf("%d: %s", level, message)
})
```

### 2. Initializing devices <a name="initializing-devices"></a>

Initializing a device is the process of acquiring a reference to a particular device node for it to be manipulated.

Devices may be initialised using the `cryptsetup.Init()` function.

**Parameters:**

- `string`: the device's path.

**Return values:**

- `nil` on success.
- `error` with code `-15` if the specified device is not readable, or doesn't exist.

**Supported operating modes:** All

**Example:**

```go
device, err := cryptsetup.Init("path-to-device-node")
if err == nil {
	// device was successfully initialised
} else {
	// error handling
}
```

### 3. Formatting devices <a name="formatting-devices"></a>

After a device has been initialised, it's possible to `Format()` it.

Formatting a device will write to its device node, based on the chosen device type/operating mode.

**Parameters:**

- `DeviceType`: a valid implementation of the `DeviceType` interface, specifying the chosen device type and its parameters.
- `GenericParams`: struct specifying generic parameters, applicable to all device types.

**Return values:**

- A `Device` object, and `nil` on success.
- `nil`, and an `error` on failure.

**Supported operating modes:**

- LUKS1
- LUKS2

**Example using LUKS1:**

```go
luks1 := cryptsetup.LUKS1{Hash: "sha256"}
genericParams := cryptsetup.GenericParams{
	Cipher: "aes",
	CipherMode: "xts-plain64",
	VolumeKeySize: 512 / 8,
}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err == nil {
	err = device.Format(luks1, genericParams)
	if err == nil {
		// success: device was formatted correctly and may be used
	} else {
		// Format() error handling
	}
} else {
	// Init() error handling
}
```

### 4. Loading devices <a name="loading-devices"></a>

After formatting a device, the next time you allocate an object referencing it, it will have to be loaded.

Doing this is as simple as calling `Load()`.

**Return values:**

- `nil` on success, or an `error` on failure.

**Supported operating modes:**

- LUKS1
- LUKS2

**Example using LUKS1:**

```go
// we assume this device node had already been formatted using LUKS1
luks1 := cryptsetup.LUKS1{Hash: "sha256"}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err == nil {
	err = device.Load()
	if err == nil {
		// success: device was loaded correctly and may be used
	} else {
		// Load() error handling
	}
} else {
	// Init() error handling
}
```

### 5. Adding a keyslot by volume key <a name="adding-keyslot-volume-key"></a>

For LUKS 1 or 2 devices, you might want to add a keyslot having a passphrase, by using the configured volume key.

This is done by calling the `KeyslotAddByVolumeKey()` method.

**Parameters:**

- `int`: The keyslot to be added.
- `string`: The volume key. Must match the volume key that was used to format the device. Use an empty string if the key was auto-generated by crytpsetup (not provided when formatting the device).
- `string`: The passphrase to be added to the keyslot.

**Return values:**

- `nil` on success, or an `error` on failure.

**Supported operating modes:**

- LUKS1
- LUKS2

**Example using LUKS1:**

```go
luks1 := cryptsetup.LUKS1{Hash: "sha256"}
genericParams := cryptsetup.GenericParams{
	Cipher: "aes",
	CipherMode: "xts-plain64",
	VolumeKeySize: 512 / 8,
}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err == nil {
	if device.Format(luks1, genericParams) == nil {
		device.KeyslotAddByVolumeKey(0, "", "hypothetical-passphrase")
	}
}
```

### 6. Adding a keyslot by passphrase <a name="adding-keyslot-passphrase"></a>

After a keyslot has been added, it's possible to use its passphrase to add subsequent keyslots.

This is done by calling the `KeyslotAddByPassphrase()` method.

**Parameters:**

- `int`: The keyslot to be added.
- `string`: A passphrase that already exists in a keyslot on this device.
- `string`: Passphrase to be added to the keyslot.

**Return values:**

- `nil` on success, or an `error` on failure.

**Supported operating modes:**

- LUKS1
- LUKS2

**Example using LUKS1:**

```go
luks1 := cryptsetup.LUKS1{Hash: "sha256"}
genericParams := cryptsetup.GenericParams{
	Cipher: "aes",
	CipherMode: "xts-plain64",
	VolumeKeySize: 512 / 8,
}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err == nil {
	if device.Format(luks1, genericParams) == nil {
		if device.KeyslotAddByVolumeKey(0, "", "first-passphrase") == nil {
			device.KeyslotAddByPassphrase(1, "first-passphrase", "second-passphrase")
		}
	}
}
```

### 7. Changing a keyslot by passphrase <a name="changing-keyslot-passphrase"></a>

It's also possible to update a keyslot by using a valid passphrase.

This is done by calling the `KeyslotChangeByPassphrase()` method.

**Parameters:**

- `int`: Current keyslot, must already exist. Will be replaced with the new one.
- `int`: New keyslot.
- `string`: Current passphrase, must be valid. Will be replaced by the new one.
- `string`: New passphrase.

**Return values:**

- `nil` on success, or an `error` on failure.

**Supported operating modes:**

- LUKS1
- LUKS2

**Example using LUKS1:**

```go
luks1 := cryptsetup.LUKS1{Hash: "sha256"}
genericParams := cryptsetup.GenericParams{
	Cipher: "aes",
	CipherMode: "xts-plain64",
	VolumeKeySize: 512 / 8,
}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err == nil {
	if device.Format(luks1, genericParams) == nil {
		if device.KeyslotAddByVolumeKey(0, "", "passphrase") == nil {
			device.KeyslotChangeByPassphrase(0, 0, "passphrase", "new-passphrase")
		}
	}
}
```

### 8. Activating devices using the volume key <a name="activating-devices-volume-key"></a>

The volume key may be used to activate the device, by using the `ActivateByVolumeKey()` method.

**Parameters:**

- `string`: A name for the device to be activated with. This will be the name of the new device node in `/dev/mapper`.
- `string`: The volume key to be used to activate the device. Use an empty string if the key was auto-generated by crytpsetup (not provided when formatting the device).
- `int`: The volume key's length.
- `int`: Activation flags. Check `const.go` for more information.

**Return values:**

- `nil` on success, or an `error` on failure.

**Supported operating modes:** All

**Example using LUKS1:**

```go
luks1 := cryptsetup.LUKS1{Hash: "sha256"}
genericParams := cryptsetup.GenericParams{
	Cipher: "aes",
	CipherMode: "xts-plain64",
	VolumeKeySize: 512 / 8,
}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err == nil {
	if device.Format(luks1, genericParams) == nil {
	    device.ActivateByVolumeKey("hypothetical-device-name", "", 24, 0)
	}
}
```

### 9. Activating devices using a passphrase <a name="activating-devices-passphrase"></a>

A valid passphrase may be used to activate the device, by using the `ActivateByPassphrase()` method.

**Parameters:**

- `string`: A name for the device to be activated with. This will be the name of the new device node in `/dev/mapper`.
- `int`: Keyslot having the passphrase that will be used for activation.
- `string`: Passphrase to activate the device. Must be valid for the specified keyslot.
- `int`: Activation flags. Check `const.go` for more information.

**Return values:**

- `nil` on success, or an `error` on failure.

**Supported operating modes:** All

**Example using LUKS1:**

```go
luks1 := cryptsetup.LUKS1{Hash: "sha256"}
genericParams := cryptsetup.GenericParams{
	Cipher: "aes",
	CipherMode: "xts-plain64",
	VolumeKeySize: 512 / 8,
}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err == nil {
	if device.Format(luks1, genericParams) == nil {
		if device.KeyslotAddByVolumeKey(0, "", "passphrase") == nil {
			device.ActivateByPassphrase("hypothetical-device", 0, "passphrase", 0)
		}
	}
}
```

### 10. Deactivating devices <a name="deactivating-devices"></a>

Deactivating a device is done by calling the `Deactivate()` method.

**Parameters:**

- `string`: The name the device was given when it was activated. This corresponds to its device node name in `/dev/mapper`.

**Return values:**

- `nil` on success, or an `error` on failure.

**Supported operating modes:** All

**Example using LUKS1:**

```go
luks1 := cryptsetup.LUKS1{Hash: "sha256"}
genericParams := cryptsetup.GenericParams{
	Cipher: "aes",
	CipherMode: "xts-plain64",
	VolumeKeySize: 512 / 8,
}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err == nil {
	if device.Format(luks1, genericParams) == nil {
		if device.ActivateByVolumeKey("hypothetical-device", "", 24, 0) == nil {
			device.Deactivate("hypothetical-device")
		}
	}
}
```
