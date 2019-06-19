# Go bindings for libcryptsetup

## Rationale
A number of projects have been using Go's `os/exec` package to interface with the upstream [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup "cryptsetup upstream repository") tools.

Doing so poses some technical issues:

- Uses `fork()` to spawn subprocesses.
- More complicated error handling: requires monitoring the subprocesses' return codes.
- No direct access to cryptsetup's logging infrastructure.
- Programs now depend on the cryptsetup binaries being installed and available in `$PATH`.
- Couples programs to those binaries' command line interfaces.
- Potentially harder to control cryptsetup's finer grained options.

This project is a _pure Go interface for libcryptsetup_, providing a clean and polymorphic API that is both correct and easy to work with.


## Compatibility

These bindings have been tested using libcryptsetup >= 2.0.


## Installation

Run the following command to install the bindings:

`$ go get -u github.com/martinjungblut/go-cryptsetup`

Before using these bindings, you have to install the upstream shared objects and development headers.

On Debian/Ubuntu/Linux Mint:

`# apt install libcryptsetup12 libcryptset-dev`

On Arch Linux, everything is available under a single package, including the upstream binaries:

`# pacman -S cryptsetup`

On Fedora, CentOS and RHEL:

`# dnf install cryptsetup-devel cryptsetup-libs`

On Gentoo, the `sys-fs/cryptsetup` package is masked for versions >= 2.0.
You might want to unmask it, and then:

`# emerge sys-fs/cryptsetup`


## API reference

Everything is available under the `cryptsetup` module.

Cryptsetup supports different encryption operating modes to use with _dm-crypt_.
Some operations are only supported for some operating modes.

The following modes are currently supported by `go-cryptsetup`:

- Plain
- LUKS1
- LUKS2

Notice that support for the remaining operating modes is planned.

### 1. Configuring logging

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

### 2. Initialising devices

Initialising a device is the process of acquiring a reference to a particular device node for it to be manipulated.

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
if err != nil {
	// error handling
} else {
	// device was successfully initialised
}
```

### 3. Formatting devices

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
	VolumeKeySize: 256 / 8
}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err != nil {
	// Init() error handling
} else {
	err = device.Format(luks1, genericParams)
	if err != nil {
		// Format() error handling
	}
}
```

### 4. Loading devices

After formatting a device, the next time you allocate an object referencing it, it will have to be loaded.
Doing this is as simple as calling `Load()` providing the correct device type/operating mode.

**Parameters:**

- `DeviceType`: A valid implementation of the `DeviceType` interface, specifying the chosen device type and its parameters.

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
if err != nil {
	// Init() error handling
} else {
	err = device.Load(luks1)
	if err != nil {
		// Load() error handling
	} else {
		// device was loaded correctly and may be used
	}
}
```

### 5. Adding a keyslot by volume key

For LUKS 1 or 2 devices, you might want to add a keyslot having a passphrase, by using the configured volume key.
This is done by calling the `KeyslotAddByVolumeKey()` method.

**Parameters:**

- `int`: The keyslot to be added.
- `string`: Volume key. Must match the volume key that was used to format the device.
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
	VolumeKeySize: 256 / 8
}

device, err := cryptsetup.Init("/dev/hypothetical-device-node")
if err == nil {
	if device.Format(luks1, genericParams) == nil {
		device.KeyslotAddByVolumeKey(0, "", "hypothetical-passphrase")
	}
}
```
