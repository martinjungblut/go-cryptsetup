# Go bindings for libcryptsetup

## Rationale
A number of projects have been using Go's `os/exec` package to interface with the upstream [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup "cryptsetup upstream repository") tools.

Doing so poses some technical issues:

- Programs now depend on the cryptsetup binaries being installed and available in `$PATH`.
- Couples programs to those binaries' command line interfaces.
- Uses `fork()` to spawn subprocesses.
- More complicated error handling: requires monitoring the subprocesses' return codes.
- No direct access to cryptsetup's logging infrastructure.
- Harder to control cryptsetup's finer grained options.

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

Slackware doesn't provide cryptsetup >= 2.0. You might want to build it yourself.


## API reference

Everything is available under the `cryptsetup` module.

### 1. Initialising devices

Initialising a device is the process of acquiring a reference to a particular device that will be manipulated later on.
Devices may be initialised using the `cryptsetup.Init()` function.
It receives a single argument: the device's path.

`cryptsetup.Init()` returns an error with code `-15` if the specified device is not readable, or doesn't exist.

```go
device, err := cryptsetup.Init("path-to-device-node")
if err != nil {
	// error handling
}
```

<!-- ## What's planned -->
<!-- The following function calls will be implemented for the first release (1.0): -->

<!--  1. crypt_init() -->
<!--  2. crypt_format() with plain, LUKS, and Loop-AES types supported -->
<!--  3. crypt_load() -->
<!--  4. crypt_activate_by_passphrase() -->
<!--  5. crypt_activate_by_keyfile_offset() -->
<!--  6. crypt_activate_by_keyfile() -->
<!--  7. crypt_activate_by_volume_key() -->
<!--  8. crypt_deactivate() -->


<!-- ## What's been done already -->

<!--  1. crypt_init() -->
<!--  2. crypt_format() with LUKS support -->
