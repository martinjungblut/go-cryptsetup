package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
import "C"

const (
	/** enable discards aka trim */
	CRYPT_ACTIVATE_ALLOW_DISCARDS = C.CRYPT_ACTIVATE_ALLOW_DISCARDS

	/** corruption detected (verity), output only */
	CRYPT_ACTIVATE_CORRUPTED = C.CRYPT_ACTIVATE_CORRUPTED

	/** dm-verity: ignore_corruption flag - ignore corruption, log it only */
	CRYPT_ACTIVATE_IGNORE_CORRUPTION = C.CRYPT_ACTIVATE_IGNORE_CORRUPTION

	/** ignore persistently stored flags */
	CRYPT_ACTIVATE_IGNORE_PERSISTENT = C.CRYPT_ACTIVATE_IGNORE_PERSISTENT

	/** dm-verity: ignore_zero_blocks - do not verify zero blocks */
	CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS = C.CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS

	/** key loaded in kernel keyring instead directly in dm-crypt */
	CRYPT_ACTIVATE_KEYRING_KEY = C.CRYPT_ACTIVATE_KEYRING_KEY

	/** dm-integrity: direct writes, do not use journal */
	CRYPT_ACTIVATE_NO_JOURNAL = C.CRYPT_ACTIVATE_NO_JOURNAL

	/** only reported for device without uuid */
	CRYPT_ACTIVATE_NO_UUID = C.CRYPT_ACTIVATE_NO_UUID

	/** skip global udev rules in activation ("private device"), input only */
	CRYPT_ACTIVATE_PRIVATE = C.CRYPT_ACTIVATE_PRIVATE

	/** device is read only */
	CRYPT_ACTIVATE_READONLY = C.CRYPT_ACTIVATE_READONLY

	/** dm-integrity: recovery mode - no journal, no integrity checks */
	CRYPT_ACTIVATE_RECOVERY = C.CRYPT_ACTIVATE_RECOVERY

	/** dm-verity: restart_on_corruption flag - restart kernel on corruption */
	CRYPT_ACTIVATE_RESTART_ON_CORRUPTION = C.CRYPT_ACTIVATE_RESTART_ON_CORRUPTION

	/** use same_cpu_crypt option for dm-crypt */
	CRYPT_ACTIVATE_SAME_CPU_CRYPT = C.CRYPT_ACTIVATE_SAME_CPU_CRYPT

	/** activate even if cannot grant exclusive access (dangerous) */
	CRYPT_ACTIVATE_SHARED = C.CRYPT_ACTIVATE_SHARED

	/** use submit_from_crypt_cpus for dm-crypt */
	CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS = C.CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS

	/** iterate through all keyslots and find first one that fits */
	CRYPT_ANY_SLOT = C.CRYPT_ANY_SLOT

	/** iterate through all tokens */
	CRYPT_ANY_TOKEN = C.CRYPT_ANY_TOKEN

	/** lazy deactivation - remove once last user releases it */
	CRYPT_DEACTIVATE_DEFERRED = C.CRYPT_DEACTIVATE_DEFERRED

	/** force deactivation - if the device is busy, it is replaced by error device */
	CRYPT_DEACTIVATE_FORCE = C.CRYPT_DEACTIVATE_FORCE

	/** debug all */
	CRYPT_DEBUG_ALL = C.CRYPT_DEBUG_ALL

	/** debug none */
	CRYPT_DEBUG_NONE = C.CRYPT_DEBUG_NONE

	/** integrity dm-integrity device */
	CRYPT_INTEGRITY = C.CRYPT_INTEGRITY

	/** argon2i according to rfc */
	CRYPT_KDF_ARGON2I = C.CRYPT_KDF_ARGON2I

	/** argon2id according to rfc */
	CRYPT_KDF_ARGON2ID = C.CRYPT_KDF_ARGON2ID

	/** pbkdf2 according to rfc2898, luks1 legacy */
	CRYPT_KDF_PBKDF2 = C.CRYPT_KDF_PBKDF2

	/** read key only to the first end of line (\\n). */
	CRYPT_KEYFILE_STOP_EOL = C.CRYPT_KEYFILE_STOP_EOL

	/** debug log level - always on stdout */
	CRYPT_LOG_DEBUG = C.CRYPT_LOG_DEBUG

	/** error log level */
	CRYPT_LOG_ERROR = C.CRYPT_LOG_ERROR

	/** normal log level */
	CRYPT_LOG_NORMAL = C.CRYPT_LOG_NORMAL

	/** verbose log level */
	CRYPT_LOG_VERBOSE = C.CRYPT_LOG_VERBOSE

	/** loop-aes compatibility mode */
	CRYPT_LOOPAES = C.CRYPT_LOOPAES

	/** luks version 1 header on-disk */
	CRYPT_LUKS1 = C.CRYPT_LUKS1

	/** luks version 2 header on-disk */
	CRYPT_LUKS2 = C.CRYPT_LUKS2

	/** iteration time set by crypt_set_iteration_time(), for compatibility only. */
	CRYPT_PBKDF_ITER_TIME_SET = C.CRYPT_PBKDF_ITER_TIME_SET

	/** never run benchmarks, use pre-set value or defaults. */
	CRYPT_PBKDF_NO_BENCHMARK = C.CRYPT_PBKDF_NO_BENCHMARK

	/** plain crypt device, no on-disk header */
	CRYPT_PLAIN = C.CRYPT_PLAIN

	/** unfinished offline reencryption */
	CRYPT_REQUIREMENT_OFFLINE_REENCRYPT = C.CRYPT_REQUIREMENT_OFFLINE_REENCRYPT

	/** unknown requirement in header (output only) */
	CRYPT_REQUIREMENT_UNKNOWN = C.CRYPT_REQUIREMENT_UNKNOWN

	/** crypt_rng_random  - use /dev/random (waits if no entropy in system) */
	CRYPT_RNG_RANDOM = C.CRYPT_RNG_RANDOM

	/** crypt_rng_urandom - use /dev/urandom */
	CRYPT_RNG_URANDOM = C.CRYPT_RNG_URANDOM

	/** tcrypt (truecrypt-compatible and veracrypt-compatible) mode */
	CRYPT_TCRYPT = C.CRYPT_TCRYPT

	/** try to load backup header */
	CRYPT_TCRYPT_BACKUP_HEADER = C.CRYPT_TCRYPT_BACKUP_HEADER

	/** try to load hidden header (describing hidden device) */
	CRYPT_TCRYPT_HIDDEN_HEADER = C.CRYPT_TCRYPT_HIDDEN_HEADER

	/** include legacy modes when scanning for header */
	CRYPT_TCRYPT_LEGACY_MODES = C.CRYPT_TCRYPT_LEGACY_MODES

	/** device contains encrypted system (with boot loader) */
	CRYPT_TCRYPT_SYSTEM_HEADER = C.CRYPT_TCRYPT_SYSTEM_HEADER

	/** include veracrypt modes when scanning for header,
	 *  all other tcrypt flags applies as well.
	 *  veracrypt device is reported as tcrypt type.
	 */
	CRYPT_TCRYPT_VERA_MODES = C.CRYPT_TCRYPT_VERA_MODES

	/** dm-verity mode */
	CRYPT_VERITY = C.CRYPT_VERITY

	/** verity hash in userspace before activation */
	CRYPT_VERITY_CHECK_HASH = C.CRYPT_VERITY_CHECK_HASH

	/** create hash - format hash device */
	CRYPT_VERITY_CREATE_HASH = C.CRYPT_VERITY_CREATE_HASH

	/** no on-disk header (only hashes) */
	CRYPT_VERITY_NO_HEADER = C.CRYPT_VERITY_NO_HEADER

	/** create keyslot with volume key not associated with current dm-crypt segment */
	CRYPT_VOLUME_KEY_NO_SEGMENT = C.CRYPT_VOLUME_KEY_NO_SEGMENT

	/** use direct-io */
	CRYPT_WIPE_NO_DIRECT_IO = C.CRYPT_WIPE_NO_DIRECT_IO

	/**< Fill with zeroes */
	CRYPT_WIPE_ZERO = C.CRYPT_WIPE_ZERO

	/**< Use RNG to fill data */
	CRYPT_WIPE_RANDOM = C.CRYPT_WIPE_RANDOM

	/**< Add encryption and fill with zeroes as plaintext */
	CRYPT_WIPE_ENCRYPTED_ZERO = C.CRYPT_WIPE_ENCRYPTED_ZERO

	/**< Compatibility only, do not use (Gutmann method) */
	CRYPT_WIPE_SPECIAL = C.CRYPT_WIPE_SPECIAL
)
