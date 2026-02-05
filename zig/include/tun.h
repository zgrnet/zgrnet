/**
 * @file tun.h
 * @brief Cross-platform TUN device interface
 *
 * This header provides a C API for creating and managing TUN devices
 * on macOS, Linux, and Windows.
 *
 * Example usage:
 * @code
 * #include "tun.h"
 *
 * int main() {
 *     // Initialize (required on Windows for Wintun)
 *     if (tun_init() != 0) {
 *         return 1;
 *     }
 *
 *     // Create TUN device
 *     tun_t* tun = tun_create(NULL);  // NULL for auto-assign name
 *     if (!tun) {
 *         tun_deinit();
 *         return 1;
 *     }
 *
 *     // Configure IP address
 *     tun_set_ipv4(tun, "10.0.0.1", "255.255.255.0");
 *     tun_set_up(tun);
 *
 *     // Read/write packets
 *     char buf[1500];
 *     ssize_t n = tun_read(tun, buf, sizeof(buf));
 *
 *     // Cleanup
 *     tun_close(tun);
 *     tun_deinit();
 *     return 0;
 * }
 * @endcode
 */

#ifndef TUN_H
#define TUN_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
typedef SSIZE_T ssize_t;
#else
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque TUN device handle
 */
typedef struct tun_t tun_t;

/**
 * @brief Error codes returned by TUN functions
 */
typedef enum {
    TUN_OK = 0,
    TUN_ERR_CREATE_FAILED = -1,
    TUN_ERR_OPEN_FAILED = -2,
    TUN_ERR_INVALID_NAME = -3,
    TUN_ERR_PERMISSION_DENIED = -4,
    TUN_ERR_DEVICE_NOT_FOUND = -5,
    TUN_ERR_NOT_SUPPORTED = -6,
    TUN_ERR_DEVICE_BUSY = -7,
    TUN_ERR_INVALID_ARGUMENT = -8,
    TUN_ERR_SYSTEM_RESOURCES = -9,
    TUN_ERR_WOULD_BLOCK = -10,
    TUN_ERR_IO_ERROR = -11,
    TUN_ERR_SET_MTU_FAILED = -12,
    TUN_ERR_SET_ADDRESS_FAILED = -13,
    TUN_ERR_SET_STATE_FAILED = -14,
    TUN_ERR_ALREADY_CLOSED = -15,
    TUN_ERR_WINTUN_NOT_FOUND = -16,
    TUN_ERR_WINTUN_INIT_FAILED = -17,
} tun_error_t;

/* ============================================================================
 * Initialization
 * ============================================================================ */

/**
 * @brief Initialize TUN subsystem
 *
 * On Windows, this extracts and loads the embedded wintun.dll.
 * On Unix systems, this is a no-op but should still be called for portability.
 *
 * @return TUN_OK on success, or a negative error code
 */
int tun_init(void);

/**
 * @brief Cleanup TUN subsystem
 *
 * On Windows, this unloads wintun.dll.
 * On Unix systems, this is a no-op but should still be called for portability.
 */
void tun_deinit(void);

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * @brief Create a new TUN device
 *
 * @param name Device name (NULL for auto-assign)
 *             - macOS: "utunN" where N is a number (e.g., "utun0")
 *             - Linux: "tunN" or any valid interface name
 *             - Windows: Any string (used as adapter name)
 *
 * @return Pointer to TUN device on success, NULL on failure
 */
tun_t* tun_create(const char* name);

/**
 * @brief Close a TUN device
 *
 * Releases all resources associated with the device.
 * After close, the handle is invalid and must not be used.
 *
 * @param tun TUN device handle
 */
void tun_close(tun_t* tun);

/* ============================================================================
 * Read/Write
 * ============================================================================ */

/**
 * @brief Read a packet from the TUN device
 *
 * Blocks until a packet is available (unless in non-blocking mode).
 * The packet is a raw IP packet (IPv4 or IPv6).
 *
 * @param tun TUN device handle
 * @param buf Buffer to store the packet
 * @param len Maximum number of bytes to read
 *
 * @return Number of bytes read on success, or a negative error code
 */
ssize_t tun_read(tun_t* tun, void* buf, size_t len);

/**
 * @brief Write a packet to the TUN device
 *
 * The packet should be a valid IP packet (IPv4 or IPv6).
 * Packets written to the TUN device appear as if they came from the network.
 *
 * @param tun TUN device handle
 * @param buf Packet data
 * @param len Number of bytes to write
 *
 * @return Number of bytes written on success, or a negative error code
 */
ssize_t tun_write(tun_t* tun, const void* buf, size_t len);

/* ============================================================================
 * Properties
 * ============================================================================ */

/**
 * @brief Get the device name
 *
 * @param tun TUN device handle
 *
 * @return Device name (null-terminated string), or NULL on error
 */
const char* tun_get_name(tun_t* tun);

/**
 * @brief Get the underlying handle
 *
 * Returns the file descriptor (Unix) or HANDLE (Windows).
 * Useful for integrating with event loops (poll/epoll/kqueue/IOCP).
 *
 * @param tun TUN device handle
 *
 * @return File descriptor on Unix, HANDLE on Windows, or -1 on error
 */
#ifdef _WIN32
HANDLE tun_get_handle(tun_t* tun);
#else
int tun_get_handle(tun_t* tun);
#endif

/* ============================================================================
 * MTU
 * ============================================================================ */

/**
 * @brief Get the MTU (Maximum Transmission Unit)
 *
 * @param tun TUN device handle
 *
 * @return MTU value on success, or a negative error code
 */
int tun_get_mtu(tun_t* tun);

/**
 * @brief Set the MTU (Maximum Transmission Unit)
 *
 * Requires root/admin privileges.
 *
 * @param tun TUN device handle
 * @param mtu New MTU value
 *
 * @return TUN_OK on success, or a negative error code
 */
int tun_set_mtu(tun_t* tun, int mtu);

/* ============================================================================
 * Non-blocking Mode
 * ============================================================================ */

/**
 * @brief Set non-blocking mode
 *
 * In non-blocking mode, read() returns TUN_ERR_WOULD_BLOCK if no data
 * is available instead of blocking.
 *
 * @param tun TUN device handle
 * @param enabled 1 to enable non-blocking, 0 to disable
 *
 * @return TUN_OK on success, or a negative error code
 */
int tun_set_nonblocking(tun_t* tun, int enabled);

/* ============================================================================
 * Interface State
 * ============================================================================ */

/**
 * @brief Bring the interface up
 *
 * Equivalent to `ifconfig <name> up` or `ip link set <name> up`.
 * Requires root/admin privileges.
 *
 * @param tun TUN device handle
 *
 * @return TUN_OK on success, or a negative error code
 */
int tun_set_up(tun_t* tun);

/**
 * @brief Bring the interface down
 *
 * Equivalent to `ifconfig <name> down` or `ip link set <name> down`.
 * Requires root/admin privileges.
 *
 * @param tun TUN device handle
 *
 * @return TUN_OK on success, or a negative error code
 */
int tun_set_down(tun_t* tun);

/* ============================================================================
 * IP Configuration
 * ============================================================================ */

/**
 * @brief Set IPv4 address and netmask
 *
 * Requires root/admin privileges.
 *
 * @param tun TUN device handle
 * @param addr IPv4 address in dotted-decimal notation (e.g., "10.0.0.1")
 * @param netmask Netmask in dotted-decimal notation (e.g., "255.255.255.0")
 *
 * @return TUN_OK on success, or a negative error code
 */
int tun_set_ipv4(tun_t* tun, const char* addr, const char* netmask);

/**
 * @brief Set IPv6 address with prefix length
 *
 * Requires root/admin privileges.
 *
 * @param tun TUN device handle
 * @param addr IPv6 address in standard notation (e.g., "fd00::1")
 * @param prefix_len Prefix length (0-128)
 *
 * @return TUN_OK on success, or a negative error code
 */
int tun_set_ipv6(tun_t* tun, const char* addr, int prefix_len);

#ifdef __cplusplus
}
#endif

#endif /* TUN_H */
