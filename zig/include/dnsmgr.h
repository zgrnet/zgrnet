/**
 * @file dnsmgr.h
 * @brief Cross-platform OS DNS configuration manager
 *
 * This header provides a C API for configuring the operating system's
 * DNS resolver to route specific domain queries to a custom nameserver.
 *
 * Platform-specific mechanisms:
 * - macOS: /etc/resolver/ files (native split DNS)
 * - Linux: systemd-resolved or /etc/resolv.conf
 * - Windows: NRPT (Name Resolution Policy Table) registry rules
 *
 * Example usage:
 * @code
 * #include "dnsmgr.h"
 *
 * int main() {
 *     // Create manager
 *     dnsmgr_t* mgr = dnsmgr_create("utun3");
 *     if (!mgr) return 1;
 *
 *     // Route *.zigor.net queries to our Magic DNS server
 *     int rc = dnsmgr_set(mgr, "100.64.0.1", "zigor.net");
 *     if (rc != 0) {
 *         dnsmgr_close(mgr);
 *         return 1;
 *     }
 *
 *     // ... application runs ...
 *
 *     // Cleanup (restores original DNS config)
 *     dnsmgr_close(mgr);
 *     return 0;
 * }
 * @endcode
 */

#ifndef DNSMGR_H
#define DNSMGR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque DNS manager handle
 */
typedef struct dnsmgr_t dnsmgr_t;

/**
 * @brief Error codes returned by dnsmgr functions
 */
typedef enum {
    DNSMGR_OK = 0,
    DNSMGR_ERR_SET_FAILED = -1,
    DNSMGR_ERR_CREATE_FAILED = -2,
    DNSMGR_ERR_REMOVE_FAILED = -3,
    DNSMGR_ERR_PERMISSION_DENIED = -4,
    DNSMGR_ERR_NOT_SUPPORTED = -5,
    DNSMGR_ERR_INVALID_ARGUMENT = -6,
    DNSMGR_ERR_FLUSH_FAILED = -7,
    DNSMGR_ERR_DETECT_FAILED = -8,
    DNSMGR_ERR_UPSTREAM_FAILED = -9,
} dnsmgr_error_t;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * @brief Create a new DNS manager
 *
 * @param iface_name TUN interface name (e.g., "utun3", "tun0")
 *                   NULL if not applicable
 *
 * @return Pointer to DNS manager on success, NULL on failure
 */
dnsmgr_t* dnsmgr_create(const char* iface_name);

/**
 * @brief Close and destroy a DNS manager
 *
 * Restores the original DNS configuration before the manager was created.
 * After close, the handle is invalid and must not be used.
 *
 * @param mgr DNS manager handle (NULL is safe)
 */
void dnsmgr_close(dnsmgr_t* mgr);

/* ============================================================================
 * Configuration
 * ============================================================================ */

/**
 * @brief Set DNS configuration
 *
 * Routes queries for the specified domains to the given nameserver.
 *
 * @param mgr DNS manager handle
 * @param nameserver IP address of the DNS server (e.g., "100.64.0.1")
 * @param domains Comma-separated domain suffixes (e.g., "zigor.net,example.com").
 *                No limit on the number of domains.
 *
 * @return DNSMGR_OK on success, or a negative error code
 */
int dnsmgr_set(dnsmgr_t* mgr, const char* nameserver, const char* domains);

/**
 * @brief Check if platform supports split DNS
 *
 * @param mgr DNS manager handle
 *
 * @return 1 if split DNS is supported, 0 otherwise
 */
int dnsmgr_supports_split_dns(dnsmgr_t* mgr);

/**
 * @brief Flush OS DNS cache
 *
 * Forces the operating system to clear its DNS cache.
 *
 * @return DNSMGR_OK on success, or a negative error code
 */
int dnsmgr_flush_cache(void);

#ifdef __cplusplus
}
#endif

#endif /* DNSMGR_H */
