/**
 * minicoro wrapper for Zig integration.
 *
 * This file implements the minicoro header-only library and provides
 * a C interface that can be called from Zig.
 */

#define MINICORO_IMPL
#include "minicoro.h"

#include <stdlib.h>

/* ========================================================================== */
/* Type definitions                                                           */
/* ========================================================================== */

/**
 * Wrapper structure that holds the minicoro handle and user context.
 */
typedef struct {
    mco_coro* handle;
    void* user_data;
    void (*entry)(void* user_data);
} zig_coro_t;

/* ========================================================================== */
/* Internal helpers                                                           */
/* ========================================================================== */

/**
 * Internal wrapper function that minicoro calls.
 * This unpacks the user context and calls the Zig-provided entry function.
 */
static void coro_entry_wrapper(mco_coro* co) {
    zig_coro_t* zig_co = (zig_coro_t*)mco_get_user_data(co);
    if (zig_co && zig_co->entry) {
        zig_co->entry(zig_co->user_data);
    }
}

/* ========================================================================== */
/* Public API                                                                 */
/* ========================================================================== */

/**
 * Create a new coroutine.
 *
 * @param entry      Entry function to call when the coroutine is resumed.
 * @param user_data  User data passed to the entry function.
 * @param stack_size Stack size for the coroutine (0 for default).
 * @return           Opaque handle to the coroutine, or NULL on failure.
 */
zig_coro_t* zig_coro_create(void (*entry)(void*), void* user_data, size_t stack_size) {
    zig_coro_t* co = (zig_coro_t*)malloc(sizeof(zig_coro_t));
    if (!co) {
        return NULL;
    }

    co->entry = entry;
    co->user_data = user_data;

    mco_desc desc = mco_desc_init(coro_entry_wrapper, stack_size > 0 ? stack_size : 0);
    desc.user_data = co;

    mco_result res = mco_create(&co->handle, &desc);
    if (res != MCO_SUCCESS) {
        free(co);
        return NULL;
    }

    return co;
}

/**
 * Destroy a coroutine and free its resources.
 *
 * @param co  Handle to the coroutine.
 */
void zig_coro_destroy(zig_coro_t* co) {
    if (co) {
        if (co->handle) {
            mco_destroy(co->handle);
        }
        free(co);
    }
}

/**
 * Resume a coroutine.
 *
 * Transfers control to the coroutine. Returns when the coroutine yields
 * or completes.
 *
 * @param co  Handle to the coroutine.
 * @return    0 on success, non-zero on error.
 */
int zig_coro_resume(zig_coro_t* co) {
    if (!co || !co->handle) {
        return -1;
    }
    mco_result res = mco_resume(co->handle);
    return (res == MCO_SUCCESS) ? 0 : (int)res;
}

/**
 * Yield from the current coroutine.
 *
 * Must be called from within a coroutine's entry function.
 * Transfers control back to the caller of zig_coro_resume().
 *
 * @param co  Handle to the coroutine (can be NULL, will use running coro).
 * @return    0 on success, non-zero on error.
 */
int zig_coro_yield(zig_coro_t* co) {
    (void)co;  /* Unused - minicoro tracks the running coroutine internally */
    mco_result res = mco_yield(mco_running());
    return (res == MCO_SUCCESS) ? 0 : (int)res;
}

/**
 * Get the status of a coroutine.
 *
 * @param co  Handle to the coroutine.
 * @return    Status code:
 *            - 0: Dead (finished or never started)
 *            - 1: Normal (suspended)
 *            - 2: Running
 *            - 3: Suspended (in nested call)
 */
int zig_coro_status(zig_coro_t* co) {
    if (!co || !co->handle) {
        return 0;  /* Dead */
    }
    return (int)mco_status(co->handle);
}

/**
 * Check if a coroutine is dead (finished or invalid).
 *
 * @param co  Handle to the coroutine.
 * @return    1 if dead, 0 if alive.
 */
int zig_coro_is_dead(zig_coro_t* co) {
    return zig_coro_status(co) == MCO_DEAD;
}

/**
 * Get the currently running coroutine.
 *
 * @return  Handle to the running coroutine, or NULL if none.
 */
zig_coro_t* zig_coro_running(void) {
    mco_coro* co = mco_running();
    if (!co) {
        return NULL;
    }
    return (zig_coro_t*)mco_get_user_data(co);
}
