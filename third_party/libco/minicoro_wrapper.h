/* minicoro_wrapper.h - Wrapper for minicoro single-header library
 *
 * minicoro supports: x86, x86_64, ARM, ARM64, RISC-V, WebAssembly
 *
 * This wrapper provides a similar API to libco-mini for compatibility.
 */

#ifndef MINICORO_WRAPPER_H
#define MINICORO_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles */
typedef struct mc_coroutine mc_coroutine_t;
typedef struct mc_scheduler mc_scheduler_t;

/* Callback function type */
typedef void (*mc_routine_fn_t)(void*);

/*
 * Coroutine lifecycle API
 */

/* Create a new coroutine (starts suspended) */
int mc_create(mc_coroutine_t** co, mc_routine_fn_t fn, void* arg, size_t stack_size);

/* Resume a suspended coroutine (returns 1 if completed, 0 if yielded, -1 on error) */
int mc_resume(mc_coroutine_t* co);

/* Yield control back to scheduler */
void mc_yield(void);

/* Get current coroutine (NULL if called from main thread) */
mc_coroutine_t* mc_self(void);

/* Release a coroutine */
void mc_release(mc_coroutine_t* co);

/*
 * Per-thread initialization
 */

/* Initialize minicoro for current thread */
void mc_init_thread(void);

/* Check if initialized */
int mc_thread_inited(void);

/*
 * M:N Scheduler API
 */

/* Create a scheduler for current thread */
mc_scheduler_t* mc_scheduler_create(void);

/* Destroy scheduler */
void mc_scheduler_destroy(mc_scheduler_t* sched);

/* Enqueue a coroutine */
void mc_scheduler_enqueue(mc_scheduler_t* sched, mc_coroutine_t* co);

/* Run scheduler until all complete or timeout (ms) */
int mc_scheduler_run(mc_scheduler_t* sched, int timeout_ms);

/* Run one scheduler iteration */
int mc_scheduler_run_once(mc_scheduler_t* sched);

/* Get pending count */
int mc_scheduler_count(mc_scheduler_t* sched);

/*
 * Utility functions
 */

int64_t mc_now_ms(void);
void mc_sleep_ms(int ms);

#ifdef __cplusplus
}
#endif

#endif /* MINICORO_WRAPPER_H */
