/* libco_mini.h - Simplified wrapper for Tencent libco
 *
 * Provides minimal coroutine API:
 * - co_create/co_resume/co_yield/co_release
 * - M:N Scheduler (co_scheduler_*)
 *
 * Based on Tencent libco but with simplified interface
 */

#ifndef LIBCO_MINI_H
#define LIBCO_MINI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles */
typedef struct co_coroutine co_coroutine_t;
typedef struct co_scheduler co_scheduler_t;

/* Callback function type */
typedef void* (*co_routine_fn_t)(void*);

/*
 * Coroutine lifecycle API
 */

/* Create a new coroutine (starts suspended) */
int co_create(co_coroutine_t** co, co_routine_fn_t fn, void* arg);

/* Resume a suspended coroutine (returns 1 if completed, 0 if yielded, -1 on error) */
int co_resume(co_coroutine_t* co);

/* Yield control back to scheduler */
void co_yield(void);

/* Get current coroutine (NULL if called from main thread) */
co_coroutine_t* co_self(void);

/* Release a coroutine */
void co_release(co_coroutine_t* co);

/* Reset a coroutine for reuse */
int co_reset(co_coroutine_t* co);

/*
 * Per-thread initialization
 */

/* Initialize libco for current thread (call once per thread) */
void co_init_thread(void);

/* Check if libco is initialized for current thread */
int co_thread_inited(void);

/*
 * M:N Scheduler API
 *
 * Each OS thread has one scheduler. Multiple coroutines (M) run on one OS thread (N=1).
 * For true M:N across multiple OS threads, create multiple schedulers.
 */

/* Create a scheduler for current thread */
co_scheduler_t* co_scheduler_create(void);

/* Destroy scheduler */
void co_scheduler_destroy(co_scheduler_t* sched);

/* Enqueue a coroutine to scheduler's ready queue */
void co_scheduler_enqueue(co_scheduler_t* sched, co_coroutine_t* co);

/* Run scheduler until all coroutines complete or timeout (ms) */
/* Returns number of remaining coroutines (0 = all completed) */
int co_scheduler_run(co_scheduler_t* sched, int timeout_ms);

/* Run one scheduler iteration */
/* Returns number of coroutines still ready/running */
int co_scheduler_run_once(co_scheduler_t* sched);

/* Get number of pending coroutines */
int co_scheduler_count(co_scheduler_t* sched);

/* Get scheduler for current thread (NULL if not created) */
co_scheduler_t* co_thread_scheduler(void);

/* Set scheduler for current thread */
void co_set_thread_scheduler(co_scheduler_t* sched);

/*
 * Utility functions
 */

/* Enable/disable hooking of blocking syscalls (for production use) */
void co_enable_hook(void);
void co_disable_hook(void);

/* Get current time in milliseconds */
int64_t co_now_ms(void);

/* Sleep/yield for specified milliseconds */
void co_sleep_ms(int ms);

#ifdef __cplusplus
}
#endif

#endif /* LIBCO_MINI_H */
