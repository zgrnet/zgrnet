/* libco_mini.h - Minimal coroutine library (simplified from Tencent libco)
 * Only basic coroutine creation/yield/resume, no epoll hooking
 */
#ifndef LIBCO_MINI_H
#define LIBCO_MINI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque coroutine handle */
typedef struct co_coroutine co_coroutine_t;

/* Opaque scheduler handle */
typedef struct co_scheduler co_scheduler_t;

/* Callback function type for coroutine entry point */
typedef void* (*co_routine_fn_t)(void*);

/*
 * Coroutine lifecycle API
 */

/* Create a new coroutine with given entry function and argument.
 * Returns 0 on success, -1 on failure.
 * The coroutine starts in suspended state. */
int co_create(co_coroutine_t** co, co_routine_fn_t fn, void* arg);

/* Resume a suspended coroutine.
 * Returns 0 on success (coroutine yielded/completed), -1 on error. */
int co_resume(co_coroutine_t* co);

/* Yield control from current coroutine back to scheduler.
 * Only valid when called from within a coroutine. */
void co_yield(void);

/* Get current coroutine (NULL if called from main thread). */
co_coroutine_t* co_self(void);

/* Release a coroutine and free its resources.
 * Do not call on running coroutine. */
void co_release(co_coroutine_t* co);

/* Reset a coroutine to initial state (reuse stack). */
int co_reset(co_coroutine_t* co);

/*
 * M:N Scheduler API
 * One scheduler per OS thread. N coroutines mapped to 1 OS thread.
 */

/* Create a scheduler for current thread. */
co_scheduler_t* co_scheduler_create(void);

/* Destroy scheduler (must have no running coroutines). */
void co_scheduler_destroy(co_scheduler_t* sched);

/* Enqueue a coroutine to scheduler's ready queue. */
void co_scheduler_enqueue(co_scheduler_t* sched, co_coroutine_t* co);

/* Run scheduler until all coroutines complete or timeout (ms).
 * Returns number of remaining coroutines (0 = all completed). */
int co_scheduler_run(co_scheduler_t* sched, int timeout_ms);

/* Run one iteration of scheduler (process one batch of ready coroutines).
 * Returns number of coroutines still ready/running. */
int co_scheduler_run_once(co_scheduler_t* sched);

/* Get number of pending/running coroutines in scheduler. */
int co_scheduler_count(co_scheduler_t* sched);

/*
 * Per-thread API (for M:N scheduling across multiple OS threads)
 */

/* Initialize libco for current thread (call once per thread). */
void co_init_thread(void);

/* Check if libco is initialized for current thread. */
int co_thread_inited(void);

/* Get scheduler for current thread (NULL if not created). */
co_scheduler_t* co_thread_scheduler(void);

/* Set scheduler for current thread. */
void co_set_thread_scheduler(co_scheduler_t* sched);

#ifdef __cplusplus
}
#endif

#endif /* LIBCO_MINI_H */
