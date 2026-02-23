/* libco_mini.c - Minimal coroutine library implementation
 * Uses setjmp/longjmp for context switching (portable version)
 * Production version uses coctx_swap.S assembly
 */
#define _GNU_SOURCE
#include "libco_mini.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <stdint.h>
#include <assert.h>

/* Default stack size for coroutine (128KB) */
#define CO_STACK_SIZE (128 * 1024)

/* Coroutine states */
typedef enum {
    CO_STATE_INIT,      /* Created but not started */
    CO_STATE_RUNNING,   /* Currently executing */
    CO_STATE_SUSPENDED, /* Yielded, can be resumed */
    CO_STATE_DONE,      /* Completed */
    CO_STATE_ERROR      /* Error state */
} co_state_t;

/* Coroutine structure */
struct co_coroutine {
    jmp_buf ctx;           /* Saved context */
    co_routine_fn_t fn;    /* Entry function */
    void* arg;             /* Entry argument */
    void* stack;           /* Stack memory */
    size_t stack_size;     /* Stack size */
    co_state_t state;      /* Current state */
    void* ret;             /* Return value */
    int is_main;           /* 1 if this is main thread pseudo-coro */
};

/* Scheduler structure (per-thread) */
struct co_scheduler {
    co_coroutine_t** ready_queue;  /* Ready to run */
    int ready_head;                /* Pop index */
    int ready_tail;                /* Push index */
    int ready_size;                /* Queue capacity */
    int ready_count;               /* Current count */

    co_coroutine_t** all_coros;    /* All coroutines for cleanup */
    int all_count;
    int all_capacity;

    co_coroutine_t* current;       /* Currently running */
    int running;                   /* Scheduler running flag */
};

/* Thread-local storage for current coroutine and scheduler */
static __thread co_coroutine_t* t_current_coro = NULL;
static __thread co_scheduler_t* t_scheduler = NULL;
static __thread int t_inited = 0;

/* Forward declarations */
static void co_main_entry(void);

/*
 * Context switching implementation using setjmp/longjmp
 * Production: replace with coctx_swap.S assembly
 */

/* Save current context (returns 0), or restore (returns non-zero) */
#define co_save_ctx(ctx) setjmp(ctx)
#define co_restore_ctx(ctx, val) longjmp(ctx, val)

/*
 * Coroutine API Implementation
 */

void co_init_thread(void) {
    if (t_inited) return;

    /* Create pseudo-coroutine for main thread */
    t_current_coro = calloc(1, sizeof(co_coroutine_t));
    t_current_coro->is_main = 1;
    t_current_coro->state = CO_STATE_RUNNING;

    t_inited = 1;
}

int co_thread_inited(void) {
    return t_inited;
}

co_coroutine_t* co_self(void) {
    return t_current_coro;
}

/* Entry point wrapper for new coroutine */
static void co_entry_wrapper(void) {
    co_coroutine_t* co = t_current_coro;
    assert(co != NULL);
    assert(!co->is_main);

    /* Run user function */
    co->state = CO_STATE_RUNNING;
    co->ret = co->fn(co->arg);
    co->state = CO_STATE_DONE;

    /* Yield back to scheduler */
    co_yield();
}

int co_create(co_coroutine_t** co_out, co_routine_fn_t fn, void* arg) {
    if (!co_out || !fn) return -1;

    co_coroutine_t* co = calloc(1, sizeof(co_coroutine_t));
    if (!co) return -1;

    co->fn = fn;
    co->arg = arg;
    co->state = CO_STATE_INIT;
    co->stack_size = CO_STACK_SIZE;
    co->is_main = 0;

    /* Allocate stack (guard page would be added in production) */
    co->stack = malloc(co->stack_size);
    if (!co->stack) {
        free(co);
        return -1;
    }

    *co_out = co;
    return 0;
}

void co_release(co_coroutine_t* co) {
    if (!co) return;
    if (co->is_main) {
        /* Don't free main thread pseudo-coro */
        return;
    }
    if (co->stack) {
        free(co->stack);
    }
    free(co);
}

int co_reset(co_coroutine_t* co) {
    if (!co || co->is_main) return -1;
    co->state = CO_STATE_INIT;
    co->ret = NULL;
    return 0;
}

/* Yield implementation - swap back to scheduler/main */
void co_yield(void) {
    co_coroutine_t* co = t_current_coro;
    if (!co || co->is_main) {
        /* Cannot yield from main thread */
        return;
    }

    /* Save current context */
    int ret = co_save_ctx(co->ctx);
    if (ret == 0) {
        /* First return: switch to scheduler */
        co->state = CO_STATE_SUSPENDED;
        /* Jump back to scheduler (set in co_resume) */
        co_restore_ctx(co->sched_ctx, 1);
    }
    /* Second return: resumed by scheduler */
}

/* Resume implementation - run coroutine until yield/complete */
int co_resume(co_coroutine_t* co) {
    if (!co || co->is_main) return -1;
    if (co->state != CO_STATE_INIT && co->state != CO_STATE_SUSPENDED) {
        return -1;
    }

    if (!t_inited) {
        co_init_thread();
    }

    /* Save scheduler context so coroutine can yield back */
    jmp_buf sched_ctx;
    int ret = co_save_ctx(sched_ctx);
    if (ret == 0) {
        /* First return: switch to coroutine */
        co->sched_ctx = sched_ctx;
        t_current_coro = co;

        if (co->state == CO_STATE_INIT) {
            /* First time: set up stack and start */
            /* Production: use coctx_swap.S to switch stack */
            /* Portable: use setjmp/longjmp (limited stack switching) */

            /* For portable version, we just call the function directly
             * (limited stack depth, but works for testing) */
            co_entry_wrapper();
        } else {
            /* Resume from saved context */
            co_restore_ctx(co->ctx, 1);
        }
    }
    /* Second return: coroutine yielded/completed */

    t_current_coro = t_scheduler ? t_scheduler->current : NULL;
    return (co->state == CO_STATE_DONE) ? 1 : 0;
}

/*
 * Scheduler API Implementation
 */

static int queue_grow(struct co_scheduler* sched) {
    int new_size = sched->ready_size * 2;
    if (new_size < 16) new_size = 16;

    co_coroutine_t** new_queue = realloc(sched->ready_queue,
                                         new_size * sizeof(co_coroutine_t*));
    if (!new_queue) return -1;

    sched->ready_queue = new_queue;
    sched->ready_size = new_size;
    return 0;
}

co_scheduler_t* co_scheduler_create(void) {
    if (!t_inited) {
        co_init_thread();
    }

    co_scheduler_t* sched = calloc(1, sizeof(co_scheduler_t));
    if (!sched) return NULL;

    sched->ready_size = 64;
    sched->ready_queue = calloc(sched->ready_size, sizeof(co_coroutine_t*));
    if (!sched->ready_queue) {
        free(sched);
        return NULL;
    }

    sched->all_capacity = 64;
    sched->all_coros = calloc(sched->all_capacity, sizeof(co_coroutine_t*));
    if (!sched->all_coros) {
        free(sched->ready_queue);
        free(sched);
        return NULL;
    }

    sched->ready_head = 0;
    sched->ready_tail = 0;
    sched->ready_count = 0;
    sched->all_count = 0;
    sched->current = NULL;
    sched->running = 0;

    t_scheduler = sched;
    return sched;
}

void co_scheduler_destroy(co_scheduler_t* sched) {
    if (!sched) return;

    /* Cleanup all coroutines */
    for (int i = 0; i < sched->all_count; i++) {
        co_release(sched->all_coros[i]);
    }
    free(sched->all_coros);
    free(sched->ready_queue);
    free(sched);

    if (t_scheduler == sched) {
        t_scheduler = NULL;
    }
}

void co_scheduler_enqueue(co_scheduler_t* sched, co_coroutine_t* co) {
    if (!sched || !co) return;

    /* Grow queue if needed */
    if (sched->ready_count >= sched->ready_size - 1) {
        if (queue_grow(sched) < 0) return;
    }

    sched->ready_queue[sched->ready_tail] = co;
    sched->ready_tail = (sched->ready_tail + 1) % sched->ready_size;
    sched->ready_count++;

    /* Track for cleanup */
    if (sched->all_count >= sched->all_capacity) {
        int new_cap = sched->all_capacity * 2;
        co_coroutine_t** new_arr = realloc(sched->all_coros,
                                          new_cap * sizeof(co_coroutine_t*));
        if (new_arr) {
            sched->all_coros = new_arr;
            sched->all_capacity = new_cap;
        }
    }
    if (sched->all_count < sched->all_capacity) {
        sched->all_coros[sched->all_count++] = co;
    }
}

int co_scheduler_run_once(co_scheduler_t* sched) {
    if (!sched) return -1;

    int processed = 0;
    int initial_count = sched->ready_count;

    for (int i = 0; i < initial_count && sched->ready_count > 0; i++) {
        co_coroutine_t* co = sched->ready_queue[sched->ready_head];
        sched->ready_head = (sched->ready_head + 1) % sched->ready_size;
        sched->ready_count--;

        if (co->state == CO_STATE_DONE) {
            continue;  /* Skip completed */
        }

        sched->current = co;
        int done = co_resume(co);
        processed++;

        if (!done && co->state != CO_STATE_DONE) {
            /* Re-enqueue if not done */
            co_scheduler_enqueue(sched, co);
        }

        sched->current = NULL;
    }

    return sched->ready_count;
}

int co_scheduler_run(co_scheduler_t* sched, int timeout_ms) {
    if (!sched) return -1;

    int64_t start = 0;  /* Would use actual time in production */
    (void)start;
    (void)timeout_ms;

    sched->running = 1;

    while (sched->ready_count > 0 && sched->running) {
        co_scheduler_run_once(sched);

        /* In production: sleep/yield to prevent busy loop */
        /* For now: break if no progress */
        if (sched->ready_count == 0) break;
    }

    sched->running = 0;
    return sched->ready_count;
}

int co_scheduler_count(co_scheduler_t* sched) {
    if (!sched) return 0;
    return sched->ready_count;
}

co_scheduler_t* co_thread_scheduler(void) {
    return t_scheduler;
}

void co_set_thread_scheduler(co_scheduler_t* sched) {
    t_scheduler = sched;
}
