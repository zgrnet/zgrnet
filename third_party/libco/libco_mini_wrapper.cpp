/* libco_mini_wrapper.cpp - Simplified wrapper implementation for Tencent libco
 *
 * Wraps libco's C++ API with a clean C API and adds M:N scheduler support.
 */

#include "libco_mini.h"
#include "co_routine.h"
#include <assert.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

/* Default stack size */
#define CO_STACK_SIZE (128 * 1024)

/* Coroutine wrapper structure */
struct co_coroutine {
    stCoRoutine_t* co;     /* libco handle */
    co_routine_fn_t fn;    /* User function */
    void* arg;             /* User argument */
    void* ret;             /* Return value */
    int completed;         /* Completion flag */
};

/* Scheduler structure */
struct co_scheduler {
    std::vector<co_coroutine_t*> ready_queue;
    co_coroutine_t* current;
    int running;
};

/* Thread-local storage */
static thread_local int t_inited = 0;
static thread_local co_scheduler_t* t_scheduler = nullptr;

/* Current coroutine being executed (for yield) */
static thread_local co_coroutine_t* t_current_coro = nullptr;

/*
 * Coroutine entry wrapper
 */
static void* co_entry_wrapper(void* arg) {
    co_coroutine_t* co = static_cast<co_coroutine_t*>(arg);
    t_current_coro = co;

    /* Execute user function */
    co->ret = co->fn(co->arg);
    co->completed = 1;

    /* Yield back to scheduler */
    co_yield_ct();

    return nullptr;
}

/*
 * Coroutine API Implementation
 */

void co_init_thread(void) {
    if (t_inited) return;

    /* Initialize libco for this thread - use co_self to init env */
    (void)co_self();

    t_inited = 1;
}

int co_thread_inited(void) {
    return t_inited;
}

/* Note: co_self is provided by libco, we use our own wrapper function */
static co_coroutine_t* get_current_coro(void) {
    return t_current_coro;
}

int co_create(co_coroutine_t** co_out, co_routine_fn_t fn, void* arg) {
    if (!co_out || !fn) return -1;

    if (!t_inited) {
        co_init_thread();
    }

    co_coroutine_t* co = new co_coroutine_t();
    co->fn = fn;
    co->arg = arg;
    co->ret = nullptr;
    co->completed = 0;

    /* Create libco coroutine with 128KB stack */
    stCoRoutineAttr_t attr;
    attr.stack_size = CO_STACK_SIZE;
    attr.share_stack = nullptr;

    /* Call libco's co_create */
    int rc = ::co_create(&co->co, &attr, co_entry_wrapper, co);
    if (rc != 0) {
        delete co;
        return -1;
    }

    *co_out = co;
    return 0;
}

int co_resume(co_coroutine_t* co) {
    if (!co || !co->co) return -1;

    if (co->completed) {
        return 1;  /* Already completed */
    }

    t_current_coro = co;
    ::co_resume(co->co);
    t_current_coro = nullptr;

    return co->completed ? 1 : 0;
}

void co_yield(void) {
    if (t_current_coro) {
        co_yield_ct();
    }
}

co_coroutine_t* mini_co_self(void) {
    return t_current_coro;
}

void co_release(co_coroutine_t* co) {
    if (!co) return;

    if (co->co) {
        ::co_release(co->co);
    }
    delete co;
}

int co_reset(co_coroutine_t* co) {
    if (!co) return -1;

    /* libco doesn't have a direct reset, so we recreate */
    if (co->co) {
        ::co_release(co->co);
    }

    co->ret = nullptr;
    co->completed = 0;

    stCoRoutineAttr_t attr;
    attr.stack_size = CO_STACK_SIZE;
    attr.share_stack = nullptr;

    return ::co_create(&co->co, &attr, co_entry_wrapper, co);
}

/*
 * Scheduler API Implementation
 */

co_scheduler_t* co_scheduler_create(void) {
    if (!t_inited) {
        co_init_thread();
    }

    co_scheduler_t* sched = new co_scheduler_t();
    sched->current = nullptr;
    sched->running = 0;

    t_scheduler = sched;
    return sched;
}

void co_scheduler_destroy(co_scheduler_t* sched) {
    if (!sched) return;

    if (t_scheduler == sched) {
        t_scheduler = nullptr;
    }
    delete sched;
}

void co_scheduler_enqueue(co_scheduler_t* sched, co_coroutine_t* co) {
    if (!sched || !co) return;

    sched->ready_queue.push_back(co);
}

int co_scheduler_run_once(co_scheduler_t* sched) {
    if (!sched) return -1;

    size_t initial_count = sched->ready_queue.size();
    std::vector<co_coroutine_t*> remaining;

    for (size_t i = 0; i < initial_count && i < sched->ready_queue.size(); i++) {
        co_coroutine_t* co = sched->ready_queue[i];

        if (co->completed) {
            continue;  /* Skip completed */
        }

        sched->current = co;
        int done = co_resume(co);
        sched->current = nullptr;

        if (!done) {
            /* Not done, will be re-queued */
            remaining.push_back(co);
        }
    }

    /* Update queue with remaining coroutines */
    sched->ready_queue = remaining;

    return static_cast<int>(sched->ready_queue.size());
}

int co_scheduler_run(co_scheduler_t* sched, int timeout_ms) {
    if (!sched) return -1;

    auto start = std::chrono::steady_clock::now();
    sched->running = 1;

    while (!sched->ready_queue.empty() && sched->running) {
        co_scheduler_run_once(sched);

        /* Check timeout */
        if (timeout_ms > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= timeout_ms) {
                break;
            }
        }

        /* Yield to prevent busy loop if no work */
        if (sched->ready_queue.empty()) {
            break;
        }
    }

    sched->running = 0;
    return static_cast<int>(sched->ready_queue.size());
}

int co_scheduler_count(co_scheduler_t* sched) {
    if (!sched) return 0;
    return static_cast<int>(sched->ready_queue.size());
}

co_scheduler_t* co_thread_scheduler(void) {
    return t_scheduler;
}

void co_set_thread_scheduler(co_scheduler_t* sched) {
    t_scheduler = sched;
}

/*
 * Utility functions
 */

void co_enable_hook(void) {
    co_enable_hook_sys();
}

void co_disable_hook(void) {
    co_disable_hook_sys();
}

int64_t co_now_ms(void) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void co_sleep_ms(int ms) {
    if (ms <= 0) return;

    if (t_current_coro) {
        /* Yield multiple times to approximate sleep */
        /* In production: use proper sleep hook */
        int yields = ms / 10;  /* Approximate: 10ms per yield */
        if (yields < 1) yields = 1;
        if (yields > 100) yields = 100;

        for (int i = 0; i < yields; i++) {
            co_yield();
        }
    } else {
        /* Main thread: use OS sleep */
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }
}
