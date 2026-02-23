// libco_mini_test.c - Simple test for libco-mini
#include "libco_mini.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

static int counter = 0;
static int active_coroutines = 0;

void* worker_coroutine(void* arg) {
    int id = (int)(size_t)arg;
    (void)id;

    for (int i = 0; i < 1000; i++) {
        counter++;

        // Yield periodically to let other coroutines run
        if (counter % 100 == 0) {
            co_yield();
        }
    }

    active_coroutines--;
    return NULL;
}

void* simple_coroutine(void* arg) {
    int id = (int)(size_t)arg;
    printf("Coroutine %d starting\n", id);

    for (int i = 0; i < 5; i++) {
        printf("Coroutine %d: iteration %d\n", id, i);
        co_yield();
    }

    printf("Coroutine %d ending\n", id);
    active_coroutines--;
    return NULL;
}

int test_basic_coroutines(void) {
    printf("\n=== Test: Basic Coroutines ===\n");

    co_scheduler_t* sched = co_scheduler_create();
    if (!sched) {
        fprintf(stderr, "Failed to create scheduler\n");
        return 1;
    }

    active_coroutines = 3;

    for (int i = 0; i < 3; i++) {
        co_coroutine_t* co;
        int rc = co_create(&co, simple_coroutine, (void*)(size_t)i);
        if (rc != 0) {
            fprintf(stderr, "Failed to create coroutine %d\n", i);
            return 1;
        }
        co_scheduler_enqueue(sched, co);
    }

    // Run until all complete
    int remaining = co_scheduler_run(sched, 5000);
    printf("Scheduler finished with %d coroutines remaining\n", remaining);

    co_scheduler_destroy(sched);

    printf("Basic coroutine test: PASSED\n");
    return 0;
}

int test_stress_coroutines(void) {
    printf("\n=== Test: Stress Test (100 coroutines x 1000 iterations) ===\n");

    co_scheduler_t* sched = co_scheduler_create();
    if (!sched) {
        fprintf(stderr, "Failed to create scheduler\n");
        return 1;
    }

    counter = 0;
    active_coroutines = 100;
    const int num_coroutines = 100;

    for (int i = 0; i < num_coroutines; i++) {
        co_coroutine_t* co;
        int rc = co_create(&co, worker_coroutine, (void*)(size_t)i);
        if (rc != 0) {
            fprintf(stderr, "Failed to create coroutine %d\n", i);
            return 1;
        }
        co_scheduler_enqueue(sched, co);
    }

    // Run until all complete
    int remaining = co_scheduler_run(sched, 10000);
    printf("Scheduler finished with %d coroutines remaining\n", remaining);
    printf("Final counter: %d (expected: %d)\n", counter, num_coroutines * 1000);

    assert(counter == num_coroutines * 1000);
    assert(remaining == 0);

    co_scheduler_destroy(sched);

    printf("Stress test: PASSED\n");
    return 0;
}

int main(void) {
    printf("libco-mini test suite\n");
    printf("=====================\n");

    if (test_basic_coroutines() != 0) {
        fprintf(stderr, "Basic test FAILED\n");
        return 1;
    }

    if (test_stress_coroutines() != 0) {
        fprintf(stderr, "Stress test FAILED\n");
        return 1;
    }

    printf("\n=== All tests PASSED ===\n");
    return 0;
}
