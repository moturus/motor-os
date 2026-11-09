#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { COUNT = 65536 };

static int compare(const void *a, const void *b) {
    uint32_t left = *(const uint32_t *)a;
    uint32_t right = *(const uint32_t *)b;
    return (left > right) - (left < right);
}

static int compare_context(const void *a, const void *b, void *context) {
    assert(*(const int *)context == -1);
    return -compare(a, b);
}

/* Check ordering and preservation of every value for both public APIs. */
static void check_pattern(uint32_t *values, uint32_t *counts, int pattern, int reverse) {
    memset(counts, 0, COUNT * sizeof(*counts));
    for (uint32_t i = 0; i < COUNT; i++) {
        uint32_t value = i;
        if (pattern == 1) value = COUNT - 1 - i;
        if (pattern == 2) value = 42;
        if (pattern == 3) value = i % 7;
        if (pattern == 4) value = (i * 40503u + 17u) % COUNT;
        values[i] = value;
        counts[value]++;
    }
    int direction = -1;
    if (reverse)
        qsort_r(values, COUNT, sizeof(*values), compare_context, &direction);
    else
        qsort(values, COUNT, sizeof(*values), compare);
    for (size_t i = 0; i < COUNT; i++) {
        assert(values[i] < COUNT && counts[values[i]] > 0);
        counts[values[i]]--;
        if (i > 0)
            assert(reverse ? values[i - 1] >= values[i] : values[i - 1] <= values[i]);
    }
    for (size_t i = 0; i < COUNT; i++)
        assert(counts[i] == 0);
}

static int compare_record(const void *a, const void *b) {
    return memcmp(a, b, 3);
}

int main(void) {
    uint32_t single = 42;
    int direction = -1;
    qsort(&single, 0, sizeof(single), compare);
    qsort(&single, 1, sizeof(single), compare);
    qsort_r(&single, 0, sizeof(single), compare_context, &direction);
    qsort_r(&single, 1, sizeof(single), compare_context, &direction);
    assert(single == 42);

    uint32_t *values = malloc(COUNT * sizeof(*values));
    uint32_t *counts = malloc(COUNT * sizeof(*counts));
    assert(values && counts);
    for (int pattern = 0; pattern < 5; pattern++) {
        check_pattern(values, counts, pattern, 0);
        check_pattern(values, counts, pattern, 1);
    }
    free(counts);
    free(values);

    unsigned char records[][3] = {{2, 3, 4}, {0, 9, 8}, {2, 3, 3}, {1, 7, 6}};
    const unsigned char expected[][3] = {{0, 9, 8}, {1, 7, 6}, {2, 3, 3}, {2, 3, 4}};
    qsort(records, 4, sizeof(records[0]), compare_record);
    assert(memcmp(records, expected, sizeof(records)) == 0);
    puts("quickjs libc qsort: PASS");
    return 0;
}
