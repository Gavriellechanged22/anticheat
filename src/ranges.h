#ifndef AC_RANGES_H
#define AC_RANGES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct AcRange {
    uintptr_t base;
    uintptr_t end;
} AcRange;

typedef struct AcRangeIndex {
    AcRange *items;
    size_t count;
    size_t capacity;
    bool finalized;
} AcRangeIndex;

void ac_range_index_init(AcRangeIndex *index);
void ac_range_index_free(AcRangeIndex *index);
void ac_range_index_clear(AcRangeIndex *index);
bool ac_range_index_add(AcRangeIndex *index, uintptr_t base, size_t size);
void ac_range_index_finalize(AcRangeIndex *index);
bool ac_range_index_contains(const AcRangeIndex *index, uintptr_t base, size_t size);

#endif
