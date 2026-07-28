#include "ranges.h"

#include <stdlib.h>
#include <string.h>

static uintptr_t ac_range_end(uintptr_t base, size_t size)
{
    if (size == 0) {
        return base;
    }
    if ((uintptr_t)size > UINTPTR_MAX - base) {
        return UINTPTR_MAX;
    }
    return base + (uintptr_t)size;
}

static int ac_range_compare(const void *left, const void *right)
{
    const AcRange *a = (const AcRange *)left;
    const AcRange *b = (const AcRange *)right;

    if (a->base < b->base) {
        return -1;
    }
    if (a->base > b->base) {
        return 1;
    }
    if (a->end < b->end) {
        return -1;
    }
    if (a->end > b->end) {
        return 1;
    }
    return 0;
}

void ac_range_index_init(AcRangeIndex *index)
{
    if (index == NULL) {
        return;
    }
    index->items = NULL;
    index->count = 0;
    index->capacity = 0;
    index->finalized = false;
}

void ac_range_index_free(AcRangeIndex *index)
{
    if (index == NULL) {
        return;
    }
    free(index->items);
    ac_range_index_init(index);
}

void ac_range_index_clear(AcRangeIndex *index)
{
    if (index == NULL) {
        return;
    }
    index->count = 0;
    index->finalized = false;
}

bool ac_range_index_add(AcRangeIndex *index, uintptr_t base, size_t size)
{
    uintptr_t end;

    if (index == NULL || size == 0) {
        return false;
    }

    end = ac_range_end(base, size);
    if (end <= base) {
        return false;
    }

    if (index->count == index->capacity) {
        const size_t capacity = index->capacity == 0 ? 64u : index->capacity * 2u;
        AcRange *items;

        if (capacity > SIZE_MAX / sizeof(AcRange)) {
            return false;
        }
        items = (AcRange *)realloc(index->items, capacity * sizeof(AcRange));
        if (items == NULL) {
            return false;
        }
        index->items = items;
        index->capacity = capacity;
    }

    index->items[index->count].base = base;
    index->items[index->count].end = end;
    ++index->count;
    index->finalized = false;
    return true;
}

void ac_range_index_finalize(AcRangeIndex *index)
{
    size_t read_index;
    size_t write_index;

    if (index == NULL || index->finalized) {
        return;
    }

    if (index->count > 1) {
        qsort(index->items, index->count, sizeof(AcRange), ac_range_compare);
    }

    write_index = 0;
    for (read_index = 0; read_index < index->count; ++read_index) {
        const AcRange current = index->items[read_index];

        if (write_index > 0 && current.base <= index->items[write_index - 1].end) {
            if (current.end > index->items[write_index - 1].end) {
                index->items[write_index - 1].end = current.end;
            }
            continue;
        }
        index->items[write_index++] = current;
    }

    index->count = write_index;
    index->finalized = true;
}

bool ac_range_index_contains(const AcRangeIndex *index, uintptr_t base, size_t size)
{
    size_t low;
    size_t high;
    uintptr_t end;

    if (index == NULL || index->count == 0 || size == 0 || !index->finalized) {
        return false;
    }

    end = ac_range_end(base, size);
    if (end <= base) {
        return false;
    }

    low = 0;
    high = index->count;
    while (low < high) {
        const size_t middle = low + (high - low) / 2u;
        if (index->items[middle].base <= base) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }

    if (low == 0) {
        return false;
    }
    return index->items[low - 1u].end >= end;
}
