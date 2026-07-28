#ifndef AC_DEDUP_H
#define AC_DEDUP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct AcDedupEntry {
    uint64_t fingerprint;
    uint64_t occurrences;
    uint64_t occurrences_at_last_emit;
    uint64_t first_scan_id;
    uint64_t last_scan_id;
    uint64_t last_emit_ms;
    bool used;
} AcDedupEntry;

typedef struct AcDedup {
    AcDedupEntry *entries;
    size_t capacity;
    size_t used;
    size_t high_water_mark;
    uint64_t repeat_interval_ms;
    uint64_t suppressed_total;
    uint64_t saturated_events;
} AcDedup;

typedef struct AcDedupDecision {
    bool emit;
    bool first_seen;
    bool table_saturated;
    uint64_t occurrences;
    uint64_t suppressed_since_last_emit;
    uint64_t first_scan_id;
} AcDedupDecision;

bool ac_dedup_init(AcDedup *dedup, size_t capacity, uint64_t repeat_interval_ms);
void ac_dedup_free(AcDedup *dedup);
void ac_dedup_observe(
    AcDedup *dedup,
    uint64_t fingerprint,
    uint64_t scan_id,
    uint64_t now_ms,
    AcDedupDecision *decision_out);

#endif
