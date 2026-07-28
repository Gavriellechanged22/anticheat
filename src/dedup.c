#include "dedup.h"

#include <stdlib.h>
#include <string.h>

static size_t ac_round_up_power_of_two(size_t value)
{
    size_t result = 1u;

    while (result < value && result < (SIZE_MAX / 2u) + 1u) {
        result <<= 1;
    }
    return result;
}

static uint64_t ac_mix_fingerprint(uint64_t fingerprint)
{
    uint64_t value = fingerprint;

    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdull;
    value ^= value >> 33;
    value *= 0xc4ceb9fe1a85ec53ull;
    value ^= value >> 33;
    return value;
}

bool ac_dedup_init(AcDedup *dedup, size_t capacity, uint64_t repeat_interval_ms)
{
    size_t slots;

    if (dedup == NULL || capacity == 0) {
        return false;
    }

    slots = ac_round_up_power_of_two(capacity);
    if (slots > SIZE_MAX / sizeof(AcDedupEntry)) {
        return false;
    }

    memset(dedup, 0, sizeof(*dedup));
    dedup->entries = (AcDedupEntry *)calloc(slots, sizeof(AcDedupEntry));
    if (dedup->entries == NULL) {
        return false;
    }

    dedup->capacity = slots;
    dedup->high_water_mark = slots - (slots / 4u);
    dedup->repeat_interval_ms = repeat_interval_ms;
    return true;
}

void ac_dedup_free(AcDedup *dedup)
{
    if (dedup == NULL) {
        return;
    }
    free(dedup->entries);
    memset(dedup, 0, sizeof(*dedup));
}

void ac_dedup_observe(
    AcDedup *dedup,
    uint64_t fingerprint,
    uint64_t scan_id,
    uint64_t now_ms,
    AcDedupDecision *decision_out)
{
    AcDedupDecision decision;
    AcDedupEntry *entry = NULL;
    size_t mask;
    size_t slot;
    size_t probe;

    memset(&decision, 0, sizeof(decision));
    decision.emit = true;
    decision.first_seen = true;
    decision.occurrences = 1u;
    decision.first_scan_id = scan_id;

    if (dedup == NULL || dedup->entries == NULL || dedup->capacity == 0) {
        if (decision_out != NULL) {
            *decision_out = decision;
        }
        return;
    }

    mask = dedup->capacity - 1u;
    slot = (size_t)(ac_mix_fingerprint(fingerprint) & (uint64_t)mask);

    for (probe = 0; probe < dedup->capacity; ++probe) {
        AcDedupEntry *candidate = &dedup->entries[(slot + probe) & mask];

        if (!candidate->used) {
            if (dedup->used < dedup->high_water_mark) {
                entry = candidate;
            }
            break;
        }
        if (candidate->fingerprint == fingerprint) {
            entry = candidate;
            break;
        }
    }

    if (entry == NULL) {
        ++dedup->saturated_events;
        decision.table_saturated = true;
        if (decision_out != NULL) {
            *decision_out = decision;
        }
        return;
    }

    if (!entry->used) {
        entry->used = true;
        entry->fingerprint = fingerprint;
        entry->occurrences = 1u;
        entry->occurrences_at_last_emit = 1u;
        entry->first_scan_id = scan_id;
        entry->last_scan_id = scan_id;
        entry->last_emit_ms = now_ms;
        ++dedup->used;

        decision.first_scan_id = scan_id;
        if (decision_out != NULL) {
            *decision_out = decision;
        }
        return;
    }

    ++entry->occurrences;
    entry->last_scan_id = scan_id;

    decision.first_seen = false;
    decision.occurrences = entry->occurrences;
    decision.first_scan_id = entry->first_scan_id;

    if (dedup->repeat_interval_ms == 0 ||
        now_ms < entry->last_emit_ms ||
        now_ms - entry->last_emit_ms < dedup->repeat_interval_ms) {
        decision.emit = false;
        ++dedup->suppressed_total;
        if (decision_out != NULL) {
            *decision_out = decision;
        }
        return;
    }

    decision.emit = true;
    decision.suppressed_since_last_emit =
        entry->occurrences - entry->occurrences_at_last_emit - 1u;
    entry->occurrences_at_last_emit = entry->occurrences;
    entry->last_emit_ms = now_ms;

    if (decision_out != NULL) {
        *decision_out = decision;
    }
}
