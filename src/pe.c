#include "pe.h"

#include <stdlib.h>
#include <string.h>

#define AC_PE_DOS_MAGIC 0x5a4du
#define AC_PE_NT_MAGIC 0x00004550u
#define AC_PE_OPTIONAL_MAGIC_32 0x010bu
#define AC_PE_OPTIONAL_MAGIC_64 0x020bu
#define AC_PE_COFF_HEADER_SIZE 20u
#define AC_PE_SECTION_HEADER_SIZE 40u
#define AC_PE_IMPORT_DESCRIPTOR_SIZE 20u
#define AC_PE_DELAY_DESCRIPTOR_SIZE 32u
#define AC_PE_EXPORT_DIRECTORY_SIZE 40u
#define AC_PE_MAX_THUNKS 65536u
#define AC_PE_MAX_DESCRIPTORS 4096u

#define AC_PE_REL_ABSOLUTE 0u
#define AC_PE_REL_HIGH 1u
#define AC_PE_REL_LOW 2u
#define AC_PE_REL_HIGHLOW 3u
#define AC_PE_REL_HIGHADJ 4u
#define AC_PE_REL_DIR64 10u

const char *ac_pe_status_name(AcPeStatus status)
{
    switch (status) {
        case AC_PE_OK: return "ok";
        case AC_PE_ERR_TRUNCATED: return "truncated";
        case AC_PE_ERR_NOT_PE: return "not_pe";
        case AC_PE_ERR_UNSUPPORTED: return "unsupported";
        case AC_PE_ERR_MALFORMED: return "malformed";
        case AC_PE_ERR_NO_MEMORY: return "no_memory";
        default: return "unknown";
    }
}

static bool ac_pe_readable(const AcPeImage *image, uint64_t offset, uint64_t length)
{
    return offset <= image->size && length <= image->size - offset;
}

static bool ac_pe_u16_at(const uint8_t *data, size_t size, uint64_t offset, uint16_t *value_out)
{
    if (offset + 2u > size) {
        return false;
    }
    *value_out = (uint16_t)((uint16_t)data[offset] | ((uint16_t)data[offset + 1u] << 8));
    return true;
}

static bool ac_pe_u32_at(const uint8_t *data, size_t size, uint64_t offset, uint32_t *value_out)
{
    if (offset + 4u > size) {
        return false;
    }
    *value_out = (uint32_t)data[offset] |
                 ((uint32_t)data[offset + 1u] << 8) |
                 ((uint32_t)data[offset + 2u] << 16) |
                 ((uint32_t)data[offset + 3u] << 24);
    return true;
}

static bool ac_pe_u64_at(const uint8_t *data, size_t size, uint64_t offset, uint64_t *value_out)
{
    uint32_t low;
    uint32_t high;

    if (!ac_pe_u32_at(data, size, offset, &low) ||
        !ac_pe_u32_at(data, size, offset + 4u, &high)) {
        return false;
    }
    *value_out = (uint64_t)low | ((uint64_t)high << 32);
    return true;
}

AcPeStatus ac_pe_parse(const uint8_t *data, size_t size, AcPeImage *image)
{
    uint16_t dos_magic;
    uint32_t nt_offset;
    uint32_t nt_signature;
    uint16_t machine;
    uint16_t section_count;
    uint16_t optional_size;
    uint16_t optional_magic;
    uint64_t optional_offset;
    uint64_t section_offset;
    uint32_t directory_count;
    uint64_t directory_offset;
    uint32_t index;

    if (image == NULL) {
        return AC_PE_ERR_MALFORMED;
    }
    memset(image, 0, sizeof(*image));
    if (data == NULL || size < 0x40u) {
        return AC_PE_ERR_TRUNCATED;
    }

    image->data = data;
    image->size = size;

    if (!ac_pe_u16_at(data, size, 0, &dos_magic) || dos_magic != AC_PE_DOS_MAGIC) {
        return AC_PE_ERR_NOT_PE;
    }
    if (!ac_pe_u32_at(data, size, 0x3cu, &nt_offset)) {
        return AC_PE_ERR_TRUNCATED;
    }
    if ((uint64_t)nt_offset + 4u + AC_PE_COFF_HEADER_SIZE > size) {
        return AC_PE_ERR_TRUNCATED;
    }
    if (!ac_pe_u32_at(data, size, nt_offset, &nt_signature) ||
        nt_signature != AC_PE_NT_MAGIC) {
        return AC_PE_ERR_NOT_PE;
    }

    if (!ac_pe_u16_at(data, size, (uint64_t)nt_offset + 4u, &machine) ||
        !ac_pe_u16_at(data, size, (uint64_t)nt_offset + 6u, &section_count) ||
        !ac_pe_u16_at(data, size, (uint64_t)nt_offset + 20u, &optional_size)) {
        return AC_PE_ERR_TRUNCATED;
    }

    if (section_count == 0 || section_count > AC_PE_MAX_SECTIONS) {
        return AC_PE_ERR_UNSUPPORTED;
    }

    optional_offset = (uint64_t)nt_offset + 4u + AC_PE_COFF_HEADER_SIZE;
    if (optional_size < 2u || optional_offset + optional_size > size) {
        return AC_PE_ERR_TRUNCATED;
    }
    if (!ac_pe_u16_at(data, size, optional_offset, &optional_magic)) {
        return AC_PE_ERR_TRUNCATED;
    }

    if (optional_magic == AC_PE_OPTIONAL_MAGIC_64) {
        image->is_64bit = true;
    } else if (optional_magic == AC_PE_OPTIONAL_MAGIC_32) {
        image->is_64bit = false;
    } else {
        return AC_PE_ERR_UNSUPPORTED;
    }

    image->machine = machine;
    image->section_count = section_count;

    if (image->is_64bit) {
        if (!ac_pe_u64_at(data, size, optional_offset + 24u, &image->image_base) ||
            !ac_pe_u32_at(data, size, optional_offset + 108u, &directory_count)) {
            return AC_PE_ERR_TRUNCATED;
        }
        directory_offset = optional_offset + 112u;
    } else {
        uint32_t base32 = 0;

        if (!ac_pe_u32_at(data, size, optional_offset + 28u, &base32) ||
            !ac_pe_u32_at(data, size, optional_offset + 92u, &directory_count)) {
            return AC_PE_ERR_TRUNCATED;
        }
        image->image_base = base32;
        directory_offset = optional_offset + 96u;
    }

    if (!ac_pe_u32_at(data, size, optional_offset + 16u, &image->entry_point) ||
        !ac_pe_u32_at(data, size, optional_offset + 56u, &image->size_of_image) ||
        !ac_pe_u32_at(data, size, optional_offset + 60u, &image->size_of_headers)) {
        return AC_PE_ERR_TRUNCATED;
    }

    if (directory_count > AC_PE_DIRECTORY_COUNT) {
        directory_count = AC_PE_DIRECTORY_COUNT;
    }
    for (index = 0; index < directory_count; ++index) {
        const uint64_t entry = directory_offset + (uint64_t)index * 8u;

        if (!ac_pe_u32_at(data, size, entry, &image->directories[index].rva) ||
            !ac_pe_u32_at(data, size, entry + 4u, &image->directories[index].size)) {
            return AC_PE_ERR_TRUNCATED;
        }
    }

    section_offset = optional_offset + optional_size;
    if (section_offset + (uint64_t)section_count * AC_PE_SECTION_HEADER_SIZE > size) {
        return AC_PE_ERR_TRUNCATED;
    }

    for (index = 0; index < section_count; ++index) {
        const uint64_t entry = section_offset + (uint64_t)index * AC_PE_SECTION_HEADER_SIZE;
        AcPeSection *section = &image->sections[index];

        memcpy(section->name, data + entry, 8u);
        section->name[8] = '\0';

        if (!ac_pe_u32_at(data, size, entry + 8u, &section->virtual_size) ||
            !ac_pe_u32_at(data, size, entry + 12u, &section->virtual_address) ||
            !ac_pe_u32_at(data, size, entry + 16u, &section->raw_size) ||
            !ac_pe_u32_at(data, size, entry + 20u, &section->raw_offset) ||
            !ac_pe_u32_at(data, size, entry + 36u, &section->characteristics)) {
            return AC_PE_ERR_TRUNCATED;
        }

        if (section->virtual_size == 0) {
            section->virtual_size = section->raw_size;
        }
        if ((uint64_t)section->virtual_address + section->virtual_size > 0xffffffffull) {
            return AC_PE_ERR_MALFORMED;
        }
        if (section->raw_size != 0 &&
            (uint64_t)section->raw_offset + section->raw_size > size) {
            /* Truncated payload: keep the header but expose no readable bytes. */
            section->raw_size = 0;
        }
    }

    return AC_PE_OK;
}

bool ac_pe_section_is_executable(const AcPeSection *section)
{
    if (section == NULL) {
        return false;
    }
    return (section->characteristics & AC_PE_SCN_MEM_EXECUTE) != 0 ||
           (section->characteristics & AC_PE_SCN_CNT_CODE) != 0;
}

const AcPeSection *ac_pe_find_section_by_rva(const AcPeImage *image, uint32_t rva)
{
    uint16_t index;

    if (image == NULL) {
        return NULL;
    }

    for (index = 0; index < image->section_count; ++index) {
        const AcPeSection *section = &image->sections[index];

        if (rva >= section->virtual_address &&
            rva - section->virtual_address < section->virtual_size) {
            return section;
        }
    }
    return NULL;
}

bool ac_pe_rva_to_offset(const AcPeImage *image, uint32_t rva, uint32_t *offset_out)
{
    const AcPeSection *section = ac_pe_find_section_by_rva(image, rva);
    uint32_t delta;

    if (offset_out == NULL) {
        return false;
    }

    if (section == NULL) {
        if (image != NULL && rva < image->size_of_headers && rva < image->size) {
            *offset_out = rva;
            return true;
        }
        return false;
    }

    delta = rva - section->virtual_address;
    if (delta >= section->raw_size) {
        return false;
    }

    *offset_out = section->raw_offset + delta;
    return true;
}

bool ac_pe_read_u32_rva(const AcPeImage *image, uint32_t rva, uint32_t *value_out)
{
    uint32_t offset;

    if (image == NULL || value_out == NULL || !ac_pe_rva_to_offset(image, rva, &offset)) {
        return false;
    }
    return ac_pe_u32_at(image->data, image->size, offset, value_out);
}

void ac_pe_mask_init(AcPeMask *mask)
{
    if (mask == NULL) {
        return;
    }
    mask->items = NULL;
    mask->count = 0;
    mask->capacity = 0;
    mask->finalized = false;
}

void ac_pe_mask_free(AcPeMask *mask)
{
    if (mask == NULL) {
        return;
    }
    free(mask->items);
    ac_pe_mask_init(mask);
}

void ac_pe_mask_clear(AcPeMask *mask)
{
    if (mask == NULL) {
        return;
    }
    mask->count = 0;
    mask->finalized = false;
}

bool ac_pe_mask_add(AcPeMask *mask, uint32_t rva, uint32_t size)
{
    uint64_t end;

    if (mask == NULL || size == 0) {
        return false;
    }

    end = (uint64_t)rva + size;
    if (end > 0xffffffffull) {
        end = 0xffffffffull;
    }

    if (mask->count == mask->capacity) {
        const size_t capacity = mask->capacity == 0 ? 16u : mask->capacity * 2u;
        AcPeRange *items;

        if (capacity > SIZE_MAX / sizeof(AcPeRange)) {
            return false;
        }
        items = (AcPeRange *)realloc(mask->items, capacity * sizeof(AcPeRange));
        if (items == NULL) {
            return false;
        }
        mask->items = items;
        mask->capacity = capacity;
    }

    mask->items[mask->count].start = rva;
    mask->items[mask->count].end = (uint32_t)end;
    ++mask->count;
    mask->finalized = false;
    return true;
}

static int ac_pe_range_compare(const void *left, const void *right)
{
    const AcPeRange *a = (const AcPeRange *)left;
    const AcPeRange *b = (const AcPeRange *)right;

    if (a->start < b->start) {
        return -1;
    }
    if (a->start > b->start) {
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

void ac_pe_mask_finalize(AcPeMask *mask)
{
    size_t read_index;
    size_t write_index = 0;

    if (mask == NULL || mask->finalized) {
        return;
    }

    if (mask->count > 1) {
        qsort(mask->items, mask->count, sizeof(AcPeRange), ac_pe_range_compare);
    }

    for (read_index = 0; read_index < mask->count; ++read_index) {
        const AcPeRange current = mask->items[read_index];

        if (write_index > 0 && current.start <= mask->items[write_index - 1].end) {
            if (current.end > mask->items[write_index - 1].end) {
                mask->items[write_index - 1].end = current.end;
            }
            continue;
        }
        mask->items[write_index++] = current;
    }

    mask->count = write_index;
    mask->finalized = true;
}

bool ac_pe_mask_covers(const AcPeMask *mask, uint32_t rva)
{
    size_t low;
    size_t high;

    if (mask == NULL || mask->count == 0 || !mask->finalized) {
        return false;
    }

    low = 0;
    high = mask->count;
    while (low < high) {
        const size_t middle = low + (high - low) / 2u;

        if (mask->items[middle].start <= rva) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }

    return low > 0 && rva < mask->items[low - 1u].end;
}

void ac_pe_mask_zero(
    const AcPeMask *mask,
    uint8_t *buffer,
    uint32_t buffer_rva,
    uint32_t buffer_size)
{
    size_t index;

    if (mask == NULL || buffer == NULL || buffer_size == 0 || !mask->finalized) {
        return;
    }

    for (index = 0; index < mask->count; ++index) {
        const uint64_t range_start = mask->items[index].start;
        const uint64_t range_end = mask->items[index].end;
        const uint64_t window_start = buffer_rva;
        const uint64_t window_end = (uint64_t)buffer_rva + buffer_size;
        uint64_t overlap_start;
        uint64_t overlap_end;

        if (range_end <= window_start) {
            continue;
        }
        if (range_start >= window_end) {
            break;
        }

        overlap_start = range_start > window_start ? range_start : window_start;
        overlap_end = range_end < window_end ? range_end : window_end;
        memset(
            buffer + (overlap_start - window_start),
            0,
            (size_t)(overlap_end - overlap_start));
    }
}

AcPeStatus ac_pe_materialize_section(
    const AcPeImage *image,
    const AcPeSection *section,
    uint8_t *output,
    uint32_t output_size)
{
    uint32_t copy_size;

    if (image == NULL || section == NULL || output == NULL) {
        return AC_PE_ERR_MALFORMED;
    }
    if (output_size < section->virtual_size) {
        return AC_PE_ERR_MALFORMED;
    }

    memset(output, 0, output_size);

    copy_size = section->raw_size < section->virtual_size
        ? section->raw_size
        : section->virtual_size;
    if (copy_size == 0) {
        return AC_PE_OK;
    }

    if (!ac_pe_readable(image, section->raw_offset, copy_size)) {
        return AC_PE_ERR_TRUNCATED;
    }

    memcpy(output, image->data + section->raw_offset, copy_size);
    return AC_PE_OK;
}

AcPeStatus ac_pe_apply_relocations(
    const AcPeImage *image,
    const AcPeSection *section,
    uint8_t *buffer,
    int64_t delta,
    AcPeMask *mask)
{
    const AcPeDirectory *directory;
    uint32_t directory_offset;
    uint64_t cursor;
    uint64_t limit;

    if (image == NULL || section == NULL || buffer == NULL) {
        return AC_PE_ERR_MALFORMED;
    }

    directory = &image->directories[AC_PE_DIRECTORY_BASERELOC];
    if (directory->rva == 0 || directory->size == 0 || delta == 0) {
        return AC_PE_OK;
    }

    if (!ac_pe_rva_to_offset(image, directory->rva, &directory_offset)) {
        return AC_PE_ERR_MALFORMED;
    }
    if (!ac_pe_readable(image, directory_offset, directory->size)) {
        return AC_PE_ERR_TRUNCATED;
    }

    cursor = directory_offset;
    limit = (uint64_t)directory_offset + directory->size;

    while (cursor + 8u <= limit) {
        uint32_t block_rva = 0;
        uint32_t block_size = 0;
        uint64_t entry_cursor;
        uint64_t entry_limit;

        if (!ac_pe_u32_at(image->data, image->size, cursor, &block_rva) ||
            !ac_pe_u32_at(image->data, image->size, cursor + 4u, &block_size)) {
            return AC_PE_ERR_TRUNCATED;
        }
        if (block_size < 8u || (uint64_t)cursor + block_size > limit) {
            return AC_PE_ERR_MALFORMED;
        }

        entry_cursor = cursor + 8u;
        entry_limit = cursor + block_size;

        while (entry_cursor + 2u <= entry_limit) {
            uint16_t entry = 0;
            uint32_t type;
            uint32_t target_rva;
            uint32_t offset_in_section;

            if (!ac_pe_u16_at(image->data, image->size, entry_cursor, &entry)) {
                return AC_PE_ERR_TRUNCATED;
            }
            entry_cursor += 2u;

            type = (uint32_t)(entry >> 12);
            if (type == AC_PE_REL_ABSOLUTE) {
                continue;
            }

            target_rva = block_rva + (uint32_t)(entry & 0x0fffu);
            if (target_rva < section->virtual_address) {
                continue;
            }
            offset_in_section = target_rva - section->virtual_address;
            if (offset_in_section >= section->virtual_size) {
                continue;
            }

            switch (type) {
                case AC_PE_REL_HIGHLOW: {
                    uint32_t value;

                    if ((uint64_t)offset_in_section + 4u > section->virtual_size) {
                        (void)ac_pe_mask_add(mask, target_rva, 4u);
                        break;
                    }
                    value = (uint32_t)buffer[offset_in_section] |
                            ((uint32_t)buffer[offset_in_section + 1u] << 8) |
                            ((uint32_t)buffer[offset_in_section + 2u] << 16) |
                            ((uint32_t)buffer[offset_in_section + 3u] << 24);
                    value = (uint32_t)(value + (uint32_t)(int32_t)delta);
                    buffer[offset_in_section] = (uint8_t)value;
                    buffer[offset_in_section + 1u] = (uint8_t)(value >> 8);
                    buffer[offset_in_section + 2u] = (uint8_t)(value >> 16);
                    buffer[offset_in_section + 3u] = (uint8_t)(value >> 24);
                    break;
                }
                case AC_PE_REL_DIR64: {
                    uint64_t value = 0;
                    unsigned int byte_index;

                    if ((uint64_t)offset_in_section + 8u > section->virtual_size) {
                        (void)ac_pe_mask_add(mask, target_rva, 8u);
                        break;
                    }
                    for (byte_index = 0; byte_index < 8u; ++byte_index) {
                        value |= (uint64_t)buffer[offset_in_section + byte_index] <<
                                 (8u * byte_index);
                    }
                    value = (uint64_t)(value + (uint64_t)delta);
                    for (byte_index = 0; byte_index < 8u; ++byte_index) {
                        buffer[offset_in_section + byte_index] =
                            (uint8_t)(value >> (8u * byte_index));
                    }
                    break;
                }
                case AC_PE_REL_HIGH:
                case AC_PE_REL_LOW:
                    (void)ac_pe_mask_add(mask, target_rva, 2u);
                    break;
                case AC_PE_REL_HIGHADJ:
                    /* Consumes an extra entry; mask both the target and skip it. */
                    (void)ac_pe_mask_add(mask, target_rva, 4u);
                    entry_cursor += 2u;
                    break;
                default:
                    (void)ac_pe_mask_add(mask, target_rva, 8u);
                    break;
            }
        }

        cursor += block_size;
    }

    return AC_PE_OK;
}

static AcPeStatus ac_pe_mask_thunk_array(
    const AcPeImage *image,
    uint32_t table_rva,
    AcPeMask *mask)
{
    const uint32_t entry_size = image->is_64bit ? 8u : 4u;
    uint32_t index;

    if (table_rva == 0) {
        return AC_PE_OK;
    }

    for (index = 0; index < AC_PE_MAX_THUNKS; ++index) {
        const uint64_t slot_rva = (uint64_t)table_rva + (uint64_t)index * entry_size;
        uint32_t offset;
        uint64_t value = 0;

        if (slot_rva > 0xffffffffull ||
            !ac_pe_rva_to_offset(image, (uint32_t)slot_rva, &offset)) {
            break;
        }

        if (image->is_64bit) {
            if (!ac_pe_u64_at(image->data, image->size, offset, &value)) {
                break;
            }
        } else {
            uint32_t value32 = 0;

            if (!ac_pe_u32_at(image->data, image->size, offset, &value32)) {
                break;
            }
            value = value32;
        }

        if (value == 0) {
            break;
        }
        if (!ac_pe_mask_add(mask, (uint32_t)slot_rva, entry_size)) {
            return AC_PE_ERR_NO_MEMORY;
        }
    }

    return AC_PE_OK;
}

AcPeStatus ac_pe_mask_import_tables(const AcPeImage *image, AcPeMask *mask)
{
    const AcPeDirectory *iat;
    const AcPeDirectory *import;
    const AcPeDirectory *delay;
    uint32_t index;

    if (image == NULL || mask == NULL) {
        return AC_PE_ERR_MALFORMED;
    }

    iat = &image->directories[AC_PE_DIRECTORY_IAT];
    if (iat->rva != 0 && iat->size != 0) {
        if (!ac_pe_mask_add(mask, iat->rva, iat->size)) {
            return AC_PE_ERR_NO_MEMORY;
        }
    }

    import = &image->directories[AC_PE_DIRECTORY_IMPORT];
    if (import->rva != 0 && import->size != 0) {
        for (index = 0; index < AC_PE_MAX_DESCRIPTORS; ++index) {
            const uint64_t descriptor_rva =
                (uint64_t)import->rva + (uint64_t)index * AC_PE_IMPORT_DESCRIPTOR_SIZE;
            uint32_t offset;
            uint32_t name_rva = 0;
            uint32_t first_thunk = 0;

            if (descriptor_rva > 0xffffffffull ||
                !ac_pe_rva_to_offset(image, (uint32_t)descriptor_rva, &offset)) {
                break;
            }
            if (!ac_pe_u32_at(image->data, image->size, offset + 12u, &name_rva) ||
                !ac_pe_u32_at(image->data, image->size, offset + 16u, &first_thunk)) {
                break;
            }
            if (name_rva == 0 && first_thunk == 0) {
                break;
            }

            if (ac_pe_mask_thunk_array(image, first_thunk, mask) == AC_PE_ERR_NO_MEMORY) {
                return AC_PE_ERR_NO_MEMORY;
            }
        }
    }

    delay = &image->directories[AC_PE_DIRECTORY_DELAY_IMPORT];
    if (delay->rva != 0 && delay->size != 0) {
        for (index = 0; index < AC_PE_MAX_DESCRIPTORS; ++index) {
            const uint64_t descriptor_rva =
                (uint64_t)delay->rva + (uint64_t)index * AC_PE_DELAY_DESCRIPTOR_SIZE;
            uint32_t offset;
            uint32_t name_rva = 0;
            uint32_t module_handle = 0;
            uint32_t delay_iat = 0;

            if (descriptor_rva > 0xffffffffull ||
                !ac_pe_rva_to_offset(image, (uint32_t)descriptor_rva, &offset)) {
                break;
            }
            if (!ac_pe_u32_at(image->data, image->size, offset + 4u, &name_rva) ||
                !ac_pe_u32_at(image->data, image->size, offset + 8u, &module_handle) ||
                !ac_pe_u32_at(image->data, image->size, offset + 12u, &delay_iat)) {
                break;
            }
            if (name_rva == 0 && delay_iat == 0) {
                break;
            }

            if (module_handle != 0 &&
                !ac_pe_mask_add(mask, module_handle, image->is_64bit ? 8u : 4u)) {
                return AC_PE_ERR_NO_MEMORY;
            }
            if (ac_pe_mask_thunk_array(image, delay_iat, mask) == AC_PE_ERR_NO_MEMORY) {
                return AC_PE_ERR_NO_MEMORY;
            }
        }
    }

    return AC_PE_OK;
}

static AcPeStatus ac_pe_visit_thunk_array(
    const AcPeImage *image,
    uint32_t table_rva,
    bool delay_load,
    AcPeIatVisitor visitor,
    void *user,
    bool *stop)
{
    const uint32_t entry_size = image->is_64bit ? 8u : 4u;
    uint32_t index;

    if (table_rva == 0) {
        return AC_PE_OK;
    }

    for (index = 0; index < AC_PE_MAX_THUNKS; ++index) {
        const uint64_t slot_rva = (uint64_t)table_rva + (uint64_t)index * entry_size;
        uint32_t offset;
        uint64_t value = 0;

        if (slot_rva > 0xffffffffull ||
            !ac_pe_rva_to_offset(image, (uint32_t)slot_rva, &offset)) {
            break;
        }

        if (image->is_64bit) {
            if (!ac_pe_u64_at(image->data, image->size, offset, &value)) {
                break;
            }
        } else {
            uint32_t value32 = 0;

            if (!ac_pe_u32_at(image->data, image->size, offset, &value32)) {
                break;
            }
            value = value32;
        }

        if (value == 0) {
            break;
        }
        if (!visitor(user, (uint32_t)slot_rva, delay_load)) {
            *stop = true;
            return AC_PE_OK;
        }
    }

    return AC_PE_OK;
}

AcPeStatus ac_pe_for_each_iat_slot(
    const AcPeImage *image,
    AcPeIatVisitor visitor,
    void *user)
{
    const AcPeDirectory *import;
    const AcPeDirectory *delay;
    bool stop = false;
    uint32_t index;

    if (image == NULL || visitor == NULL) {
        return AC_PE_ERR_MALFORMED;
    }

    import = &image->directories[AC_PE_DIRECTORY_IMPORT];
    if (import->rva != 0 && import->size != 0) {
        for (index = 0; index < AC_PE_MAX_DESCRIPTORS && !stop; ++index) {
            const uint64_t descriptor_rva =
                (uint64_t)import->rva + (uint64_t)index * AC_PE_IMPORT_DESCRIPTOR_SIZE;
            uint32_t offset;
            uint32_t name_rva = 0;
            uint32_t first_thunk = 0;

            if (descriptor_rva > 0xffffffffull ||
                !ac_pe_rva_to_offset(image, (uint32_t)descriptor_rva, &offset)) {
                break;
            }
            if (!ac_pe_u32_at(image->data, image->size, offset + 12u, &name_rva) ||
                !ac_pe_u32_at(image->data, image->size, offset + 16u, &first_thunk)) {
                break;
            }
            if (name_rva == 0 && first_thunk == 0) {
                break;
            }

            (void)ac_pe_visit_thunk_array(image, first_thunk, false, visitor, user, &stop);
        }
    }

    delay = &image->directories[AC_PE_DIRECTORY_DELAY_IMPORT];
    if (delay->rva != 0 && delay->size != 0) {
        for (index = 0; index < AC_PE_MAX_DESCRIPTORS && !stop; ++index) {
            const uint64_t descriptor_rva =
                (uint64_t)delay->rva + (uint64_t)index * AC_PE_DELAY_DESCRIPTOR_SIZE;
            uint32_t offset;
            uint32_t name_rva = 0;
            uint32_t delay_iat = 0;

            if (descriptor_rva > 0xffffffffull ||
                !ac_pe_rva_to_offset(image, (uint32_t)descriptor_rva, &offset)) {
                break;
            }
            if (!ac_pe_u32_at(image->data, image->size, offset + 4u, &name_rva) ||
                !ac_pe_u32_at(image->data, image->size, offset + 12u, &delay_iat)) {
                break;
            }
            if (name_rva == 0 && delay_iat == 0) {
                break;
            }

            (void)ac_pe_visit_thunk_array(image, delay_iat, true, visitor, user, &stop);
        }
    }

    return AC_PE_OK;
}

AcPeStatus ac_pe_export_functions(
    const AcPeImage *image,
    uint32_t *table_rva_out,
    uint32_t *count_out)
{
    const AcPeDirectory *directory;
    uint32_t offset;
    uint32_t count = 0;
    uint32_t table_rva = 0;

    if (image == NULL || table_rva_out == NULL || count_out == NULL) {
        return AC_PE_ERR_MALFORMED;
    }
    *table_rva_out = 0;
    *count_out = 0;

    directory = &image->directories[AC_PE_DIRECTORY_EXPORT];
    if (directory->rva == 0 || directory->size < AC_PE_EXPORT_DIRECTORY_SIZE) {
        return AC_PE_OK;
    }

    if (!ac_pe_rva_to_offset(image, directory->rva, &offset)) {
        return AC_PE_ERR_MALFORMED;
    }
    if (!ac_pe_u32_at(image->data, image->size, offset + 20u, &count) ||
        !ac_pe_u32_at(image->data, image->size, offset + 28u, &table_rva)) {
        return AC_PE_ERR_TRUNCATED;
    }

    if (count == 0 || table_rva == 0) {
        return AC_PE_OK;
    }
    if ((uint64_t)count * 4u > 0xffffffffull ||
        (uint64_t)table_rva + (uint64_t)count * 4u > image->size_of_image) {
        return AC_PE_ERR_MALFORMED;
    }

    *table_rva_out = table_rva;
    *count_out = count;
    return AC_PE_OK;
}
