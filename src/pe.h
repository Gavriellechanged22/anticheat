#ifndef AC_PE_H
#define AC_PE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AC_PE_MAX_SECTIONS 96u
#define AC_PE_DIRECTORY_COUNT 16u
#define AC_PE_SECTION_NAME_SIZE 9u

#define AC_PE_DIRECTORY_EXPORT 0u
#define AC_PE_DIRECTORY_IMPORT 1u
#define AC_PE_DIRECTORY_BASERELOC 5u
#define AC_PE_DIRECTORY_IAT 12u
#define AC_PE_DIRECTORY_DELAY_IMPORT 13u

#define AC_PE_SCN_CNT_CODE 0x00000020u
#define AC_PE_SCN_MEM_EXECUTE 0x20000000u
#define AC_PE_SCN_MEM_WRITE 0x80000000u

typedef enum AcPeStatus {
    AC_PE_OK = 0,
    AC_PE_ERR_TRUNCATED,
    AC_PE_ERR_NOT_PE,
    AC_PE_ERR_UNSUPPORTED,
    AC_PE_ERR_MALFORMED,
    AC_PE_ERR_NO_MEMORY
} AcPeStatus;

typedef struct AcPeSection {
    char name[AC_PE_SECTION_NAME_SIZE];
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
} AcPeSection;

typedef struct AcPeDirectory {
    uint32_t rva;
    uint32_t size;
} AcPeDirectory;

typedef struct AcPeImage {
    const uint8_t *data;
    size_t size;
    bool is_64bit;
    uint16_t machine;
    uint16_t section_count;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t entry_point;
    uint64_t image_base;
    AcPeSection sections[AC_PE_MAX_SECTIONS];
    AcPeDirectory directories[AC_PE_DIRECTORY_COUNT];
} AcPeImage;

typedef struct AcPeRange {
    uint32_t start;
    uint32_t end;
} AcPeRange;

/* Sorted, merged set of RVA ranges excluded from integrity comparison. */
typedef struct AcPeMask {
    AcPeRange *items;
    size_t count;
    size_t capacity;
    bool finalized;
} AcPeMask;

const char *ac_pe_status_name(AcPeStatus status);

AcPeStatus ac_pe_parse(const uint8_t *data, size_t size, AcPeImage *image);
bool ac_pe_section_is_executable(const AcPeSection *section);
const AcPeSection *ac_pe_find_section_by_rva(const AcPeImage *image, uint32_t rva);
bool ac_pe_rva_to_offset(const AcPeImage *image, uint32_t rva, uint32_t *offset_out);
bool ac_pe_read_u32_rva(const AcPeImage *image, uint32_t rva, uint32_t *value_out);

void ac_pe_mask_init(AcPeMask *mask);
void ac_pe_mask_free(AcPeMask *mask);
void ac_pe_mask_clear(AcPeMask *mask);
bool ac_pe_mask_add(AcPeMask *mask, uint32_t rva, uint32_t size);
void ac_pe_mask_finalize(AcPeMask *mask);
bool ac_pe_mask_covers(const AcPeMask *mask, uint32_t rva);
void ac_pe_mask_zero(
    const AcPeMask *mask,
    uint8_t *buffer,
    uint32_t buffer_rva,
    uint32_t buffer_size);

/* Reconstruct the bytes the loader is expected to place at a section's RVA. */
AcPeStatus ac_pe_materialize_section(
    const AcPeImage *image,
    const AcPeSection *section,
    uint8_t *output,
    uint32_t output_size);

/* Rebase a materialized section. Relocation forms this build cannot apply are
   added to `mask` so they are excluded from comparison instead of misreported. */
AcPeStatus ac_pe_apply_relocations(
    const AcPeImage *image,
    const AcPeSection *section,
    uint8_t *buffer,
    int64_t delta,
    AcPeMask *mask);

/* Exclude loader-populated import address tables from comparison. */
AcPeStatus ac_pe_mask_import_tables(const AcPeImage *image, AcPeMask *mask);

typedef bool (*AcPeIatVisitor)(void *user, uint32_t slot_rva, bool delay_load);
AcPeStatus ac_pe_for_each_iat_slot(
    const AcPeImage *image,
    AcPeIatVisitor visitor,
    void *user);

AcPeStatus ac_pe_export_functions(
    const AcPeImage *image,
    uint32_t *table_rva_out,
    uint32_t *count_out);

#endif
