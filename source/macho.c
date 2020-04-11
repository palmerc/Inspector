#include "macho.h"

#include <mach-o/dyld.h>
#include <mach-o/ldsyms.h>

#include <CommonCrypto/CommonDigest.h>

#include <stdbool.h>
#include <string.h>

#include "load_commands.h"
#include "cs_magic.h"
#include "utils.h"


#define PRINT_STR "%s section: addr 0x%x, size %u, offset 0x%x, calc address 0x%lx\n"
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))


bool is_magic_64(uint32_t magic) {
  return magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
}

bool should_swap_bytes(uint32_t magic) {
  return magic == MH_CIGAM || magic == MH_CIGAM_64;
}

struct _cpu_type_names {
    cpu_type_t cputype;
    const char *cpu_name; /* FIXME: -Wpadded from clang */
};

static struct _cpu_type_names cpu_type_names[] = {
    { CPU_TYPE_I386, "i386" },
    { CPU_TYPE_X86_64, "x86_64" },
    { CPU_TYPE_ARM, "arm" },
    { CPU_TYPE_ARM64, "arm64" }
};

static const char *cpu_type_name(cpu_type_t cpu_type) {
    static int cpu_type_names_size = sizeof(cpu_type_names) / sizeof(struct _cpu_type_names);
    for (int i = 0; i < cpu_type_names_size; i++ ) {
        if (cpu_type == cpu_type_names[i].cputype) {
            return cpu_type_names[i].cpu_name;
        }
    }
    
    return "unknown";
}




uint32_t get_image_count() {
    return _dyld_image_count();
}

const char *get_name(uint32_t image_no) {
    return _dyld_get_image_name(image_no);
}

const struct mach_header *get_mach_header(uint32_t image_no) {
    return _dyld_get_image_header(image_no);
}

bool is_main(const struct mach_header *mach_hdr) {
    uint32_t command_count = get_load_command_count_by_type(mach_hdr, LC_MAIN);
    return command_count > 0;
}

bool is_codesigned(const struct mach_header *mach_hdr) {
    uint32_t command_count = get_load_command_count_by_type(mach_hdr, LC_CODE_SIGNATURE);
    return command_count > 0;
}

const uint8_t *get_uuid(const struct mach_header *mach_hdr) {
    uint32_t command_count = get_load_command_count_by_type(mach_hdr, LC_UUID);
    const struct load_command **load_commands = get_load_commands_by_type(mach_hdr, LC_UUID);
    for (int i = 0; i < command_count;) {
        return ((const struct uuid_command *)load_commands[i])->uuid;
    }
    free(load_commands);

    return NULL;
}

uint32_t get_load_command_count(const struct mach_header *mach_hdr) {
    if (mach_hdr == NULL) return 0;

    return mach_hdr->ncmds;
}


const struct load_command *get_first_load_command(const struct mach_header *mach_hdr) {
    if (mach_hdr == NULL) return NULL;
    
    size_t header_size;
    if (is_magic_64(mach_hdr->magic)) {
        header_size = sizeof(struct mach_header_64);
    } else {
        header_size = sizeof(struct mach_header);
    }
    
    void *start = (void *)mach_hdr + header_size;
    return (struct load_command *)start;
}

const struct load_command **get_load_commands(const struct mach_header *mach_hdr) {
    uint32_t command_count = get_load_command_count(mach_hdr);
    void *next_record = (void *)get_first_load_command(mach_hdr);

    const struct load_command **load_commands = malloc(command_count * sizeof(struct load_command *));
    for (int i = 0; i < command_count; i++) {
        const struct load_command *cmd = (struct load_command *)next_record;
        load_commands[i] = cmd;
        next_record += cmd->cmdsize;
    }

    return load_commands;
}

uint32_t get_load_command_count_by_type(const struct mach_header *mach_hdr, uint32_t type) {
    uint32_t count = 0;
    
    uint32_t command_count = get_load_command_count(mach_hdr);
    const struct load_command **load_commands = get_load_commands(mach_hdr);
    for (int i = 0; i < command_count; i++) {
        const struct load_command *cmd = load_commands[i];
        if (cmd->cmd == type) {
            count++;
        }
    }
    free(load_commands);
    
    return count;
}

const struct load_command **get_load_commands_by_type(const struct mach_header *mach_hdr, uint32_t type) {
    uint32_t command_count = get_load_command_count(mach_hdr);
    const struct load_command **load_commands = get_load_commands(mach_hdr);
    uint32_t type_count = get_load_command_count_by_type(mach_hdr, type);
    const struct load_command **type_commands = malloc(type_count * sizeof(struct load_command *));
    uint32_t type_index = 0;
    for (int i = 0; i < command_count; i++) {
        const struct load_command *cmd = load_commands[i];
        if (cmd->cmd == type) {
            type_commands[type_index] = cmd;
            type_index++;
        }
    }
    free(load_commands);
    
    return type_commands;
}

uint8_t *get_cs_blob_by_magic(const struct mach_header *mach_hdr, enum cs_magic magic) {
    uint32_t command_count = get_load_command_count_by_type(mach_hdr, LC_CODE_SIGNATURE);
    if (command_count > 0) {
        const struct load_command **load_commands = get_load_commands_by_type(mach_hdr, LC_CODE_SIGNATURE);
        for (int i = 0; i < command_count; i++) {
            const struct linkedit_data_command *data_command = (const struct linkedit_data_command *) load_commands[i];
            uint32_t signature_offset = data_command->dataoff;

            uint8_t *lc_code_signature = (uint8_t *) mach_hdr + signature_offset;
            CS_SuperBlob *super_blob = (CS_SuperBlob *) lc_code_signature;
            if (ntohl(super_blob->magic) == CSMAGIC_EMBEDDED_SIGNATURE) {
                uint32_t blob_count = ntohl(super_blob->count);
                for (int i = 0; i < blob_count; i++) {
                    uint32_t blob_offset = ntohl(super_blob->index[i].offset);
                    uint8_t *blob_bytes = lc_code_signature + blob_offset;
                    CS_Blob *blob = (CS_Blob *) blob_bytes;
                    uint32_t blob_magic = ntohl(blob->magic);
                    if (blob_magic == magic) {
                        return blob_bytes;
                    }
                }
            }
        }
    }

    return NULL;
}

uint8_t *get_entitlements_blob(const struct mach_header *mach_hdr) {
    return get_cs_blob_by_magic(mach_hdr,CSMAGIC_ENTITLEMENTS);
}

char *get_embedded_entitlements_plist(const struct mach_header *mach_hdr) {
    char *plist = NULL;

    CS_Blob *blob = (CS_Blob *)get_entitlements_blob(mach_hdr);
    if (blob != NULL) {
        uint32_t plist_length = ntohl(blob->length) - 8;
        plist = malloc(sizeof(char) * (plist_length + 1));
        memset(plist, 0, plist_length);
        memcpy(plist, blob->bytes, plist_length);
    }
    
    return plist;
}

CS_Digest get_cd_slot_by_index(uint8_t *blob_bytes, int32_t index) {
    CS_Digest digest = {.type = 0, .length = 0, .bytes = NULL};

    const CS_CodeDirectory *cd = (const CS_CodeDirectory *)blob_bytes;
    if (cd != NULL) {
        digest.type = cd->hashType;
        digest.length = cd->hashSize;
        digest.bytes = blob_bytes + ntohl(cd->hashOffset) + (index * cd->hashSize);
    }

    return digest;
}

CS_Digest get_cd_special_slot_by_id(const struct mach_header *mach_hdr, enum ss_id id) {
    uint8_t *blob_bytes = get_cs_blob_by_magic(mach_hdr, CSMAGIC_CODEDIRECTORY);
    return get_cd_slot_by_index(blob_bytes, id - SPECIALSLOT_INDEX_END);
}

CS_Digest get_entitlements_digest(const struct mach_header *mach_hdr) {
    return get_cd_special_slot_by_id(mach_hdr, SPECIALSLOT_ENTITLEMENT);
}

bool validate_embedded_entitlements_plist(const struct mach_header *mach_hdr) {
    uint8_t *blob_bytes = get_entitlements_blob(mach_hdr);
    if (blob_bytes == NULL) return false;
    
    CS_Blob *blob_struct = (CS_Blob *)blob_bytes;
    uint32_t blob_length = ntohl(blob_struct->length);
    CS_Digest entitlements_digest = get_entitlements_digest(mach_hdr);
    switch (entitlements_digest.type) {
        case 1:
        {
            unsigned char sha1_digest[CC_SHA1_DIGEST_LENGTH];
            CC_SHA1(blob_bytes, blob_length, sha1_digest);
            return (memcmp(entitlements_digest.bytes, sha1_digest, CC_SHA1_DIGEST_LENGTH) == 0);
        }
        case 2:
        {
            unsigned char sha256_digest[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(blob_bytes, blob_length, sha256_digest);
            return (memcmp(entitlements_digest.bytes, sha256_digest, CC_SHA256_DIGEST_LENGTH) == 0);
        }
    }
    
    return false;
}
