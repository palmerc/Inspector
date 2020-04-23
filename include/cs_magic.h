#ifndef cs_magic_h
#define cs_magic_h

#include <stdlib.h>


enum cs_magic {
    CSMAGIC_BLOBWRAPPER = 0xfade0b01,
    CSMAGIC_REQUIREMENT = 0xfade0c00,       /* single Requirement blob */
    CSMAGIC_REQUIREMENTS = 0xfade0c01,      /* Requirements vector (internal requirements) */
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,     /* CodeDirectory blob */
    CSMAGIC_ENTITLEMENTS = 0xfade7171,
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */

    CSSLOT_CODEDIRECTORY = 0,               /* slot index for CodeDirectory */
};

enum ss_id {
    SPECIALSLOT_ENTITLEMENT = 0,
    SPECIALSLOT_APP_SPECIFIC,
    SPECIALSLOT_CODE_RESOURCES,
    SPECIALSLOT_INTERNAL_REQUIREMENTS,
    SPECIALSLOT_BOUND_PLIST,
    SPECIALSLOT_INDEX_END
};

/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
    uint32_t magic;                 /* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;                /* total length of CodeDirectory blob */
    uint32_t version;               /* compatibility version */
    uint32_t flags;                 /* setup and mode flags */
    uint32_t hashOffset;            /* offset of hash slot element at index zero */
    uint32_t identOffset;           /* offset of identifier string */
    uint32_t nSpecialSlots;         /* number of special hash slots */
    uint32_t nCodeSlots;            /* number of ordinary (code) hash slots */
    uint32_t codeLimit;             /* limit to main image signature range */
    uint8_t hashSize;               /* size of each hash in bytes */
    uint8_t hashType;               /* type of hash (cdHashType* constants) */
    uint8_t spare1;                 /* unused (must be zero) */
    uint8_t pageSize;               /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;                /* unused (must be zero) */
    /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

typedef struct __BlobIndex {
    uint32_t type;                   /* type of entry */
    uint32_t offset;                 /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;                  /* magic number */
    uint32_t length;                 /* total length of SuperBlob */
    uint32_t count;                  /* number of index entries following */
    CS_BlobIndex index[];                 /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;

typedef struct __Blob {
    uint32_t magic;
    uint32_t length;
    uint8_t bytes[];
} CS_Blob;

typedef struct __Digest {
    uint32_t type;
    uint32_t length;
    uint8_t *bytes;
} CS_Digest;

char *specialslot_name(uint8_t ss_index);

#endif /* cs_magic_h */
