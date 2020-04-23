#ifndef macho_h
#define macho_h

#import <stdio.h>
#import <stdbool.h>
#include <mach-o/loader.h>

#include "cs_magic.h"


uint32_t get_image_count(void);
const char *get_image_name(uint32_t image_no);
const struct mach_header *get_mach_header(uint32_t image_no);
const uint8_t *get_uuid(const struct mach_header *mach_hdr);
bool is_main(const struct mach_header *mach_hdr);

uint32_t get_load_command_count(const struct mach_header *mach_hdr);
const struct load_command **get_load_commands(const struct mach_header *mach_hdr);

uint32_t get_load_command_count_by_type(const struct mach_header *mach_hdr, uint32_t type);
const struct load_command **get_load_commands_by_type(const struct mach_header *mach_hdr, uint32_t type);

char *get_embedded_entitlements_plist(const struct mach_header *mach_hdr);
bool validate_embedded_entitlements_plist(const struct mach_header *mach_hdr);

uint8_t *get_entitlements_blob(const struct mach_header *mach_hdr);
CS_Digest get_entitlements_digest(const struct mach_header *mach_hdr);

void get_specialslots(void);
void get_codeslots(void);
void get_signing(void);

void validate_codeslot(int slot);
void validate_codeslots(void);

#endif /* macho_h */
