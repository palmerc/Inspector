#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <Inspector.h>
#include "utils.h"
#include "load_commands.h"


int main(int argc, const char * argv[]) {
    const struct mach_header *mach_hdr = get_mach_header(0);
    const struct load_command **load_commands = get_load_commands(mach_hdr);
    for (int i = 0; i < get_load_command_count(mach_hdr); i++) {
        const struct load_command *load_command = load_commands[i];
        printf("%s\n", lc_lookup_by_value(load_command->cmd));
    }
    free(load_commands);

    printf("UUID: ");
    char *uuid = format_canonical_uuid(get_uuid(mach_hdr));
    printf("%s\n", uuid);
    free(uuid);

    printf("Plist: ");
    char *entitlements_plist = get_embedded_entitlements_plist(mach_hdr);
    printf("%s\n", entitlements_plist);
    free(entitlements_plist);
    
    CS_Digest digest = get_entitlements_digest(mach_hdr);
    char *hex_digest = format_bytes_as_hex(digest.bytes, digest.length);
    printf("Digest: %s\n", hex_digest);
    free(hex_digest);
    
    printf("Embedded plist: ");
    if (validate_embedded_entitlements_plist(mach_hdr)) {
        printf("valid\n");
    } else {
        printf("invalid\n");
    }
    
    return 0;
}
