#include "cs_magic.h"


char *specialslot_name(uint8_t ss_index) {
    switch (ss_index) {
        case SPECIALSLOT_ENTITLEMENT: return "SPECIALSLOT_ENTITLEMENT";
        case SPECIALSLOT_APP_SPECIFIC: return "SPECIALSLOT_APP_SPECIFIC";
        case SPECIALSLOT_CODE_RESOURCES: return "SPECIALSLOT_CODE_RESOURCES";
        case SPECIALSLOT_INTERNAL_REQUIREMENTS: return "SPECIALSLOT_INTERNAL_REQUIREMENTS";
        case SPECIALSLOT_BOUND_PLIST: return "SPECIALSLOT_BOUND_PLIST";
        default: return NULL;
    }
}
