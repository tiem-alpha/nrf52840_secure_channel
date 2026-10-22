#include "lkp1/acl.h"
#include "lkp1/crypto.h"

int lkp1_acl_contains(const uint8_t subject_id[16],
                       const uint8_t (*allowed_ids)[16], size_t count)
{
    int found = 0;
    if (subject_id == NULL || allowed_ids == NULL || count > 8) {
        return 0;
    }
    for (size_t i = 0; i < count; i++) {
        found |= lkp1_constant_time_equal(subject_id, allowed_ids[i], 16);
    }
    return found;
}
