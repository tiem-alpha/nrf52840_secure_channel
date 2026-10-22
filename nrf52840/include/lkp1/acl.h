#ifndef LKP1_ACL_H
#define LKP1_ACL_H
#include <stddef.h>
#include <stdint.h>

/* A fixed factory allowlist for the prototype. Product revocation and
 * enrollment policy require a separate authenticated management flow. */
int lkp1_acl_contains(const uint8_t subject_id[16],
                       const uint8_t (*allowed_ids)[16], size_t count);
#endif
