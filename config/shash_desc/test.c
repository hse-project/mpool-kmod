#include "../test.h"
#include <crypto/hash.h>

int
test(void)
{
	SHASH_DESC_ON_STACK(desc, NULL);

    desc->flags = 0;

    return desc->flags;
}
