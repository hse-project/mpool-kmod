#include "../test.h"
#include <linux/bio.h>

int
test(void)
{
    return bioset_create(NULL, 0, 0) ? 0 : -EINVAL;
}
