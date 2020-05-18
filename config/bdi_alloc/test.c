#include "../test.h"
#include <linux/backing-dev.h>

int
test(void)
{
    return bdi_alloc(0) ? 0 : -EINVAL;
}
