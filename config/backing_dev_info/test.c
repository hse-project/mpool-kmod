#include "../test.h"
#include <linux/fs.h>

int
test(void)
{
    struct address_space m = { .backing_dev_info = NULL, };

    return m.backing_dev_info ? 0 : -EINVAL;
}
