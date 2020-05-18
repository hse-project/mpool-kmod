#include "../test.h"
#include <linux/blkdev.h>

int
test(void)
{
    return blkdev_issue_zeroout((struct block_device *)NULL, 0, 0, 0, 0);
}
