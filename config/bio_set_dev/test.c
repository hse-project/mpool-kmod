#include "../test.h"
#include <linux/bio.h>

int
test(void)
{
    struct block_device *bdev = (void *)1;
    struct bio *bio = (void *)1;

    bio_set_dev(bio, bdev);

    return 0;
}
