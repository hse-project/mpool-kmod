#include "../test.h"
#include <linux/bio.h>

int
test(void)
{
    bio_set_op_attrs(NULL, 0, 0);

    return 0;
}
