#include "../test.h"
#include <linux/uio.h>

int
test(void)
{
    iov_iter_init(NULL, 0, NULL, 0, 0);

    return 0;
}
