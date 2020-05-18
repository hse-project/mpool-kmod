#include "../test.h"
#include <linux/uio.h>

int
test(void)
{
    return iov_iter_get_pages(NULL, NULL, 0, 0, NULL);
}
