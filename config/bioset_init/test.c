#include "../test.h"
#include <linux/bio.h>

int
test(void)
{
    return bioset_init(NULL, 0, 0, 0);

}
