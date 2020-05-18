#include "../test.h"
#include <linux/bio.h>

int
test(void)
{
    submit_bio(NULL);

    return 0;
}
