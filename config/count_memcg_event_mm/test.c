#include "../test.h"
#include <linux/memcontrol.h>

int
test(void)
{
    count_memcg_event_mm(NULL, 0);

    return 0;
}
