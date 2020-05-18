#include "../test.h"
#include <linux/memcontrol.h>

int
test(void)
{
    mem_cgroup_count_vm_event((struct mm_struct *)NULL, 0);

    return 0;
}
