#include "../test.h"

vm_fault_t x = 0;

int
test(void)
{
    return sizeof(x);
}
