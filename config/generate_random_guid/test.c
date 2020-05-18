#include "../test.h"
#include <linux/uuid.h>

int
test(unsigned char uuid[16])
{
	generate_random_guid(uuid);

    return 0;
}
