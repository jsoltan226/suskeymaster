#include <stdatomic.h>

int util_atomic_load_int(const _Atomic int *a)
{
    return atomic_load(a);
}

void util_atomic_store_int(_Atomic int *a, int value)
{
    atomic_store(a, value);
}
