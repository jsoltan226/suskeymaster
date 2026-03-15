#include <stdatomic.h>

int do_atomic_load_int(const _Atomic int *a)
{
    return atomic_load(a);
}

void do_atomic_store_int(_Atomic int *a, int value)
{
    atomic_store(a, value);
}
