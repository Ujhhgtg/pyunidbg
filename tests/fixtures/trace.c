#include <stdint.h>

__attribute__((visibility("default")))
int64_t traced_add(int64_t left, int64_t right) {
    return left + right;
}
