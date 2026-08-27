#include <stdint.h>

__attribute__((visibility("default")))
int64_t add_numbers(int64_t left, int64_t right) {
    return left + right;
}

__attribute__((visibility("default")))
int64_t read_number(const int64_t *value) {
    return *value;
}

__attribute__((visibility("default")))
void write_number(int64_t *target, int64_t value) {
    *target = value;
}

extern uint64_t strlen(const char *value);

__attribute__((visibility("default")))
uint64_t call_strlen(const char *value) {
    return strlen(value);
}

extern int64_t dep_value(void);

__attribute__((visibility("default")))
int64_t call_dependency(void) {
    return dep_value();
}

extern int __system_property_get(const char *name, char *value);

__attribute__((visibility("default")))
int64_t call_system_property(const char *name, char *value) {
    return __system_property_get(name, value);
}
