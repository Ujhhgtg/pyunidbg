typedef unsigned long size_t;

size_t strlen(const char *value) {
    size_t size = 0;
    while (value[size] != '\0') {
        size++;
    }
    return size;
}

int __system_property_get(const char *name, char *value) {
    (void) name;
    value[0] = '\0';
    return 0;
}
