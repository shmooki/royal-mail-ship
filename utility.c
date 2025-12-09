#include <stdio.h>
#include <stdlib.h>
#include "utility.h"

void flush_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

uint64_t generate_uuid(int length) {
    uint64_t uuid = 0;
    for (int i = 0; i < length; i++) {
        uuid = uuid * 10 + (rand() % 10);
    }

    return uuid;
}