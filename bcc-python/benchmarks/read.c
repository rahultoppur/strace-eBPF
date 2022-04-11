#include <stdio.h>
#include <unistd.h>

/* Source: https://github.com/arkanis/syscall-benchmark/blob/master/12_read_stdio.c */

/* Read intensive syscalls */

int main() {
    FILE* file = fopen("/dev/zero", "r");
    int data = 0;
    //for (ssize_t i = 1000000000; i > 0; i--) {
    for (ssize_t i = 100000000; i > 0; i--) {
        fread(&data, sizeof(data), 1, file);
    }
    fclose(file);
    return 0;
}
