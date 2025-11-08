#include <stdio.h>

int func(int num) {
    volatile int x = num * num;
    return x;
}

void omain() {
    int ret = func(4);
    printf("Ret: %d\n", ret);
}

void nmain() {
    printf("Ret: %d\n", func(5));
}

int main() {
    omain();
    nmain();
}
