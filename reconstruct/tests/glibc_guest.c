#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *buffer = malloc(32);
    if (!buffer) {
        return 2;
    }
    strcpy(buffer, "attesor");
    char *grown = realloc(buffer, 4096);
    if (!grown) {
        free(buffer);
        return 3;
    }

    void *library = dlopen("libattesor_glibc_fixture.so", RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "%s\n", dlerror());
        free(grown);
        return 4;
    }
    int (*add)(int) = (int (*)(int))dlsym(library, "attesor_fixture_add");
    if (!add) {
        dlclose(library);
        free(grown);
        return 5;
    }
    printf("%s:%d\n", grown, add((int)strlen(grown)));
    dlclose(library);
    free(grown);
    return 0;
}
