#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <moto_rt.h>

int main(void) {
    char path[4096];
    size_t size = sizeof(path);
    assert(moto_rt_exepath((uint8_t *)path, &size) == 0);
    assert(path[0] == '/' && size == strlen(path));
    assert(size >= strlen("/exepath-buffer"));
    assert(!strcmp(path + size - strlen("/exepath-buffer"), "/exepath-buffer"));

    char tiny[2] = {'x', 'y'};
    size = 1;
    assert(moto_rt_exepath((uint8_t *)tiny, &size) == -MOTO_E_INVALID_ARGUMENT);
    assert(size == 1 && tiny[0] == 'x' && tiny[1] == 'y');
    size = 0;
    assert(moto_rt_exepath((uint8_t *)tiny, &size) == -MOTO_E_INVALID_ARGUMENT);
    assert(size == 0 && tiny[0] == 'x' && tiny[1] == 'y');
    assert(moto_rt_exepath(NULL, &size) == -MOTO_E_INVALID_ARGUMENT);
    assert(moto_rt_exepath((uint8_t *)tiny, NULL) == -MOTO_E_INVALID_ARGUMENT);
    puts("quickjs executable-path buffers: PASS");
    return 0;
}
