#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "config.h"
#define LIBSSH_STATIC
#include <libssh/priv.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "channels.c"

static void test_my_ssh_channel_is_open(void **state) {
    ssh_channel channel;
    int result;
    (void)state;
    
    channel = ssh_channel_new(NULL);
    

    result = ssh_channel_is_open(channel);

    assert_int_equal(result, 0);

    ssh_channel_free(channel);
}

static void test_my_ssh_channel_is_close(void **state) {
    ssh_channel channel;
    int result;
    (void)state;

    channel = ssh_channel_new(NULL);

    result = ssh_channel_is_closed(channel);

    assert_int_equal(result, SSH_ERROR);

    ssh_channel_free(channel);
}

int main(void) {
    int ret;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_my_ssh_channel_is_open),
        cmocka_unit_test(test_my_ssh_channel_is_close),
    };
    ssh_init();
    ret = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return ret;
}
