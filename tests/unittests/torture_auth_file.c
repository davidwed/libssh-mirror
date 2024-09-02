#include "libssh/libssh.h"
#include "libssh/auth_options.h"
#include "auth_file.c"
#include "torture.h"

#define USER_CA_KEY "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVP5D0py0vKPUdROCegYGkxfARTlu6WDf16Ld1j9Lg9IZ+pdL9X3OT4+vDIPk5bzvewDyQAdNyuITTdy2gK94Br8C7IaHG3K77k4kDGosyJHcK9WnfV98o+hfvmb8KA6PKdduRkGPEZI93ezGqGTPAOb3mYcbVOY/KzzA31QkRro820r0Ff564p94tjCh8WvLGJWmqG8rIpolyAZO5WS9J7XcS/lztQlnLXVZYjkvByhBFqn6iBND88fj0NNzhF4OThUwRkdVsSDdio6tSdb4brVionPp17Lg8rLh7WO/vPhjXMt34A7uuxsYKdxyOZBMGnMrkZI0gPlpLB6MhSLYp user_ca"
#define CERT_NO_ALL "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAggzaP6/sPUwzVdSOd9zqsn9bViXFwCN5ltGn+zjLTd6cAAAADAQABAAABAQCgRZ+EFUwGpJyMfA3s6AURcyOdoUn3xl4mItNjx88RkMbKg9ck4XZkMZ4ws3rsRfDws0GrE+n7oP1n7QJH4Li7zGlGwuc2GI0NGoxxGajIfIh1D8hqs3DrdC5f9TLK0jIMLfSC/epXFkira6npgfzbpndmi844NJasEfb8X7lciOLqrAA8KkGa+VmN3zNbHP3JRBf9nywVhOZ0LH/fieCkektbyGewmNFO9GjRtmNUgP2BvL+dFJpW+Jx8iavQ5xHvfqEZi8HNzFPohOm1qkzY3Q859jp7Nq50PfC7DDDreSVzBDYmFa8XO8NU7wLiRNTts3QKAGL+lOzRRnl0IxFFAAAAAAAAAAAAAAABAAAADmxpYnNzaF90b3J0dXJlAAAAAAAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEA1T+Q9KctLyj1HUTgnoGBpMXwEU5bulg39ei3dY/S4PSGfqXS/V9zk+PrwyD5OW873sA8kAHTcriE03ctoCveAa/AuyGhxtyu+5OJAxqLMiR3CvVp31ffKPoX75m/CgOjynXbkZBjxGSPd3sxqhkzwDm95mHG1TmPys8wN9UJEa6PNtK9BX+euKfeLYwofFryxiVpqhvKyKaJcgGTuVkvSe13Ev5c7UJZy11WWI5LwcoQRap+ogTQ/PH49DTc4ReDk4VMEZHVbEg3YqOrUnW+G61YqJz6dey4PKy4e1jv7z4Y1zLd+AO7rsbGCnccjmQTBpzK5GSNID5aSwejIUi2KQAAARQAAAAMcnNhLXNoYTItNTEyAAABALylZqe6Ep03UVhVL4BYJzb3UGRCitcJgYV8wjUBtCPw6A/b6L4gIDSb8ZJv+MPAsuXlVPtx7QfOI2DxRWYwPXKRIeHx7jjgQKHjyPm/aeESyQF85jaxr92TKOuNDwoT3PSU7trGMQeteaRlCMVJr+G5mDj2YmJdmjqT8mhehmAaLswW5sMOf6/83+5q/lHfepenfQAAyZpF5S1mk2it2Nf0eX3wuAkajO/IaA2r0GJ9tEN2eMszq/hLEd76aob575ayDmwz7Hrkemr3zjRiIEbYPWzXP78MYOQjmJucSmeJgjjg8kyT0KfBplwS6y8d91x+nDBzI8+3d07aoSj3M9U= efe@rollo-tp"
#define CERT_WITH_PRINCIPALS "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgDkXO+f9NBl/lL1UhjRJzBc0CWEeHs6KBv7t4zexYnQMAAAADAQABAAABAQCgRZ+EFUwGpJyMfA3s6AURcyOdoUn3xl4mItNjx88RkMbKg9ck4XZkMZ4ws3rsRfDws0GrE+n7oP1n7QJH4Li7zGlGwuc2GI0NGoxxGajIfIh1D8hqs3DrdC5f9TLK0jIMLfSC/epXFkira6npgfzbpndmi844NJasEfb8X7lciOLqrAA8KkGa+VmN3zNbHP3JRBf9nywVhOZ0LH/fieCkektbyGewmNFO9GjRtmNUgP2BvL+dFJpW+Jx8iavQ5xHvfqEZi8HNzFPohOm1qkzY3Q859jp7Nq50PfC7DDDreSVzBDYmFa8XO8NU7wLiRNTts3QKAGL+lOzRRnl0IxFFAAAAAAAAAAAAAAABAAAADmxpYnNzaF90b3J0dXJlAAAAFwAAAANib2IAAAAFYWxpY2UAAAADZG9lAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDVP5D0py0vKPUdROCegYGkxfARTlu6WDf16Ld1j9Lg9IZ+pdL9X3OT4+vDIPk5bzvewDyQAdNyuITTdy2gK94Br8C7IaHG3K77k4kDGosyJHcK9WnfV98o+hfvmb8KA6PKdduRkGPEZI93ezGqGTPAOb3mYcbVOY/KzzA31QkRro820r0Ff564p94tjCh8WvLGJWmqG8rIpolyAZO5WS9J7XcS/lztQlnLXVZYjkvByhBFqn6iBND88fj0NNzhF4OThUwRkdVsSDdio6tSdb4brVionPp17Lg8rLh7WO/vPhjXMt34A7uuxsYKdxyOZBMGnMrkZI0gPlpLB6MhSLYpAAABFAAAAAxyc2Etc2hhMi01MTIAAAEAPogQSUNXn+dKgQXcn9cfE+LNk1G/YGatyaQQ26qFznN7kP9A7Cs1md/VzsLt/EM7Shj6Iyy+vDnlLQvJvh8kfkrYonbaUcpmHjmoI1lIb61efBcQCddXMLLUNH5x5ffNZrDJg1ffkxq93BIXRs2UvkJ9pKEWuOv/p2gzkKIm5Bfe/1iyDTnCzhE6fH0N8Y9jKDcJT+0FbnjFPubxnKhLr+u1W0/Mm+kCm6WCjD7AcJAkRx3Xvq38onWdHgMhvWbC/1owQxCBTKxNqT+K3AhEpAAKKAmKCdDVawZTFvDpeK6xE7tW30UioivEYCZsU0eQuriKdjdEe1v6WSq6K0J+2g== efe@rollo-tp"
#define CERT_WITH_SOURCE_ADDRESS "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg2SmRvDKKD4gkKZ9Z1lcj3Nf9ZfJ4CUQRC0IKufGIB68AAAADAQABAAABAQCgRZ+EFUwGpJyMfA3s6AURcyOdoUn3xl4mItNjx88RkMbKg9ck4XZkMZ4ws3rsRfDws0GrE+n7oP1n7QJH4Li7zGlGwuc2GI0NGoxxGajIfIh1D8hqs3DrdC5f9TLK0jIMLfSC/epXFkira6npgfzbpndmi844NJasEfb8X7lciOLqrAA8KkGa+VmN3zNbHP3JRBf9nywVhOZ0LH/fieCkektbyGewmNFO9GjRtmNUgP2BvL+dFJpW+Jx8iavQ5xHvfqEZi8HNzFPohOm1qkzY3Q859jp7Nq50PfC7DDDreSVzBDYmFa8XO8NU7wLiRNTts3QKAGL+lOzRRnl0IxFFAAAAAAAAAAAAAAABAAAADmxpYnNzaF90b3J0dXJlAAAAFwAAAANib2IAAAAFYWxpY2UAAAADZG9lAAAAAAAAAAD//////////wAAADYAAAAOc291cmNlLWFkZHJlc3MAAAAgAAAAHDE5OC41MS4wLjAvMTYsMjAwMTowZGI4OjovMzIAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDVP5D0py0vKPUdROCegYGkxfARTlu6WDf16Ld1j9Lg9IZ+pdL9X3OT4+vDIPk5bzvewDyQAdNyuITTdy2gK94Br8C7IaHG3K77k4kDGosyJHcK9WnfV98o+hfvmb8KA6PKdduRkGPEZI93ezGqGTPAOb3mYcbVOY/KzzA31QkRro820r0Ff564p94tjCh8WvLGJWmqG8rIpolyAZO5WS9J7XcS/lztQlnLXVZYjkvByhBFqn6iBND88fj0NNzhF4OThUwRkdVsSDdio6tSdb4brVionPp17Lg8rLh7WO/vPhjXMt34A7uuxsYKdxyOZBMGnMrkZI0gPlpLB6MhSLYpAAABFAAAAAxyc2Etc2hhMi01MTIAAAEAdAIhqu9+EuHE4MtzHcGmL6AfmHGdwHGHt8XJK1+gwOFgkNIqCUT+CNdcVaBPfP/Mg2Nd0csEYm1MX4m0rDceHLSeibjxD4cC9JDTgpnkcvDNvwK8G9hoLvCS35HFgRxT/RIUz5innGLnXJmX4AFO84dtYF3f+XBG5sr4m5v0cSD0kosZACcxFURsrlUUPQqS8oEYO7pTmezAcFsd6LgeirS8qehBFwSO1s4ybJfaVORYvRjm3fQ6I6F1W+n5IuglU/DvWRC6PW4F2ZyqN4xqVI/tGH0xTNGOWbcsgJzxF2RvQHzOgUZCENa/YgLshgF8iBB2pVWqWHZPPM8fUKliVQ== efe@rollo-tp"
#define CERT_WITH_FORCE_COMMAND "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgISNo2LclR4+sAiTZAC1CQqIsiQdbHV8wvdPv61U1UxgAAAADAQABAAABAQCgRZ+EFUwGpJyMfA3s6AURcyOdoUn3xl4mItNjx88RkMbKg9ck4XZkMZ4ws3rsRfDws0GrE+n7oP1n7QJH4Li7zGlGwuc2GI0NGoxxGajIfIh1D8hqs3DrdC5f9TLK0jIMLfSC/epXFkira6npgfzbpndmi844NJasEfb8X7lciOLqrAA8KkGa+VmN3zNbHP3JRBf9nywVhOZ0LH/fieCkektbyGewmNFO9GjRtmNUgP2BvL+dFJpW+Jx8iavQ5xHvfqEZi8HNzFPohOm1qkzY3Q859jp7Nq50PfC7DDDreSVzBDYmFa8XO8NU7wLiRNTts3QKAGL+lOzRRnl0IxFFAAAAAAAAAAAAAAABAAAADmxpYnNzaF90b3J0dXJlAAAAFwAAAANib2IAAAAFYWxpY2UAAAADZG9lAAAAAAAAAAD//////////wAAAC4AAAANZm9yY2UtY29tbWFuZAAAABkAAAAVL3Vzci9iaW4vZXhlYyAtb3B0aW9uAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEA1T+Q9KctLyj1HUTgnoGBpMXwEU5bulg39ei3dY/S4PSGfqXS/V9zk+PrwyD5OW873sA8kAHTcriE03ctoCveAa/AuyGhxtyu+5OJAxqLMiR3CvVp31ffKPoX75m/CgOjynXbkZBjxGSPd3sxqhkzwDm95mHG1TmPys8wN9UJEa6PNtK9BX+euKfeLYwofFryxiVpqhvKyKaJcgGTuVkvSe13Ev5c7UJZy11WWI5LwcoQRap+ogTQ/PH49DTc4ReDk4VMEZHVbEg3YqOrUnW+G61YqJz6dey4PKy4e1jv7z4Y1zLd+AO7rsbGCnccjmQTBpzK5GSNID5aSwejIUi2KQAAARQAAAAMcnNhLXNoYTItNTEyAAABAKzADwFafSDxgMElz1vZaolFt7Rew4SWM5gcuObwpu0Vla99dqjgT1wUjjFli5+kevvbK7yGOAuHQFGabZrZNf72Xcmjd1PJWVmiDG8xVW1Geq0xPolAWZcXXJ4WwEH7K9CbYiJM7dwI6WUtZB27uVzOeV33+St/hQDN49u2JUvaNm8yNLBFLb7ViTCfJWakm/Nw5OnElN8nyrpjfaKrtQVWfRI0IaL6a+cBKttJtZABGdqhnku+42MeqmN1YnfiedE1Pt7FcsZMaY6rBvm0zVBE9JynPjp9fJj2458FH9S4WUrkbnYNJHywnCXWs7Rbf4+lSGMHOBJjadIlTZKwiuk= efe@rollo-tp"

#define RSA_KEY_1 "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLpnWky+5bodU+C1R5VPBfWS7y33TEnVaE7apWszJD1Qjm9DC4+921HrWpJF+xo2qH09uVcAm+9N5cgiXWtjQ/aXFX0YUBTEfn8apWKzbhrtUEfiEMaBnuc3Aos3EZjj+L5wrzgqdwg/FLU3/Yt/9Mx+3S5SNgrgg2DFFgo8UYbXCC9BLr9sSjO+i7cDmRdRDYl8O5cCltQn7f6t87UGB7iz2wnC/HyBCRqbpevlQF/kaQuN2Dl+F7cEbRE38LYB6Y7f+EVZR4u2L51lXvBRLHC81zLy+JN1+TKodfCcyaeISELLDV/++H+ssk2I36qk7IBkfPZTMZujJTzpPPH7Ih rsa1@libssh"
#define RSA_KEY_2 "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqq4Rl043RloSljr6L5wFbMkIF3EqdOnTkIs6sVQQNv55pmlCPZsKiyxqKCvfoXG3c8lcZ4QYBUXvc4mcIdqzgB/pPRn2YGL9WrVLDzGLhkQj1wSkWwflaSwCrnVCZYcSrkaQkb4QmaOReaZWPERVDP9+luYkprfq+lzipy5oxRsB410AlC7QpfBlDna2EfrOn+Djrxdr03TtQnTxbxM3Mlyai/q6R4kZz1R2R26o1LWh0KI+st/+s6hGHY0s9GMcDtFXgzkMRDQwIabqjWHBoPMkF2b/Laim3yt5HjqUvFBhKh7HG0FfHW7tr1AwtKtb9a7sv8zBIyxlihh1g5uBH rsa2@libssh"
#define ECDSA_KEY_1 "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI3mfaZxZKz6wAU7+gLsrh61KepUDHFN0EeIIO3xlAcwDx/bGX2vLFbcXg4N789ni5tFeACoO9yxgzvDDHqTd/M= ecdsa1@libssh"
#define ECDSA_KEY_2 "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBFcasZJwq+BFtCj4YjFestz/t3oKE3cwRGgHCxCWyRnKe8VpUtn7IRSbQnGaD1dyZLRqb3NtagCdWJ+yypA2a8jwiyeUk92ihstVKOnJFLr7Ca1Oa5DfS7IksZqhrx/sXg== ecdsa2@libssh"
#define ECDSA_KEY_3 "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGPdbJkevkJEue3r9sfXo2h66IyrHkFVs2713qkcRQGpxfOSO+KzMvxJwZ2GcFAYPJnligC3CSrg7KVZTiK9fYEbQBXEz0fec6jlD+8dLT1bWchoa8m7SQd5pUl8QNXzMbgm28YkOr6OvBsLFOtaSKPBIr1N0KhNyUZEiKg0H5JbW8IBg== ecdsa3@libssh"

struct test_auth_file {
    ssh_key test_key;
    struct ssh_auth_options *auth_opts;
    char *temp_dir;
    char *auth_file;
};

const char dir_template[] = "temp_dir_XXXXXX";
const char auth_template[] = "authorized_keys_XXXXXX";

static int
setup_auth_file_state(void **state)
{
    struct test_auth_file *ta = NULL;
    char *temp_dir = NULL;

    ta = calloc(1, sizeof(struct test_auth_file));
    assert_non_null(ta);

    temp_dir = torture_make_temp_dir(dir_template);
    assert_non_null(temp_dir);

    ta->temp_dir = temp_dir;

    *state = ta;
    return 0;
}

static int
teardown_auth_file_state(void **state)
{
    struct test_auth_file *ta = *state;
    int rc;

    assert_non_null(ta);

    rc = torture_rmdirs(ta->temp_dir);
    assert_int_equal(rc, 0);

    SAFE_FREE(ta->temp_dir);
    SAFE_FREE(ta->auth_file);
    SSH_KEY_FREE(ta->test_key);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);
    SAFE_FREE(ta);
    return 0;
}

static void
setup_authorized_keys_file(void **state, const char *opt_list, bool want_ca)
{
    char *auth_file = NULL;
    char authorized_key_path[1024], auth_line[8192];
    struct test_auth_file *ta = *state;

    SAFE_FREE(ta->auth_file);
    /* Write authorized keys file */
    snprintf(authorized_key_path,
             sizeof(authorized_key_path),
             "%s/%s",
             ta->temp_dir,
             auth_template);

    auth_file = torture_create_temp_file(authorized_key_path);
    assert_non_null(auth_file);
    ta->auth_file = auth_file;

    /* Write auth line */
    snprintf(auth_line,
             sizeof(auth_line),
             "%s %s\n",
             opt_list,
             want_ca ? USER_CA_KEY : RSA_KEY_1);
    torture_write_file(auth_file, auth_line);
}

static void
setup_test_key(void **state, const char *key, bool want_cert)
{
    struct test_auth_file *ta = *state;
    char key_path[1024];
    char *key_file = NULL;
    ssh_key import_key = NULL;
    int rc;

    SSH_KEY_FREE(ta->test_key);
    /* Write test key path */
    snprintf(key_path,
             sizeof(key_path),
             "%s/%s",
             ta->temp_dir,
             "test-cert.pub");

    key_file = torture_create_temp_file(key_path);
    assert_non_null(key_file);
    torture_write_file(key_file, key);

    if (want_cert) {
        rc = ssh_pki_import_cert_file(key_path, &import_key);
    } else {
        rc = ssh_pki_import_pubkey_file(key_path, &import_key);
    }
    assert_return_code(rc, SSH_OK);

    ta->test_key = import_key;
    SAFE_FREE(key_file);
}

static void
setup_authorized_keys_file_multiple_keys(void **state)
{
    char *auth_file = NULL;
    char authorized_key_path[1024];
    struct test_auth_file *ta = *state;
    FILE *fp = NULL;
    int ret;

    SAFE_FREE(ta->auth_file);
    /* Write authorized keys file */
    snprintf(authorized_key_path,
             sizeof(authorized_key_path),
             "%s/%s",
             ta->temp_dir,
             auth_template);

    auth_file = torture_create_temp_file(authorized_key_path);
    assert_non_null(auth_file);
    ta->auth_file = auth_file;

    /* Write different keys testing different possible spaces at each new line*/
    fp = fopen(auth_file, "w");
    assert_non_null(fp);

    /* RSA 1 */
    ret = fprintf(fp, "%s\n", RSA_KEY_1);
    if (ret < 0) {
        fail();
    }

    /* RSA 2 */
    ret = fprintf(fp, "\t\t\r   %s\n", RSA_KEY_2);
    if (ret < 0) {
        fail();
    }

    /* RSA USER CA */
    ret = fprintf(fp, "   \t  \t cert-authority %s\n", USER_CA_KEY);
    if (ret < 0) {
        fail();
    }

    /* COMMENT LINE */
    ret = fprintf(fp, "#%s\n", USER_CA_KEY);
    if (ret < 0) {
        fail();
    }

    /* ECDSA 1 */
    ret = fprintf(fp, "\n\n\n\n\n\r%s\n", ECDSA_KEY_1);
    if (ret < 0) {
        fail();
    }

    /* ECDSA 2 */
    ret = fprintf(fp, "\r\r %s\n", ECDSA_KEY_2);
    if (ret < 0) {
        fail();
    }

    fclose(fp);
}

static void
setup_authorized_principals_file(void **state,
                                 const char *opt_list,
                                 const char *principal)
{
    char *auth_file = NULL;
    char auth_principals_path[1024], auth_principals_line[8192];
    struct test_auth_file *ta = *state;

    SAFE_FREE(ta->auth_file);
    /* Write authorized keys file */
    snprintf(auth_principals_path,
             sizeof(auth_principals_path),
             "%s/%s",
             ta->temp_dir,
             auth_template);

    auth_file = torture_create_temp_file(auth_principals_path);
    assert_non_null(auth_file);
    ta->auth_file = auth_file;

    /* Write auth line */
    snprintf(auth_principals_line,
             sizeof(auth_principals_line),
             "%s %s\n",
             opt_list,
             principal);
    torture_write_file(auth_file, auth_principals_line);
}

static void
torture_authorized_keys_cert_no_options(void **state)
{
    /* CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      (none)
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    /* cert-authority option is mandatory for authorizing a certificate */
    const char *opt_list = "cert-authority";
    const char *remote_ip = "not-needed";
    const char *remote_hostname = "not-needed";
    const char *user = "user";

    /* Setup authorized_keys file and certificate as testing key */
    setup_authorized_keys_file((void **)&ta, opt_list, true);
    setup_test_key((void **)&ta, CERT_NO_ALL, true);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        user,
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * Missing cert-authority while authorizing a certificate key should result
     * in a no match being found.
     */
    setup_authorized_keys_file((void **)&ta, "", true);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        user,
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
}

static void
torture_authorized_keys_cert_principals(void **state)
{
    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      bob,alice,doe
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    /* cert-authority option is mandatory for authorizing a certificate */
    const char *opt_list = "cert-authority";
    const char *remote_ip = "not-needed";
    const char *remote_hostname = "not-needed";

    /* Setup authorized_keys file and certificate as testing key */
    setup_authorized_keys_file((void **)&ta, opt_list, true);
    setup_test_key((void **)&ta, CERT_WITH_PRINCIPALS, true);

    /* Preliminary test: authorize valid user against cert principals */
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /* Preliminary test: authorize invalid user against cert principals */
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "john",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);

    /*
     * Test principals as in-line option. In-line principals options are
     * preferred to cert principals. The certificate contains at least one
     * principal listed in the in-line option (bob).
     */
    opt_list = "cert-authority,principals=\"bob\"";
    setup_authorized_keys_file((void **)&ta, opt_list, true);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "alice",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "doe",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * Even if it was "userX" authenticating, the certificate should still
     * be accepted.
     * From sshd manpage: "At least one name from the list must appear in the
     * certificate's list of principals for the certificate to be accepted."
     */
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "userX",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * In-line principals list does not match any certificate principals.
     * A valid principal (bob) from cert principals can't be accepted as
     * a valid principal for in-line auth options.
     */
    opt_list = "cert-authority,principals=\"random1,random2,random3,random4\"";
    setup_authorized_keys_file((void **)&ta, opt_list, true);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
}

static void
torture_authorized_keys_cert_from_option(void **state)
{
    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      bob,alice,doe
     * Validity:        forever
     * Critical opts:   source-address="198.51.0.0/16,2001:0db8::/32"
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    /* cert-authority option is mandatory for authorizing a certificate */
    const char *opt_list = "cert-authority";
    const char *remote_ip = "198.51.100.22";
    const char *remote_hostname = "libssh-test";

    /* Setup authorized_keys file and certificate as testing key */
    setup_authorized_keys_file((void **)&ta, opt_list, true);
    setup_test_key((void **)&ta, CERT_WITH_SOURCE_ADDRESS, true);

    /* Preliminary test: authorize valid user against source-address cert opt */
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * Test "from" option. This option contains an explicit IP address, a CIDR
     * list and two hostnames. Matching result ordered based on the check
     * sequence:
     * 172.16.22.4 -> no match
     * openssh-test -> no match
     * libssh-test -> match
     * 198.51.0.0/16 -> match (CIDR list equal to the certificate one)
     */
    opt_list = "cert-authority,"
               "from=\"172.16.22.4,198.51.0.0/16,openssh-test,libssh-test\"";
    setup_authorized_keys_file((void **)&ta, opt_list, true);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);

    /* The first match is "libssh-test" -> no need to wrap it for Windows*/
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * There is no explicit IP address or hostname matching now. The match
     * should be found with CIDR list. On Windows the CIDR matching check
     * is skipped.
     * 198.51.100.22 -> match
     * 2001:0db8::a4d7:25ff -> match
     */
    opt_list = "cert-authority,"
               "from=\"172.16.22.4,198.51.0.0/16,2001:0db8::/32,openssh-test\"";
    setup_authorized_keys_file((void **)&ta, opt_list, true);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
#ifdef _WIN32
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
#else
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);
#endif

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
#ifdef _WIN32
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
#else
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);
#endif

    /*
     * Test authorized user against explicit IPv4 address.
     * 198.51.100.22 -> match
     */
    opt_list = "cert-authority,"
               "from=\"openssh-test,random1,172.18.0.88,198.51.100.22\"";
    setup_authorized_keys_file((void **)&ta, opt_list, true);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * Test authorized user against explicit IPv6 address.
     * 2001:0db8::a4d7:25ff -> match
     */
    opt_list = "cert-authority,"
               "from=\"openssh-test,2001:0db8::a4d7:25ff,random1,172.18.0.88\"";
    remote_ip = "2001:0db8::a4d7:25ff";
    setup_authorized_keys_file((void **)&ta, opt_list, true);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * Test "unknown" IP address and hostname. "unknown" will not match
     * "from" nor "source-address" options. This scenario occurs when an error
     * happens while attempting to retrieve the remote peer's IP address or
     * hostname from the socket. As a result, the remote IP and hostname are
     * both set to "unknown".
     * unknown -> no match
     */
    remote_ip = "unknown";
    remote_hostname = "unknown";
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);

    /*
     * Test non-matching "from" option behavior. "from" option is preferred to
     * source-address option. If there is no match with "from" option then,
     * even if cert source-address option exists, the user is not authorized.
     * 2001:0db8::a4d7:25ff -> matches CIDR list of cert
     *                         source-address="198.51.0.0/16,2001:0db8::/32"
     *                         but it does not meet "from" option
     */
    opt_list = "cert-authority,"
               "from=\"openssh-test,random1,172.18.0.88\"";
    setup_authorized_keys_file((void **)&ta, opt_list, true);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);

    /*
     * Test non-matching "from" and "source-address" options.
     * 150.58.88.1 -> no match
     */
    remote_ip = "150.58.88.1";
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);

    /*
     * Load a certificate that does not contain "source-address" option and
     * retry an invalid match against "from" option.
     * 150.58.88.1 -> no match
     */
    SSH_KEY_FREE(ta->test_key);
    setup_test_key((void **)&ta, CERT_NO_ALL, true);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "bob",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
}

static void
torture_authorized_keys_cert_command_option(void **state)
{
    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      bob,alice,doe
     * Validity:        forever
     * Critical opts:   force-command="/usr/bin/exec -option"
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    /* cert-authority option is mandatory for authorizing a certificate */
    const char *opt_list = "cert-authority,command=\"/usr/bin/exec -option\"";
    const char *remote_ip = "not-needed";
    const char *remote_hostname = "not-needed";

    /* Setup authorized_keys file and certificate as testing key */
    setup_authorized_keys_file((void **)&ta, opt_list, true);
    setup_test_key((void **)&ta, CERT_WITH_FORCE_COMMAND, true);

    /*
     * Authorization check is done on matching CA key and certificate principal.
     * Check that command option matches the certificate force-command option.
     */
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "alice",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * Test non-matching force-command option.
     * "/usr/bin/another-exec -option" > does not match "/usr/bin/exec -option"
     */
    opt_list = "cert-authority,command=\"/usr/bin/another-exec -option\"";
    setup_authorized_keys_file((void **)&ta, opt_list, true);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "alice",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    /*
     * The function returns -1 instead of a non-matching key (0). This is good
     * because it alerts the user that there is an error in how the "command"
     * option is handled.
     */
    assert_int_equal(rc, -1);
    assert_null(ta->auth_opts);
}

static void
torture_authorized_keys_cert_expiry_time_option(void **state)
{
    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      bob,alice,doe
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    /* cert-authority option is mandatory for authorizing a certificate */
    const char *opt_list = "cert-authority,expiry-time=\"202008101545Z\"";
    const char *remote_ip = "not-needed";
    const char *remote_hostname = "not-needed";

    /* Setup authorized_keys file and certificate as testing key */
    setup_authorized_keys_file((void **)&ta, opt_list, true);
    setup_test_key((void **)&ta, CERT_WITH_PRINCIPALS, true);

    /*
     * Authorization check is done on matching CA key and certificate principal.
     * Check that expiry-time invalidates the certificate (valid forever).
     * New expiry-time: 2020, August 10th 15:45 UTC
     */
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "alice",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
}

static void
torture_authorized_keys_plain_key_no_options(void **state)
{
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    const char *opt_list = "";
    const char *remote_ip = "not-needed";
    const char *remote_hostname = "not-needed";

    /* Setup authorized_keys file and a plain RSA 1 key as testing key */
    setup_authorized_keys_file((void **)&ta, opt_list, false);
    setup_test_key((void **)&ta, RSA_KEY_1, false);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "libssh_user",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /* Test with a non-matching key */
    setup_authorized_keys_file((void **)&ta, opt_list, true);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "libssh_user",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
}

/**
 * @note The "from" option unit tests for plain keys are nearly identical to
 * those for certificate keys. The only difference is that plain keys do not
 * include a "source-address" option, which will be skipped during
 * `ssh_authorize_authkey_options` processing.
 */
static void
torture_authorized_keys_plain_key_from_option(void **state)
{
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    const char *opt_list = "from=\"172.16.22.4,198.51.0.0/16,openssh-test,"
                           "libssh-test\"";
    const char *remote_ip = "198.51.100.22";
    const char *remote_hostname = "libssh-test";

    /* Setup authorized_keys file and a plain RSA 1 key as testing key */
    setup_authorized_keys_file((void **)&ta, opt_list, false);
    setup_test_key((void **)&ta, RSA_KEY_1, false);

    /*
     * Test "from" option. This option contains an explicit IP address, a CIDR
     * list and two hostnames. Matching result ordered based on the check
     * sequence:
     * 172.16.22.4 -> no match
     * openssh-test -> no match
     * libssh-test -> match
     * 198.51.0.0/16 -> match
     */
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "libssh_user",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);

    /* The first match is "libssh-test" -> no need to wrap it for Windows*/
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * There is no explicit IP address or hostname matching now. The match
     * should be found with CIDR list. On Windows the CIDR matching check
     * is skipped.
     * 198.51.100.22 -> match
     * 2001:0db8::a4d7:25ff -> match
     */
    opt_list = "from=\"172.16.22.4,198.51.0.0/16,2001:0db8::/32,openssh-test\"";
    setup_authorized_keys_file((void **)&ta, opt_list, false);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "libssh_user",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
#ifdef _WIN32
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
#else
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);
#endif

    /*
     * Test authorized user against explicit IPv4 address.
     * 198.51.100.22 -> match
     */
    opt_list = "from=\"openssh-test,random1,172.18.0.88,198.51.100.22\"";
    setup_authorized_keys_file((void **)&ta, opt_list, false);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "libssh_user",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * Test authorized user against explicit IPv6 address.
     * 2001:0db8::a4d7:25ff -> match
     */
    opt_list = "from=\"openssh-test,2001:0db8::a4d7:25ff,random1,172.18.0.88\"";
    remote_ip = "2001:0db8::a4d7:25ff";
    setup_authorized_keys_file((void **)&ta, opt_list, false);

    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "libssh_user",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * Test "unknown" IP address and hostname. "unknown" will not match
     * "from" option. This scenario occurs when an error happens while
     * attempting to retrieve the remote peer's IP address or hostname
     * from the socket. As a result, the remote IP and hostname are
     * both set to "unknown".
     * unknown -> no match
     */
    remote_ip = "unknown";
    remote_hostname = "unknown";
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "libssh_user",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);

    /*
     * Test non-matching "from" option.
     * 150.58.88.1 -> no match
     */
    remote_ip = "150.58.88.1";
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "libssh_user",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
}

/**
 * @note Testing an expiry-time that does not invalidate the key is not feasible
 * because, eventually, any expiry-time set for the test will become invalid
 * as time progresses. Although this is a limitation for unit testing the
 * expiry-time option at least we ensure the maintainability of the test code.
 */
static void
torture_authorized_keys_plain_key_expiry_time_option(void **state)
{
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    const char *opt_list = "expiry-time=\"202112011800Z\"";
    const char *remote_ip = "not-needed";
    const char *remote_hostname = "not-needed";

    /* Setup authorized_keys file and a plain RSA 1 key as testing key */
    setup_authorized_keys_file((void **)&ta, opt_list, false);
    setup_test_key((void **)&ta, RSA_KEY_1, false);

    /*
     * Check that expiry-time invalidates the key.
     * Expiry-time: 2021, December 12nd 18:00 UTC
     */
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "libssh_user",
                                        &ta->auth_opts,
                                        remote_ip,
                                        remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
}

static void
torture_authorized_keys_leading_spaces(void **state)
{
    struct test_auth_file *ta = *state;
    int rc;

    /* Setup authorized_keys file */
    setup_authorized_keys_file_multiple_keys((void **)&ta);

    /* Test RSA 1 */
    setup_test_key((void **)&ta, RSA_KEY_1, false);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "test",
                                        &ta->auth_opts,
                                        "unknown",
                                        "unknown");
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /* Test RSA 2 */
    setup_test_key((void **)&ta, RSA_KEY_2, false);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "test",
                                        &ta->auth_opts,
                                        "unknown",
                                        "unknown");
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /* Test CERTIFICATE */
    setup_test_key((void **)&ta, CERT_NO_ALL, true);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "test",
                                        &ta->auth_opts,
                                        "unknown",
                                        "unknown");
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /* Test ECDSA 1 */
    setup_test_key((void **)&ta, ECDSA_KEY_1, false);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "test",
                                        &ta->auth_opts,
                                        "unknown",
                                        "unknown");
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /* Test ECDSA 2 */
    setup_test_key((void **)&ta, ECDSA_KEY_2, false);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "test",
                                        &ta->auth_opts,
                                        "unknown",
                                        "unknown");
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /* Test not authorized ECDSA 3 key */
    setup_test_key((void **)&ta, ECDSA_KEY_3, false);
    rc = ssh_authorized_keys_check_file(ta->test_key,
                                        ta->auth_file,
                                        "test",
                                        &ta->auth_opts,
                                        "unknown",
                                        "unknown");
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
}

/**
 * @note Authorized principals unit tests skip some of the already tested
 * options within authorized_keys file since their validation follow the same
 * logic.
 */

static void
torture_authorized_principals_no_options(void **state)
{
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    const char *opt_list = "";
    const char *remote_ip = "not-needed";
    const char *remote_hostname = "not-needed";

    /*
     * Setup authorized_principals file and a certificate as testing key.
     * The authorized principal is bob.
     */
    setup_authorized_principals_file((void **)&ta, opt_list, "bob");

    /*
     * Preliminary test: check for a matching principal against a certificate
     * that does not contain any principal. Although it may seem logic to
     * accept any principals, we must make sure that the certificate is not
     * accepted.
     * From sshd manpage: "this file lists names, one of which must appear in
     *                     the certificate for it to be accepted for
     *                     authentication".
     */
    setup_test_key((void **)&ta, CERT_NO_ALL, true);
    rc = ssh_authorized_principals_check_file(ta->test_key,
                                              ta->auth_file,
                                              &ta->auth_opts,
                                              remote_ip,
                                              remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);

    /*
     * Check for a matching principal against the following certificate
     * principals: bob,alice,doe
     */
    setup_test_key((void **)&ta, CERT_WITH_PRINCIPALS, true);
    rc = ssh_authorized_principals_check_file(ta->test_key,
                                              ta->auth_file,
                                              &ta->auth_opts,
                                              remote_ip,
                                              remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /* Test a principal that does not appear in the certificate principals */
    setup_authorized_principals_file((void **)&ta, opt_list, "john");
    rc = ssh_authorized_principals_check_file(ta->test_key,
                                              ta->auth_file,
                                              &ta->auth_opts,
                                              remote_ip,
                                              remote_hostname);
    assert_int_equal(rc, 0);
    assert_null(ta->auth_opts);
}

static void
torture_authorized_principals_options(void **state)
{
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    const char *opt_list = "from=\"93.85.12.58\",command=\"/usr/bin/exec\"";
    const char *remote_ip = "93.85.12.58";
    const char *remote_hostname = "libssh-test";

    /*
     * Setup authorized_principals file and a certificate as testing key.
     * The authorized principal is bob.
     */
    setup_authorized_principals_file((void **)&ta, opt_list, "bob");

    /* Check that the in-line authentication options are correctly recognized */
    setup_test_key((void **)&ta, CERT_WITH_PRINCIPALS, true);
    rc = ssh_authorized_principals_check_file(ta->test_key,
                                              ta->auth_file,
                                              &ta->auth_opts,
                                              remote_ip,
                                              remote_hostname);
    assert_int_equal(rc, 1);
    assert_non_null(ta->auth_opts);
    assert_string_equal(ta->auth_opts->authkey_from_addr_host, "93.85.12.58");
    assert_string_equal(ta->auth_opts->force_command, "/usr/bin/exec");
    SSH_AUTH_OPTS_FREE(ta->auth_opts);

    /*
     * Check that the expiry-time invalidates the certificate.
     * Expiry-time: 2018, May 21st
     */
    opt_list = "expiry-time=\"20180521Z\"";
    setup_authorized_principals_file((void **)&ta, opt_list, "bob");
    rc = ssh_authorized_principals_check_file(ta->test_key,
                                              ta->auth_file,
                                              &ta->auth_opts,
                                              remote_ip,
                                              remote_hostname);
    assert_int_equal(rc, -1);
    assert_null(ta->auth_opts);

    /* Test invalid cert-authority option */
    opt_list = "cert-authority,from=\"93.85.12.58\",command=\"/usr/bin/exec\"";
    setup_authorized_principals_file((void **)&ta, opt_list, "bob");
    rc = ssh_authorized_principals_check_file(ta->test_key,
                                              ta->auth_file,
                                              &ta->auth_opts,
                                              remote_ip,
                                              remote_hostname);
    assert_int_equal(rc, -1);
    assert_null(ta->auth_opts);

    /* Test invalid "principals=" option */
    opt_list = "cert-authority,principals=\"bob,alice,doe\","
               "from=\"93.85.12.58\",command=\"/usr/bin/exec\"";
    setup_authorized_principals_file((void **)&ta, opt_list, "bob");
    rc = ssh_authorized_principals_check_file(ta->test_key,
                                              ta->auth_file,
                                              &ta->auth_opts,
                                              remote_ip,
                                              remote_hostname);
    assert_int_equal(rc, -1);
    assert_null(ta->auth_opts);
}

static void
torture_authorized_principals_invalid_key_type(void **state)
{
    struct test_auth_file *ta = *state;
    int rc;

    /* Test arguments */
    const char *opt_list = "";
    const char *remote_ip = "not-needed";
    const char *remote_hostname = "not-needed";

    /*
     * Setup authorized_principals file and a plain public key as testing key.
     * The authorized principal is bob.
     * The plain public key is not valid when processing the
     * authorized_principals file.
     */
    setup_authorized_principals_file((void **)&ta, opt_list, "bob");
    setup_test_key((void **)&ta, RSA_KEY_1, false);
    rc = ssh_authorized_principals_check_file(ta->test_key,
                                              ta->auth_file,
                                              &ta->auth_opts,
                                              remote_ip,
                                              remote_hostname);
    assert_int_equal(rc, -1);
    assert_null(ta->auth_opts);
}

int
torture_run_tests(void)
{
    int rc;

    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_authorized_keys_cert_no_options,
                                        setup_auth_file_state,
                                        teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(torture_authorized_keys_cert_principals,
                                        setup_auth_file_state,
                                        teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(
            torture_authorized_keys_cert_from_option,
            setup_auth_file_state,
            teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(
            torture_authorized_keys_cert_command_option,
            setup_auth_file_state,
            teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(
            torture_authorized_keys_cert_expiry_time_option,
            setup_auth_file_state,
            teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(
            torture_authorized_keys_plain_key_no_options,
            setup_auth_file_state,
            teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(
            torture_authorized_keys_plain_key_from_option,
            setup_auth_file_state,
            teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(
            torture_authorized_keys_plain_key_expiry_time_option,
            setup_auth_file_state,
            teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(torture_authorized_keys_leading_spaces,
                                        setup_auth_file_state,
                                        teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(
            torture_authorized_principals_no_options,
            setup_auth_file_state,
            teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(torture_authorized_principals_options,
                                        setup_auth_file_state,
                                        teardown_auth_file_state),
        cmocka_unit_test_setup_teardown(
            torture_authorized_principals_invalid_key_type,
            setup_auth_file_state,
            teardown_auth_file_state),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
