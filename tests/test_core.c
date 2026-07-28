#include "ac.h"

#include <stdio.h>
#include <string.h>

static int g_failures = 0;

#define AC_CHECK(expression)                                                   \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(                                                           \
                stderr,                                                        \
                "check failed at %s:%d: %s\n",                                \
                __FILE__,                                                      \
                __LINE__,                                                      \
                #expression);                                                  \
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

static void test_path_boundaries(void)
{
    AC_CHECK(ac_path_is_under(
        L"C:\\Games\\Example\\bin\\game.dll",
        L"C:\\Games\\Example"));
    AC_CHECK(ac_path_is_under(
        L"c:\\windows\\system32\\kernel32.dll",
        L"C:\\Windows\\"));
    AC_CHECK(!ac_path_is_under(
        L"C:\\Games\\Example-Evil\\payload.dll",
        L"C:\\Games\\Example"));
    AC_CHECK(!ac_path_is_under(L"C:\\Games\\Example", L""));
}

static void test_module_ranges(void)
{
    AcModuleList modules;

    memset(&modules, 0, sizeof(modules));
    modules.count = 1;
    modules.items[0].base = (uintptr_t)0x10000000u;
    modules.items[0].size = 0x10000u;

    AC_CHECK(ac_address_range_in_module(
        &modules,
        (uintptr_t)0x10000000u,
        0x1000u));
    AC_CHECK(ac_address_range_in_module(
        &modules,
        (uintptr_t)0x1000f000u,
        0x1000u));
    AC_CHECK(!ac_address_range_in_module(
        &modules,
        (uintptr_t)0x0ffff000u,
        0x2000u));
    AC_CHECK(!ac_address_range_in_module(
        &modules,
        (uintptr_t)0x1000f000u,
        0x2000u));
}

static void test_json_escaping(void)
{
    char output[64];

    ac_json_escape("C:\\Game\\line\n\"quoted\"", output, sizeof(output));
    AC_CHECK(strcmp(output, "C:\\\\Game\\\\line\\n\\\"quoted\\\"") == 0);
}

int main(void)
{
    test_path_boundaries();
    test_module_ranges();
    test_json_escaping();

    if (g_failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", g_failures);
        return 1;
    }

    puts("all core tests passed");
    return 0;
}
