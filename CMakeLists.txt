cmake_minimum_required(VERSION 3.24)

project(user_mode_anticheat VERSION 0.1.0 LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "user_mode_anticheat targets the Windows API and must be built on Windows")
endif()

add_library(anticheat_core STATIC
    src/log.c
    src/process.c
    src/scanner.c
)

target_include_directories(anticheat_core PUBLIC src)
target_compile_features(anticheat_core PUBLIC c_std_11)
target_compile_definitions(anticheat_core PUBLIC
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
)

add_executable(anticheat src/main.c)
target_link_libraries(anticheat PRIVATE anticheat_core)

function(ac_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

ac_enable_warnings(anticheat_core)
ac_enable_warnings(anticheat)

include(CTest)
if(BUILD_TESTING)
    add_executable(anticheat_tests tests/test_core.c)
    target_link_libraries(anticheat_tests PRIVATE anticheat_core)
    ac_enable_warnings(anticheat_tests)
    add_test(NAME anticheat_core_tests COMMAND anticheat_tests)
endif()

install(TARGETS anticheat RUNTIME DESTINATION bin)
