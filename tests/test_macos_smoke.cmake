if(NOT DEFINED AC_EXECUTABLE OR NOT EXISTS "${AC_EXECUTABLE}")
    message(FATAL_ERROR "AC_EXECUTABLE must name the built macOS collector")
endif()

if(NOT DEFINED AC_LOG_PATH)
    message(FATAL_ERROR "AC_LOG_PATH must be provided")
endif()

file(REMOVE "${AC_LOG_PATH}")
execute_process(
    COMMAND
        "${AC_EXECUTABLE}"
        --self
        --once
        --quiet
        --log
        "${AC_LOG_PATH}"
    RESULT_VARIABLE collector_result
    OUTPUT_VARIABLE collector_stdout
    ERROR_VARIABLE collector_stderr
)

if(NOT collector_result EQUAL 0)
    message(FATAL_ERROR
        "macOS self scan exited with ${collector_result}: ${collector_stderr}")
endif()
if(NOT collector_stdout STREQUAL "")
    message(FATAL_ERROR "quiet self scan wrote to stdout: ${collector_stdout}")
endif()
if(NOT EXISTS "${AC_LOG_PATH}")
    message(FATAL_ERROR "macOS self scan did not create a log")
endif()

file(READ "${AC_LOG_PATH}" log_content)
foreach(required_event
        log_segment_opened
        agent_started
        target_opened
        scan_completed
        agent_stopped)
    if(NOT log_content MATCHES "\"event\":\"${required_event}\"")
        message(FATAL_ERROR "missing ${required_event} in macOS self-scan log")
    endif()
endforeach()

if(NOT log_content MATCHES "\"platform\":\"macos\"")
    message(FATAL_ERROR "macOS platform metadata is missing")
endif()
if(NOT log_content MATCHES "\"regions\":[1-9][0-9]*")
    message(FATAL_ERROR "macOS self scan did not report memory regions")
endif()

file(REMOVE "${AC_LOG_PATH}")
