add_kpm_module(anti-detect anti-detect.c anti-detect-supercall.c)

add_executable(anti_detect_ctl anti_detect_ctl.c)
if(CMAKE_C_COMPILER MATCHES "linux-android" OR CMAKE_C_COMPILER_TARGET MATCHES "android")
    target_link_options(anti_detect_ctl PRIVATE -s)
else()
    target_link_options(anti_detect_ctl PRIVATE -static -s)
endif()
