add_kpm_module(wxshadow
    wxshadow.c
    wxshadow_pgtable.c
    wxshadow_handlers.c
    wxshadow_bp.c
    wxshadow_scan.c
)

# Build client tool (userspace)
add_executable(wxshadow_client wxshadow_client.c)
if(CMAKE_C_COMPILER MATCHES "linux-android" OR CMAKE_C_COMPILER_TARGET MATCHES "android")
    # Android's dynamic linker rejects some fully-static NDK binaries when the
    # generated PT_TLS alignment is below Bionic's arm64 minimum.  Build the
    # on-device helper dynamically; KPM artifacts remain freestanding.
    target_link_options(wxshadow_client PRIVATE -s)
else()
    target_link_options(wxshadow_client PRIVATE -static -s)
endif()
