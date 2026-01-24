cmake_minimum_required (VERSION 3.20)

project("etaHEN-SDK")

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)	# static libs are archive

include_directories	(SYSTEM "${PROJECT_ROOT}/include")
include_directories(SYSTEM "${PS5_PAYLOAD_SDK}")
include_directories(SYSTEM "${PS5_PAYLOAD_SDK}/include")

add_subdirectory(libhijacker)
add_subdirectory(libNidResolver)
add_subdirectory(Plugin_samples/GTRDLoader-2.20)
add_subdirectory(Plugin_samples/GTRDLoader-2.19)
add_subdirectory(Plugin_samples/GTRDLoader-2.18)
add_subdirectory(Plugin_samples/GTRDLoader-2.10)
add_subdirectory(Plugin_samples/GTRDLoader-2.11)
add_subdirectory(Plugin_samples/GTRDLoader-2.12)
add_subdirectory(Plugin_samples/GTRDLoader-2.13)
add_subdirectory(Plugin_samples/GTRDLoader-2.14)
add_subdirectory(Plugin_samples/GTRDLoader-2.15)
add_subdirectory(Plugin_samples/GTRDLoader-2.16)
add_subdirectory(Plugin_samples/GTRDLoader-2.17)
add_subdirectory(Plugin_samples/Injector)
add_subdirectory(Plugin_samples/itemzflow_xml_patches)
add_subdirectory(Plugin_samples/Error_Disabling)
add_subdirectory(Plugin_samples/PS5Debug)
add_subdirectory(Plugin_samples/PS5Debug-v2.00)
add_subdirectory(Plugin_samples/Game_Plugin_Loader)

