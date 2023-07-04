# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.18.1)

# Declares and names the project.

project("test")

AUX_SOURCE_DIRECTORY(${PROJECT_SOURCE_DIR}/rcs all)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             native-lib.cpp )

add_library(rcs-rust SHARED IMPORTED)
set_target_properties(rcs-rust PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/libs/${CMAKE_ANDROID_ARCH_ABI}/rust_rcs/lib/librust_rcs_client.so)
#add_library(rcs-rust-core SHARED IMPORTED)
#set_target_properties(rcs-rust-core PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/libs/${CMAKE_ANDROID_ARCH_ABI}/rust_rcs_core/lib/librust_rcs_core.so)

include_directories(${PROJECT_SOURCE_DIR}/libs/${CMAKE_ANDROID_ARCH_ABI}/rust_rcs/include)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

find_library( # Sets the name of the path variable.
              z-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              z )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

if (${ANDROID_ABI} STREQUAL "arm64-v8a")
    target_link_libraries( # Specifies the target library.
            native-lib

            # Links the target library to the log library
            # included in the NDK.
            ${log-lib} ${z-lib} rcs-rust )
else()
    target_link_libraries( # Specifies the target library.
            native-lib

            # Links the target library to the log library
            # included in the NDK.
            ${log-lib} ${z-lib} rcs-rust )
endif()
