
# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.18.1)

# Declares and names the project.

project("myapplication")

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_definitions("-DLOGDEBUG")

include_directories(${CMAKE_SOURCE_DIR}/include/)

add_library( # Sets the name of the library.
        myapplication

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        myapplication.cpp openssl_rsa.cpp openssl_aes.cpp openssl_tdes.cpp)

#add_library(
#        tools_openssl
#
#        STATIC
#
#        tools_openssl.cpp)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

add_library(libcrypto STATIC IMPORTED)
add_library(libssl STATIC IMPORTED)

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

#if (${ANDROID_ABI} STREQUAL "armeabi-v7a")
#    add_definitions("-l'openssl/libcrypto_armeabi-v7a.a'")
#    add_definitions("-l'openssl/libssl_armeabi-v7a.a'")
#    find_library(crypto openssl/libcrypto_armeabi-v7a.a)
#    find_library(ssl openssl/libssl_armeabi-v7a.a)
#elseif(${ANDROID_ABI} STREQUAL "arm64-v8a")
#    add_definitions("-l'openssl/libcrypto_arm64-v8a.a'")
#    add_definitions("-l'openssl/libssl_arm64-v8a.a'")
#    find_library(crypto openssl/libcrypto_arm64-v8a.a)
#    find_library(ssl openssl/libssl_arm64-v8a.a)
#elseif(${ANDROID_ABI} STREQUAL "x86_64")
#    add_definitions("-l'openssl/libcrypto_x86_64.a'")
#    add_definitions("-l'openssl/libssl_x86_64.a'")
#    find_library(crypto openssl/libcrypto_x86_64.a)
#    find_library(ssl openssl/libssl_x86_64.a)
#elseif(${ANDROID_ABI} STREQUAL "x86")
#    add_definitions("-l'openssl/libcrypto_x86.a'")
#    add_definitions("-l'openssl/libssl_x86.a'")
#    find_library(crypto openssl/libcrypto_x86.a)
#    find_library(ssl openssl/libssl_x86.a)
#endif()

set_target_properties(
        # Specifies the target library.
        libcrypto
        # Specifies the parameter you want to define.
        PROPERTIES IMPORTED_LOCATION
        # Provides the path to the library you want to import.
        ${CMAKE_SOURCE_DIR}/openssl/${ANDROID_ABI}/libcrypto.a)

set_target_properties(
        # Specifies the target library.
        libssl
        # Specifies the parameter you want to define.
        PROPERTIES IMPORTED_LOCATION
        # Provides the path to the library you want to import.
        ${CMAKE_SOURCE_DIR}/openssl/${ANDROID_ABI}/libssl.a)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
        myapplication

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} libcrypto libssl)



