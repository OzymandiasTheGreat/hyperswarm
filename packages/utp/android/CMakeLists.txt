cmake_minimum_required(VERSION 3.9.0)

set (PACKAGE_NAME "utp-react-native")
set (BUILD_DIR ./build)

set(ARCH_DIR ${ANDROID_ARCH_NAME})

if( ANDROID_ABI STREQUAL "armeabi-v7a")
  set( ARCH_DIR "armv7-a" )
elseif ( ANDROID_ABI STREQUAL "arm64-v8a")
  set( ARCH_DIR "armv8-a" )
elseif ( ANDROID_ABI STREQUAL "x86")
  set ( ARCH_DIR "i686" )
elseif ( ANDROID_ABI STREQUAL "x86_64")
  set ( ARCH_DIR "westmere" )
endif()

include_directories(
        ${PACKAGE_NAME}
        "${NODE_MODULES_DIR}/react-native/React"
        "${NODE_MODULES_DIR}/react-native/React/Base"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
        "../libuv/libuv-android-${ARCH_DIR}/include"
        "../libutp"
        "../cpp"
        "."
)

add_library(uv SHARED IMPORTED)
set_target_properties(uv PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/../libuv/libuv-android-${ARCH_DIR}/lib/libuv.so")
file (COPY "${PROJECT_SOURCE_DIR}/../libuv/libuv-android-${ARCH_DIR}/lib/libuv.so" DESTINATION "${PROJECT_SOURCE_DIR}/lib/${ANDROID_ABI}")

file (GLOB LIBRN_DIR "${BUILD_DIR}/react-native-0*/jni/${ANDROID_ABI}")

if (JSI_LIB)
  # React Native 0.66.x and above
  add_library(
          ${PACKAGE_NAME}
          SHARED
          ../libutp/utp_api.cpp
          ../libutp/utp_callbacks.cpp
          ../libutp/utp_hash.cpp
          ../libutp/utp_internal.cpp
          ../libutp/utp_packedsockaddr.cpp
          ../libutp/utp_utils.cpp
          ../cpp/utp-react-native.cpp
          ./cpp-adapter.cpp
  )

  find_library(
        JSI_LIB
        jsi
        PATHS ${LIBRN_DIR}
        NO_CMAKE_FIND_ROOT_PATH
  )
else()
  # React Native 0.65.x and below
  add_library(
          ${PACKAGE_NAME}
          SHARED
          ../node_modules/react-native/ReactCommon/jsi/jsi/jsi.cpp
          ../libutp/utp_api.cpp
          ../libutp/utp_callbacks.cpp
          ../libutp/utp_hash.cpp
          ../libutp/utp_internal.cpp
          ../libutp/utp_packedsockaddr.cpp
          ../libutp/utp_utils.cpp
          ../cpp/utp-react-native.cpp
          ./cpp-adapter.cpp
  )
endif()

find_library(
        LOG_LIB
        log
)

find_library(
        REACT_NATIVE_JNI_LIB
        reactnativejni
        PATHS ${LIBRN_DIR}
        NO_CMAKE_FIND_ROOT_PATH
)

add_definitions(
        -DPOSIX
)

set_target_properties(
        ${PACKAGE_NAME} PROPERTIES
        CXX_STANDARD 17
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
)

target_link_libraries(
        ${PACKAGE_NAME}
        ${LOG_LIB}
        ${REACT_NATIVE_JNI_LIB}
        ${JSI_LIB}
        uv
        android
)
