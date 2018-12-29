#!/bin/bash
# by KangLin(kl222@126.com)

set -e

cd $1

PROJECT_DIR=`pwd`

#Only test all platform and configure in tag
if [ "$appveyor_repo_tag" != "true" ]; then
    if [ "${Platform}" = "64" -o "${Configuration}" = "Release" -o "${Configuration}" = "release" ]; then
        echo "Don't test, When 64 bits and release, appveyor_repo_tag = false"
        cd ${PROJECT_DIR}
        exit 0
    fi
fi

case ${BUILD_TARGERT} in
    windows_msvc)
        case ${TOOLCHAIN_VERSION} in
            15)
                PRJ_GEN="Visual Studio 15 2017"
            ;;
            14)
                PRJ_GEN="Visual Studio 14 2015"
            ;;
            12)
                PRJ_GEN="Visual Studio 12 2013"
            ;;
            11)
                PRJ_GEN="Visual Studio 11 2012"
            ;;
            9)
                PRJ_GEN="Visual Studio 9 2008"
                if [ "${Platform}" = "64" ]; then
                    echo "Don't support Visual Studio 9 2008 for 64 bits in appveyor"
                    cd ${PROJECT_DIR}
                    exit 0
                fi
            ;;
        esac
        if [ "${Platform}" = "64" ]; then
            PRJ_GEN="${PRJ_GEN} Win64"
        fi
    ;;
    windows_mingw)
        PRJ_GEN="MSYS Makefiles"
    
        case ${TOOLCHAIN_VERSION} in
            630)
                if [ "${Platform}" = "64" ]; then
                    MINGW_PATH=/C/mingw-w64/x86_64-6.3.0-posix-seh-rt_v5-rev1/mingw64
                else
                    MINGW_PATH=/C/mingw-w64/i686-6.3.0-posix-dwarf-rt_v5-rev1/mingw32
                fi
            ;;
            530)
                if [ "${Platform}" = "32" ]; then
                    MINGW_PATH=/C/mingw-w64/i686-5.3.0-posix-dwarf-rt_v4-rev0/mingw32
                else
                    echo "Don't support ${TOOLCHAIN_VERSION} ${Platform} in appveyor."
                    cd ${PROJECT_DIR}
                    exit 0
                fi
            ;;
        esac
            
        if [ "${Platform}" = "64" ]; then
             export BUILD_CROSS_HOST=x86_64-w64-mingw32
        else
             export BUILD_CROSS_HOST=i686-w64-mingw32
        fi
        export BUILD_CROSS_SYSROOT=${MINGW_PATH}/${BUILD_CROSS_HOST}
        export PATH=${MINGW_PATH}/bin:$PATH
        CMAKE_PARA="${CMAKE_PARA} -DCMAKE_TOOLCHAIN_FILE=$PROJECT_DIR/cmake/Platforms/toolchain-mingw.cmake"
    ;;
    android*)
        PRJ_GEN="MSYS Makefiles"
        
        if [ "${APPVEYOR_BUILD_WORKER_IMAGE}" = "Visual Studio 2017" ]; then
            export ANDROID_NDK=/C/ProgramData/Microsoft/AndroidNDK64/android-ndk-r17
            HOST=windows-x86_64
        else
            export ANDROID_NDK=/C/ProgramData/Microsoft/AndroidNDK/android-ndk-r10e
            HOST=windows
        fi
        CMAKE_PARA="${CMAKE_PARA} -DCMAKE_TOOLCHAIN_FILE=$PROJECT_DIR/cmake/Platforms/android.toolchain.cmake"
    
        case ${BUILD_TARGERT} in
            android_arm)
                if [ "${Platform}" = "64" ]; then
                    CMAKE_PARA="${CMAKE_PARA} -DANDROID_ABI=arm64-v8a"
                    export BUILD_CROSS_HOST=aarch64-linux-android
                    export BUILD_CROSS_SYSROOT=${ANDROID_NDK}/platforms/android-${ANDROID_API}/arch-arm64
                else
                    export BUILD_CROSS_HOST=arm-linux-androideabi
                    CMAKE_PARA="${CMAKE_PARA} -DANDROID_ABI=armeabi-v7a"
                    export BUILD_CROSS_SYSROOT=${ANDROID_NDK}/platforms/android-${ANDROID_API}/arch-arm
                fi
            ;;
            android_x86)
                if [ "${Platform}" = "64" ]; then
                    export BUILD_CROSS_HOST=x86_64
                    CMAKE_PARA="${CMAKE_PARA} -DANDROID_ABI=x86_64"
                    export BUILD_CROSS_SYSROOT=${ANDROID_NDK}/platforms/android-${ANDROID_API}/arch-x86_64
                else
                    export BUILD_CROSS_HOST=x86
                    CMAKE_PARA="${CMAKE_PARA} -DANDROID_ABI=x86"
                    export BUILD_CROSS_SYSROOT=${ANDROID_NDK}/platforms/android-${ANDROID_API}/arch-x86
                fi
            ;;
        esac
        ANDROID_TOOLCHAIN_NAME=${BUILD_CROSS_HOST}-${TOOLCHAIN_VERSION}
        TOOLCHAIN_ROOT=${ANDROID_NDK}/toolchains/${ANDROID_TOOLCHAIN_NAME}/prebuilt/${HOST}
        export PATH=${TOOLCHAIN_ROOT}/bin:$PATH
        CMAKE_PARA="${CMAKE_PARA} -DANDROID_TOOLCHAIN_NAME=${ANDROID_TOOLCHAIN_NAME}"
    ;;
esac

#Build libevent
if [ ! -d /c/projects/libevent ]; then
    cd /c/projects
    mkdir -p build_libevent
    cd build_libevent
    LIBEVENT_FILE=release-2.1.8-stable 
    wget -q https://github.com/libevent/libevent/archive/${LIBEVENT_FILE}.tar.gz 
    tar -xzf ${LIBEVENT_FILE}.tar.gz
    cd libevent-${LIBEVENT_FILE}
    cmake . \
        -G"${PRJ_GEN}" \
        -DCMAKE_INSTALL_PREFIX="/c/projects/libevent" \
        -DCMAKE_VERBOSE_MAKEFILE=ON \
        -DEVENT__DISABLE_OPENSSL=ON \
        ${CMAKE_PARA}
    cmake --build . --target install
fi

CMAKE_PARA="${CMAKE_PARA} -DLibevent_DIR=/c/projects/libevent/cmake"

cd ${PROJECT_DIR}
mkdir -p build-cmake
cd build-cmake
echo "cmake .. -G\"${PRJ_GEN}\" -DCMAKE_INSTALL_PREFIX="${PROJECT_DIR}/install" -DCMAKE_BUILD_TYPE=${Configuration} ${CMAKE_PARA}"
cmake .. \
    -G"${PRJ_GEN}" \
    -DCMAKE_INSTALL_PREFIX="${PROJECT_DIR}/install" \
    -DCMAKE_BUILD_TYPE=${Configuration} \
    -DCMAKE_VERBOSE_MAKEFILE=ON \
    ${CMAKE_PARA}
cmake --build . --config ${Configuration} --target install --clean-first   

cd ${PROJECT_DIR}
