cmake_minimum_required(VERSION 3.16)
project(Cryptolib)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

set(SOURCES
    main.cpp
    hmac.cpp
    keygen.cpp
    md5.cpp
    rsa.cpp
    sha1.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})