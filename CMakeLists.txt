cmake_minimum_required(VERSION 3.10)
project(FileCrypto)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Найти OpenSSL
find_package(OpenSSL REQUIRED)
# Добавление исполняемого файла
add_executable(file_crypto main.cpp)

# Линковка с OpenSSL
target_link_libraries(file_crypto OpenSSL::Crypto OpenSSL::SSL)

# Если необходимо, вы можете добавить дополнительные параметры для компилятора
# Например, для Windows:
if (WIN32)
    target_compile_definitions(file_crypto PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()