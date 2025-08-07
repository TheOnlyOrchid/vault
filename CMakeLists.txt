cmake_minimum_required (VERSION 3.8)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_TOOLCHAIN_FILE "D:/.coding/repos/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

project ("PasswordManager")

add_executable(PasswordManager
  src/main.cpp
  src/password_manager.cpp
  src/file_utils.cpp
  src/crypto_utils.cpp
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET PasswordManager PROPERTY CXX_STANDARD 20)
endif()

find_package(OpenSSL REQUIRED)
target_include_directories(PasswordManager PRIVATE include)
target_link_libraries(PasswordManager OpenSSL::SSL OpenSSL::Crypto)