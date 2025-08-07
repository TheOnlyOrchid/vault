cmake_minimum_required(VERSION 3.20)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_TOOLCHAIN_FILE "D:/.coding/repos/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

project(PasswordManager)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(PasswordManager
  "src/main_cli.cpp"
  "src/main.cpp"
  "src/password_manager.cpp"
  "src/file_utils.cpp"
  "src/crypto_utils.cpp"
)

target_include_directories(PasswordManager PRIVATE include)

# Dependencies

find_package(OpenSSL REQUIRED)
target_link_libraries(PasswordManager PRIVATE OpenSSL::SSL OpenSSL::Crypto)

find_package(glfw3 CONFIG REQUIRED)
find_package(OpenGL REQUIRED)
target_link_libraries(PasswordManager PRIVATE glfw OpenGL::GL)

# ImGui

file(GLOB IMGUI_SRC
    ${CMAKE_SOURCE_DIR}/external/imgui/*.cpp
    ${CMAKE_SOURCE_DIR}/external/imgui/backends/imgui_impl_glfw.cpp
    ${CMAKE_SOURCE_DIR}/external/imgui/backends/imgui_impl_opengl3.cpp
)

add_library(imgui STATIC ${IMGUI_SRC})
target_include_directories(imgui PUBLIC
    ${CMAKE_SOURCE_DIR}/external/imgui
    ${CMAKE_SOURCE_DIR}/external/imgui/backends
)
target_link_libraries(imgui PUBLIC glfw OpenGL::GL)

target_link_libraries(PasswordManager PRIVATE imgui)
