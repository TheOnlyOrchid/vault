#include "password_manager.h"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "secure_memory.h"
#include "secret_string.h"
#include <GLFW/glfw3.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

static void set_status(char* dst, std::size_t dst_len, const char* msg) {
    if (!dst || dst_len == 0) return;
    std::snprintf(dst, dst_len, "%s", (msg ? msg : ""));
}

int main(int, char**) {
    // self explanatory, sets the error callback
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

    // glsl needs char* not string
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(800, 600, "Password Manager", NULL, NULL);
    if (window == NULL)
        return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    PasswordManager pm;
    bool initialized = false;

    // reserved memory
    char masterPassword[128] = "";
    char service[128] = "";
    char password[128] = "";

    char statusMessage[256] = "Enter master password to initialize";
    bool showPassword = false;
    std::vector<std::string> servicesList;
    int selectedService = -1;
    int prevSelectedService = -1;
    bool prevShowPassword = false;
    SecretString selectedPassword;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("Password Manager", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
        ImGui::SetWindowSize(ImVec2(800, 600));

        if (!initialized) {
            ImGui::Text("Password Manager Initialization");
            ImGui::Separator();
            ImGui::InputTextWithHint("Master Password", "Enter your master password", masterPassword, IM_ARRAYSIZE(masterPassword), ImGuiInputTextFlags_Password);

            if (ImGui::Button("Initialize")) {
                try {
                    if (strlen(masterPassword) == 0) {
                        set_status(statusMessage, sizeof(statusMessage), "Master password cannot be empty");
                    }
                    else {
                        SecretString master = SecretString::from_cstr(masterPassword);
                        const bool ok = pm.initialize(master);
                        master.wipe();
                        secure::zeroize(masterPassword, sizeof(masterPassword));

                        if (ok) {
                        initialized = true;
                            set_status(statusMessage, sizeof(statusMessage), "Password manager initialized successfully");
                        } else {
                            set_status(statusMessage, sizeof(statusMessage), "Initialization failed");
                        }
                    }
                }
                catch (const std::exception& e) {
                    set_status(statusMessage, sizeof(statusMessage), e.what());
                }
            }
        }
        else {
            ImGui::Text("Password Manager");
            ImGui::Separator();

            ImGui::Text("Add/Update Password");
            ImGui::InputTextWithHint("Service", "e.g. Gmail, Facebook", service, IM_ARRAYSIZE(service));
            ImGui::InputTextWithHint("Password", "Enter password", password, IM_ARRAYSIZE(password), showPassword ? 0 : ImGuiInputTextFlags_Password);
            ImGui::Checkbox("Show password", &showPassword);

            if (ImGui::Button("Save Password")) {
                if (strlen(service) == 0 || strlen(password) == 0) {
                    set_status(statusMessage, sizeof(statusMessage), "Both service and password must be filled in.");
                }
                else {
                    SecretString pw = SecretString::from_cstr(password);
                    pm.addPassword(service, pw);
                    pw.wipe();

                    std::snprintf(statusMessage, sizeof(statusMessage), "Password saved for: %s", service);
                    std::memset(service, 0, sizeof(service));
                    secure::zeroize(password, sizeof(password));
                }
            }

            ImGui::Separator();

            ImGui::Text("Password Management");

            servicesList.clear();
            servicesList = pm.listServices();

            if (ImGui::Button("Refresh List")) {
                servicesList = pm.listServices();
            }

            ImGui::SameLine();
            if (ImGui::Button("Delete Selected") && selectedService >= 0) {
                if (selectedService >= 0 && selectedService < servicesList.size()) {
                    pm.deletePassword(servicesList[selectedService]);
                    std::snprintf(statusMessage, sizeof(statusMessage), "Deleted password for: %s", servicesList[selectedService].c_str());
                    selectedService = -1;
                    servicesList = pm.listServices();
                    selectedPassword.wipe();
                }
            }

            if (ImGui::BeginListBox("Services", ImVec2(-1, 100))) {
                for (int i = 0; i < servicesList.size(); i++) {
                    const bool is_selected = (selectedService == i);
                    if (ImGui::Selectable(servicesList[i].c_str(), is_selected)) {
                        selectedService = i;
                    }

                    if (is_selected) {
                        ImGui::SetItemDefaultFocus();
                    }
                }
                ImGui::EndListBox();
            }

            if (selectedService >= 0 && selectedService < servicesList.size()) {
                ImGui::Text("Selected: %s", servicesList[selectedService].c_str());

                if (selectedService != prevSelectedService) {
                    selectedPassword.wipe();
                    prevSelectedService = selectedService;
                }

                if (!showPassword && prevShowPassword) {
                    selectedPassword.wipe();
                }
                prevShowPassword = showPassword;

                if (showPassword && selectedPassword.empty()) {
                    selectedPassword = pm.getPassword(servicesList[selectedService]);
                }

                ImGui::Text("Password: %s", showPassword ? selectedPassword.c_str() : "********");

                if (ImGui::Button("Copy Password")) {
                    if (selectedPassword.empty()) {
                        selectedPassword = pm.getPassword(servicesList[selectedService]);
                    }
                    ImGui::SetClipboardText(selectedPassword.c_str());
                    selectedPassword.wipe(); // don't keep it around after copying
                    set_status(statusMessage, sizeof(statusMessage), "Password copied to clipboard");
                }
            }
        }

        ImGui::Separator();
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "%s", statusMessage);

        ImGui::End();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
