#include "password_manager.h"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <iostream>
#include <vector>

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int, char**) {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

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
    char masterPassword[128] = "";
    char service[128] = "";
    char password[128] = "";
    char statusMessage[256] = "Enter master password to initialize";
    bool showPassword = false;
    std::vector<std::string> servicesList;
    int selectedService = -1;

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
                        strcpy(statusMessage, "Master password cannot be empty");
                    }
                    else if (pm.initialize(masterPassword)) {
                        initialized = true;
                        strcpy(statusMessage, "Password manager initialized successfully");
                    }
                    else {
                        strcpy(statusMessage, "Initialization failed");
                    }
                }
                catch (const std::exception& e) {
                    strcpy(statusMessage, e.what());
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
                    strcpy(statusMessage, "Service and password cannot be empty");
                }
                else {
                    pm.addPassword(service, password);
                    strcpy(statusMessage, (std::string("Password saved for: ") + service).c_str());
                    memset(service, 0, sizeof(service));
                    memset(password, 0, sizeof(password));
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
                    strcpy(statusMessage, (std::string("Deleted password for: ") + servicesList[selectedService]).c_str());
                    selectedService = -1;
                    servicesList = pm.listServices();
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
                std::string pwd = pm.getPassword(servicesList[selectedService]);
                ImGui::Text("Password: %s", showPassword ? pwd.c_str() : "********");

                if (ImGui::Button("Copy Password")) {
                    ImGui::SetClipboardText(pwd.c_str());
                    strcpy(statusMessage, "Password copied to clipboard");
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