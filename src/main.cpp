#include "password_manager.h"
#include <iostream>
#include <sstream>

void printUsage() {
    std::cout << "\nPassword Manager Commands:" << std::endl;
    std::cout << "  add <service> <password> - Add or update password for service" << std::endl;
    std::cout << "  get <service>            - Get password for service" << std::endl;
    std::cout << "  list                     - List all services" << std::endl;
    std::cout << "  delete <service>         - Remove a password" << std::endl;
    std::cout << "  help                     - For help" << std::endl;
    std::cout << "  quit                     - Exit program" << std::endl;
}

int main() {
    std::cout << "=--= Password Manager =--=" << std::endl;

    std::cout << "Enter master password: ";
    std::string masterPassword;
    std::getline(std::cin, masterPassword);

    if (masterPassword.empty()) {
        std::cerr << "Master password cannot be empty" << std::endl;
        return 1;
    }

    PasswordManager pm;
    if (!pm.initialize(masterPassword)) {
        std::cerr << "Failed to initialize password manager" << std::endl;
        return 1;
    }

    std::cout << "Password manager initialized" << std::endl;
    printUsage();

    std::string command;
    while (true) {
        std::cout << "\n> ";
        std::getline(std::cin, command);

        std::istringstream iss(command);
        std::string action;
        iss >> action;

        if (action == "quit" || action == "exit") {
            break;
        }

        else if (action == "help") {
            printUsage();
        }

        else if (action == "add") {
            std::string service, password;
            iss >> service >> password;
            if (service.empty() || password.empty()) {
                std::cout << "Usage: add <service> <password>" << std::endl;
            }
            else {
                pm.addPassword(service, password);
            }
        }

        else if (action == "get") {
            std::string service;
            iss >> service;
            if (service.empty()) {
                std::cout << "Usage: get <service>" << std::endl;
            }
            else {
                pm.getPassword(service);
            }
        }

        else if (action == "list") {
            pm.listServices();
        }

        else if (action == "delete") {
            std::string service;
            iss >> service;
            if (service.empty()) {
                std::cout << "Usage: delete <service>" << std::endl;
            }
            else {
                pm.deletePassword(service);
            }
        }

        else if (!action.empty()) {
            std::cout << "Unknown command: " << action << std::endl;
            std::cout << "Type 'help' for available commands." << std::endl;
        }
    }

    std::cout << "Goodbye!" << std::endl;
    return 0;
}