#pragma once

#include <future>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

class AsyncWorker {
public:
    ~AsyncWorker();

    template <typename Task>
    void start(std::string workingMessage, Task&& task);

    bool poll();
    bool consumeResult(bool& outSuccess, std::string& outMessage);
    bool isBusy() const;
    std::string currentStatusMessage() const;

private:
    mutable std::mutex mutex_;
    std::future<void> worker_;
    bool busy_ = false;
    bool completed_ = false;
    bool last_success_ = false;
    std::string working_message_;
    std::string completion_message_;
};

template <typename Task>
void AsyncWorker::start(std::string workingMessage, Task&& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (busy_) {
        throw std::runtime_error("Password manager is busy");
    }

    if (worker_.valid()) {
        worker_.get();
    }

    busy_ = true;
    completed_ = false;
    last_success_ = false;
    working_message_ = std::move(workingMessage);
    completion_message_.clear();

    worker_ = std::async(std::launch::async, [this, task = std::forward<Task>(task)]() mutable {
        bool success = false;
        std::string message;

        try {
            message = task();
            success = true;
        }
        catch (const std::exception& e) {
            message = e.what();
        }
        catch (...) {
            message = "Unknown background task failure";
        }

        std::lock_guard<std::mutex> taskLock(mutex_);
        busy_ = false;
        completed_ = true;
        last_success_ = success;
        completion_message_ = std::move(message);
        working_message_.clear();
    });
}
