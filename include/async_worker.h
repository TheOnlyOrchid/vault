#pragma once

#include <chrono>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

class AsyncWorker {
public:
    ~AsyncWorker();

    template <typename Task>
    void start(const std::string& workingMessage, Task&& task);

    bool poll();
    bool consumeResult(bool& outSuccess, std::string& outMessage);
    bool isBusy() const;

private:
    struct Result {
        bool success = false;
        std::string message;
    };

    mutable std::mutex mutex_;
    std::future<void> worker_;
    std::optional<Result> pending_result_;
};

template <typename Task>
void AsyncWorker::start(const std::string&, Task&& task) {
    std::lock_guard lock(mutex_);
    if (worker_.valid() && worker_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
        throw std::runtime_error("Password manager is busy");
    }

    if (worker_.valid()) {
        worker_.get();
    }

    pending_result_.reset();

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
        pending_result_ = Result{success, std::move(message)};
    });
}
