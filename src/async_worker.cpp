#include "async_worker.h"

#include <chrono>

AsyncWorker::~AsyncWorker() {
    std::future<void> worker;
    {
        std::lock_guard lock(mutex_);
        if (worker_.valid()) {
            worker = std::move(worker_);
        }
    }

    if (worker.valid()) {
        worker.wait();
    }
}

bool AsyncWorker::poll() {
    std::future<void> worker;
    {
        std::lock_guard lock(mutex_);
        if (!worker_.valid()) {
            return false;
        }
        if (worker_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
            return false;
        }
        worker = std::move(worker_);
    }

    worker.get();
    return true;
}

bool AsyncWorker::consumeResult(bool& outSuccess, std::string& outMessage) {
    std::lock_guard lock(mutex_);
    if (!pending_result_) {
        return false;
    }

    outSuccess = pending_result_->success;
    outMessage = std::move(pending_result_->message);
    pending_result_.reset();
    return true;
}

bool AsyncWorker::isBusy() const {
    std::lock_guard lock(mutex_);
    return !working_message_.empty();
}

std::string AsyncWorker::currentStatusMessage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return working_message_;
}
