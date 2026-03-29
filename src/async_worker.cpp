#include "async_worker.h"

#include <chrono>

// Destructor
AsyncWorker::~AsyncWorker() {
    std::future<void> worker;
    {
        // locks to safely access worker_
        std::lock_guard lock(mutex_);

        if (worker_.valid()) {
            // here we transfer ownership from worker_ to worker,
            worker = std::move(worker_);
        }

    // mutex is unlocked here
    }

    // wait for the completion THEN destruct it
    if (worker.valid()) {
        worker.wait();
    }
}

bool AsyncWorker::poll() {
    std::future<void> worker;
    {
        // locks to safely access worker_
        std::lock_guard lock(mutex_);

        // safety check
        if (!worker_.valid()) {
            return false;
        }

        // checks instantly (non blocking), and checks if the task is done.
        if (worker_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
            return false;
        }

        // here we transfer ownership from worker_ to worker,
        // so we can release the lock early and safely call .get() from outside the mutex.
        worker = std::move(worker_);

    // just a note that the mutex is unlocked here
    }

    worker.get();
    return true;
}

// if true, the string + bool input will be "filled in", if false, they wont.
bool AsyncWorker::consumeResult(bool& outSuccess, std::string& outMessage) {
    // lock to safely access worker_
    std::lock_guard lock(mutex_);

    // check if a result actually exists
    if (!pending_result_) {
        return false;
    }

    // if a result does exist, write it to the "return" values.
    outSuccess = pending_result_->success;
    outMessage = std::move(pending_result_->message);
    pending_result_.reset();
    return true;
}

bool AsyncWorker::isBusy() const {
    std::lock_guard lock(mutex_);
    return worker_.valid() && worker_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;
}
