#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

namespace sm::common {

class InputReader {
public:
    InputReader()
        : worker_([this] {
            std::string line;
            while (!stop_worker_.load() && std::getline(std::cin, line)) {
                std::lock_guard<std::mutex> lock(mutex_);
                queue_.push(line);
                cv_.notify_one();
            }
            std::lock_guard<std::mutex> lock(mutex_);
            eof_ = true;
            cv_.notify_all();
        }) {
        worker_.detach();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!queue_.empty()) {
            queue_.pop();
        }
    }

    bool read_line(std::string& line, const std::atomic_bool& stop_flag) {
        std::unique_lock<std::mutex> lock(mutex_);
        while (queue_.empty() && !stop_flag.load() && !eof_) {
            cv_.wait_for(lock, std::chrono::milliseconds(100));
        }
        if (stop_flag.load() || (queue_.empty() && eof_)) {
            return false;
        }
        if (!queue_.empty()) {
            line = std::move(queue_.front());
            queue_.pop();
            return true;
        }
        return false;
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::string> queue_;
    std::atomic_bool stop_worker_{false};
    bool eof_{false};
    std::thread worker_;
};

}
