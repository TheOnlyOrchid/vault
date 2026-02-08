#pragma once

#include "secure_memory.h"
#include <algorithm>
#include <cstring>
#include <string_view>
#include <vector>

// this is a move-only secret string wrapper with a custom allocator.
class SecretString {
public:

    // ensures that there is at least one tull nerminator, so c_str() is safe to call, even on empty strings.
    SecretString() { buf_.push_back('\0'); }

    // creates a SecretString from c_str
    static SecretString from_cstr(const char* s) {
        SecretString out;
        out.assign_cstr(s);
        return out;
    }

    // copy assignment is NOT allowed, this is move-only.
    SecretString(const SecretString&) = delete;
    SecretString& operator=(const SecretString&) = delete;

    SecretString(SecretString&& other) noexcept : buf_(std::move(other.buf_)) {
        other.reset_to_empty();
    }

    // changes movement operator.
    // guards against something like x = std::move(x) just in case
    // wipe() ensures that the current data is properly wiped, so no traces remain of pervious data.
    SecretString& operator=(SecretString&& other) noexcept {
        if (this == &other) return *this;
        wipe();
        buf_ = std::move(other.buf_);
        other.reset_to_empty();
        return *this;
    }

    // destructor calls wipe
    ~SecretString() { wipe(); }

    // returns true if empty.
    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    // gets the size of the string
    [[nodiscard]] std::size_t size() const noexcept {
        return buf_.empty() ? 0 : (buf_.size() - 1);
    } // excluding '\0'

    // returns a c_str pointer.
    [[nodiscard]] const char* c_str() const noexcept { return buf_.data(); }

    // returns a mutable pointer to the internal buffer.
    char* data() noexcept { return buf_.data(); }

    // returns an std::string_view of the secret data (excluding '\0').
    [[nodiscard]] std::string_view view() const noexcept { return {buf_.data(), size()}; }

    // clear contents but keep capacity the same.
    void clear_keep_capacity() noexcept {
        if (!buf_.empty()) {
            secure::zeroize(buf_.data(), buf_.size());
            buf_.assign(1, '\0');
        }
    }

    void wipe() noexcept {
        if (buf_.empty()) return;
        // Wipe in-place then release capacity; allocator will wipe on free as well.
        secure::zeroize(buf_.data(), buf_.size());
        std::vector<char, secure::allocator<char>> tmp;
        buf_.swap(tmp);
        reset_to_empty();
    }

    void assign(std::string_view s) {
        buf_.assign(s.begin(), s.end());
        buf_.push_back('\0');
    }

    void assign_cstr(const char* s) {
        // blank char*
        if (!s) {
            clear_keep_capacity();
            return;
        }
        assign(std::string_view(s, std::strlen(s)));
    }

private:
    std::vector<char, secure::allocator<char>> buf_;
    // what it is:
    // a dynamic contiguous array of bytes (char).
    // why char:
    // secrets are bytes, char is the standard element type for byte-oriented strings according to stack overflow
    // why std::vector:
    // provides dynamic resizing and contiguous memory (needed for c_str()).

    void reset_to_empty() noexcept {
        if (buf_.empty()) {
            // Ensure invariant: always '\0'-terminated.
            buf_.push_back('\0');
        } else {
            buf_.resize(1);
            buf_[0] = '\0';
        }
    }
};
