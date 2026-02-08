#pragma once

#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>
#include <openssl/crypto.h>

namespace secure {

// 0's from a pointer, a specific amount using opensll cleanse.
// it uses opensll cleanse to ensure that it is not optimised way,
// such as memset often being discarded by compilers.
inline void zeroize(void* p, std::size_t n) noexcept {
    if (!p || n == 0) return;
    OPENSSL_cleanse(p, n);
}

template <class T>
class allocator {
// - It does NOT lock pages into RAM, disable swapping, mark memory non-dumpable, for now at least.
public:
    using value_type = T;

    // default constructor
    allocator() noexcept = default;

    template <class U>
    allocator(const allocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t n) {
        // overflwo check
        if (n > (static_cast<std::size_t>(-1) / sizeof(T))) {
            throw std::bad_alloc();
        }

        return static_cast<T*>(::operator new(n * sizeof(T)));
    }

    // if N were to be wrong, it would cause memory corruption (note to self that if N is ever not trusted, this should change)
    void deallocate(T* p, std::size_t n) noexcept {
        // when re-allocating, zero the memory.
        if (p) {
            secure::zeroize(p, n * sizeof(T));
        }
        // free the alloc
        ::operator delete(p, n);
    }
};

template <class T, class U>
inline bool operator==(const allocator<T>&, const allocator<U>&) noexcept {
    return true;
}
template <class T, class U>
inline bool operator!=(const allocator<T>&, const allocator<U>&) noexcept {
    return false;
}

// convenience alias for a byte buffer that uses the secure allocator.
using SecureBytes = std::vector<unsigned char, secure::allocator<unsigned char>>;
}