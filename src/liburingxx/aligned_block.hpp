#pragma once

#include <array>
#include <cstddef>

namespace io_uring {

template<typename T>
struct aligned_block {
public:
    constexpr T* get() noexcept;

    constexpr const T* get() const noexcept;

    constexpr T& operator*() noexcept;

    constexpr const T& operator*() const noexcept;

    constexpr T* operator->() noexcept;

    constexpr const T* operator->() const noexcept;

private:
    alignas(T) std::array<std::byte, sizeof(T)> data;
};

}

#include <liburingxx/aligned_block.inl>
