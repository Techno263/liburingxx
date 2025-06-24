#pragma once

// Code adapted from splitmix64 algorithm by Sebastiano Vigna

#include <cstdint

namespace io_uring {

class splitmix64 {
public:
    splitmix64() = delete;

    splitmix64(const splitmix64&) = delete;

    splitmix64(splitmix64&&) noexcept = default;

    explicit splitmix64(std::uint64_t x) noexcept;

    splitmix64& operator=(const splitmix64&) = delete;

    splitmix64& operator=(splitmix64&&) = default;

    ~splitmix64() noexcept = default;

    std::uint64_t next() noexcept;

private:
    std::uint64_t x;
};

}
