#pragma once

// Code adapted from xoshiro256++ algorithm by David Blackman and Sebastiano Vigna

#include <cstdint>

namespace io_uring {

class xoshiropp {
public:
    xoshiropp();
    xoshiropp(const xoshiropp&) = delete;
    xoshiropp(xoshiropp&&) noexcept = default;

    explicit xoshiropp(const std::uint64_t s[4]) noexcept;

    xoshiropp(std::uint64_t s0, std::uint64_t s1, std::uint64_t s2, std::uint64_t s3) noexcept;

    xoshiropp& operator=(const xoshiropp&) = delete;
    xoshiropp& operator=(xoshiropp&&) noexcept = default;

    ~xoshiropp() noexcept = default;

    std::uint64_t next() noexcept;

    void jump() noexcept;

    void long_jump() noexcept;

private:
    std::uint64_t s[4];
};

}
