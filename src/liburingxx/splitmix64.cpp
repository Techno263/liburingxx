// Code adapted from splitmix64 algorithm by Sebastiano Vigna

#include <liburingxx/splitmix64.hpp>

namespace io_uring {

splitmix64::splitmix64(std::uint64_t x) noexcept
    : x(x)
{}

std::uint64_t splitmix64::next()
{
    uint64_t z = (x += 0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

}
