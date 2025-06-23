#pragma once

#include <cstdint>

namespace io_uring {

class handle {
public:
    handle() = delete;
    handle(const handle&) = default;
    handle(handle&&) noexcept = default;

    handle(std::uint32_t index, std::uint32_t version);

    handle& operator=(const handle&) = default;
    handle& operator=(handle&&) noexcept = default;

    ~handle() noexcept = default;

    std::uint32_t index() const noexcept;

    std::uint32_t version() const noexcept;

private:
    std::uint32_t _index;
    std::uint32_t _version;
};

// Ensure the handle is 8 bytes (64 bits) in size
static_assert(sizeof(handle) == 8);

}
