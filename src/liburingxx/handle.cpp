#include <liburingxx/handle.hpp>

namespace io_uring {

handle::handle(std::uint32_t index, std::uint32_t version)
    : _index(index), _version(version)
{}

std::uint32_t handle::index() const noexcept
{
    return _index;
}

std::uint32_t handle::version() const noexcept
{
    return _version;
}

}
