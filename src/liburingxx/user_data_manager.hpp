#pragma once

#include <vector>
#include <liburingxx/handle.hpp>

namespace io_uring {

template<typename T>
class user_data_manager {
public:
    user_data_manager() = delete;
    user_data_manager(const user_data_manager&) = delete;
    user_data_manager(user_data_manager&&) noexcept = default;

    user_data_manager(std::uint32_t entries);

    user_data_manager& operator=(const user_data_manager&) = delete;
    user_data_manager& operator=(user_data_manager&&) noexcept = default;

    ~user_data_manager() noexcept = default;

    handle allocate();
    
    void release(handle handle);

    T& get_data(handle handle);

private:
    std::vector<T> user_data;
    std::vector<bool> use_map;
    std::vector<uint32_t> versions;
};

}
