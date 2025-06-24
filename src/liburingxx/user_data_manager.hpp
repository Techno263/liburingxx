#pragma once

#include <vector>
#include <liburingxx/handle.hpp>
#include <liburingxx/aligned_block.hpp>

namespace io_uring {

template<typename T, bool >
class user_data_manager {
public:
    user_data_manager() = delete;

    user_data_manager(const user_data_manager&) = delete;

    user_data_manager(user_data_manager&&) noexcept = default;

    explicit user_data_manager(std::uint32_t entries);

    user_data_manager(std::uint32_t entries, std::uint64_t version_seed);

    user_data_manager& operator=(const user_data_manager&) = delete;

    user_data_manager& operator=(user_data_manager&&) noexcept = default;

    ~user_data_manager() noexcept = default;

    template<typename... Args>
    handle allocate(Args&&... args);
    
    void release(handle handle);

    T& get_data(handle handle);

private:
    std::uint32_t get_released_index();

    bool validate_handle(handle handle);

    handle allocate_helper();

    std::vector<AlignedBlock<T>> user_data;
    std::vector<bool> alloc_map;
    std::vector<uint32_t> versions;
    std::uint32_t next_index_hint;
};

}

#include <liburingxx/user_data_manager.inl>
