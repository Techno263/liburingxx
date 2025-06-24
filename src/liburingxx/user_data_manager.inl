#include <liburingxx/splitmix64.hpp>
#include <liburingxx/xoshiro256pp.hpp>
#include <ratio>

namespace io_uring {

template<typename T>
user_data_manager<T>::user_data_manager(std::uint32_t entries)
    : user_data_manager(entries, std::chrono::high_resolution_clock::now().time_since_epoch().count())
{
    // assert clock representation is 64-bits
    static_assert(sizeof(std::chrono::high_resolution_clock::duration::rep) == sizeof(std::uint64_t));
    // assert clock is nano-resolution or finer
    static_assert(std::ratio_less_equal_v<std::chrono::high_resolution_clock::period, std::nano>);
}

template<typename T>
user_data_manager<T>::user_data_manager(std::uint32_t entries, std::uint64_t version_seed)
{
    user_data.resize(entries);
    alloc_map.resize(entries, false);
    versions.reserve(entries);
    next_index_hint = 0;
    // Randomize version value to mitigate potential collision between handles
    // from different resource-manager instances
    splitmix64 sm64(version_seed);
    xoshiropp xsrpp(sm64.next(), sm64.next(), sm64.next(), sm64.next());
    for (std::uint64_t i = 0; i < entries; i += 2) {
        std::uint64_t rnd_val = xsrpp.next();
        std::uint32_t version1 = static_cast<std::uint32_t>(rnd_val);
        versions.push_back(version1);
        if (i + 1 < entries) {
            std::uint32_t version2 = static_cast<std::uint32_t>(rnd_val >> 32);
            versions.push_back(version2);
        }
    }
}

template<typename T>
template<typename... Args>
handle user_data_manager<T>::allocate(Args&&... args)
{
    std::uint32_t index = get_released_index();
    alloc_map[index] = true;
    std::uint32_t version = versions[index];
    handle output(index, version);
    std::construct_at(user_data[output.index()].get(), std::forward<Args>(args)...);
    return output;
}

template<typename T>
void user_data_manager<T>::release(handle handle)
{
    if (!validate_handle(handle)) {
        throw std::runtime_error("invalid handle");
    }
    alloc_map[handle.index()] = false;
    versions[handle.index()] += 1;
    std::destroy_at(user_data[handle.index()].get());
    
}

template<typename T>
T& user_data_manager<T>::get_data(handle handle)
{
    if (!validate_handle(handle)) {
        throw std::runtime_error("invalid handle");
    }
    return *(user_data[handle.index()]);
}

template<typename T>
std::uint32_t user_data_manager<T>::get_released_index()
{
    std::uint32_t start_index = next_index_hint;
    std::uint32_t i = next_index_hint;
    for (; i < alloc_map.size(); ++i) {
        if (!alloc_map[i]) {
            if (i + 1 < alloc_map.size()) {
                next_index_hint = i + 1;
            } else {
                next_index_hint = 0;
            }
            return i;
        }
    }
    i = 0;
    for (; i < start_index; ++i) {
        if (alloc_map[i]) {
            // no need to check `i + 1 < alloc_map.size()` because `i < start_index`
            // and start_index is always a valid index less than alloc_map.size()
            next_index_hint = i + 1;
            return i;
        }
    }
    // no available index
    throw std::runtime_error("unable to find released index");
}

template<typename T>
bool user_data_manager<T>::validate_handle(handle handle)
{
    if (handle.index() >= user_data.size()) {
        // index out of range, handle is invalid
        return false;
    }
    if (!alloc_map[handle.index()]) {
        // user_data index is not in-use, handle is invalid
        return false;
    }
    if (handle.version() != versions[handle.index()]) {
        // handle version does not match expected version, handle is invalid
        return false;
    }
    return true;
}

template<typename T>
handle user_data_manager<T>::allocate_helper()
{
    std::uint32_t index = get_released_index();
    alloc_map[index] = true;
    std::uint32_t version = versions[index];
    handle output(index, version);
    return output;
}

}
