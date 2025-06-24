#include <new>

namespace io_uring {

template<typename T>
constexpr T* aligned_block<T>::get() noexcept
{
    return std::launder(reinterpret_cast<T*>(data.data()));
}

template<typename T>
constexpr const T* aligned_block<T>::get() const noexcept
{
    return std::launder(reinterpret_cast<const T*>(data.data()));
}

template<typename T>
constexpr T& aligned_block<T>::operator*() noexcept
{
    return *get();
}

template<typename T>
constexpr const T& aligned_block<T>::operator*() const noexcept
{
    return *get();
}

template<typename T>
constexpr T* aligned_block<T>::operator->() noexcept
{
    return get();
}

template<typename T>
constexpr const T* aligned_block<T>::operator->() const noexcept
{
    return get();
}

}
