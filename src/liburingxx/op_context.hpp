#pragma once

#include <liburingxx/prep_op.hpp>

namespace io_uring {

template<typename T>
class op_context {
public:
    op_context() = delete;

    op_context(const op_context&) = default;

    op_context(op_context&&) noexcept = default;

    op_context(const T& data, prep_op prep_op) noexcept;

    op_context(T&& data, prep_op prep_op) noexcept;

    op_context& operator=(const op_context&) = default;

    op_context& operator=(op_context&&) noexcept = default;

    ~op_context() noexcept = default;

    T& data() noexcept;

    const T& data() const noexcept;

    prep_op prep_op() noexcept;
private:
    T _data;
    prep_op _prep_op;
};

}

#include <liburingxx/op_context.inl>
