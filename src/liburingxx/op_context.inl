namespace io_uring {

template<typename T>
op_context<T>::op_context(const T& data, prep_op prep_op) noexcept
    : _data(data), _prep_op(prep_op)
{}

template<typename T>
op_context<T>::op_context(T&& data, prep_op prep_op) noexcept
    :data(data), prep_op(prep_op)
{}

template<typename T>
T& op_context<T>::data() noexcept
{
    return _data;
}

template<typename T>
const T& op_context<T>::data() noexcept
{
    return _data;
}

template<typename T>
prep_op op_context<T>::prep_op() noexcept
{
    return _prep_op;
}

}
