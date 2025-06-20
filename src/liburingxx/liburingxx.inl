#include <stdexcept>
#include <bit>

namspace io_uring {

inline void __buf_ring_cq_advance(ring* ring, buf_ring* br, int cq_count, int buf_count) noexcept
{
    __io_uring_buf_ring_cq_advance(ring, br, cq_count, buf_count);
}

inline void buf_ring_add(buf_ring* br, void* addr, unsigned int len, unsigned short bid, int mask, int buf_offset) noexcept
{
    io_uring_buf_ring_add(br, addr, len, bid, mask, buf_offset);
}

inline void buf_ring_advance(buf_ring* br, int count) noexcept
{
    io_uring_buf_ring_advance(br, count);
}

inline int buf_ring_available(ring* ring, buf_ring* br, unsigned short bgid)
{
    int ret;
    ret = io_uring_buf_ring_available(ring, br, bgid);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_buf_ring_available");
    }
    return ret;
}

inline void buf_ring_cq_advance(ring* ring, buf_ring* br, int count) noexcept
{
    io_uring_buf_ring_cq_advance(ring, br, count);
}

inline void buf_ring_init(buf_ring* br) noexcept
{
    io_uring_buf_ring_init(br);
}

inline int buf_ring_mask(std::uint32_t ring_entries) noexcept
{
    return io_uring_buf_ring_mask(ring_entries);
}

inline bool check_version(int major, int minor) noexcept
{
    return io_uring_check_version(major, minor);
}

inline void clone_buffers(ring* dst, ring* src)
{
    int ret;
    ret = io_uring_clone_buffers(dst, src);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_clone_buffers");
    }
}

inline void clone_buffers_offset(ring* dst, ring* src, unsigned int dst_off, unsigned int src_off, unsigned int nr, unsigned int flags)
{
    int ret;
    ret = io_uring_clone_buffers_offset(dst, src, dst_off, src_off, nr, flags);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_clone_buffers_offset");
    }
}

inline void close_ring_fd(ring* ring)
{
    int ret;
    ret = io_uring_close_ring_fd(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_close_ring_fd");
    }
    if (ret != 1) {
        throw std::runtime_error("io_uring_close_ring_fd unknown error");
    }
}

inline void cq_advance(ring* ring, unsigned nr) noexcept
{
    io_uring_cq_advance(ring, nr);
}

inline bool cq_has_overflow(const ring* ring) noexcept
{
    return io_uring_cq_has_overflow(ring);
}

inline unsigned cq_ready(const ring* ring) noexcept
{
    return io_uring_cq_ready(ring);
}

template<>
inline void* cqe_get_data<void>(cqe* cqe) noexcept
{
    return io_uring_cqe_get_data(cqe);
}

template<typename T>
inline T* cqe_get_data(cqe* cqe) noexcept
{
    return static_cast<T*>(cqe_get_data<void>(cqe));
}

template<>
inline std::uint64_t cqe_get_data64<std::uint64_t>(cqe* cqe)
{
    return io_uring_cqe_get_data64(cqe);
}

template<typename T>
requires (sizeof(T) < sizeof(std::uint64_t))
inline T cqe_get_data64(cqe* cqe) noexcept
{
    T output;
    std::uint64_t data = cqe_get_data64<std::uint64_t>(cqe);
    std::memcpy(&output, &data, sizeof(T));
    return output;
}

template<typename T>
requires (sizeof(T) == sizeof(std::uint64_t))
inline T cqe_get_data64(cqe* cqe) noexcept
{
    return std::bit_cast<T>(cqe_get_data_64<std::uint64_t>(cqe));
}

inline void cqe_seen(ring* ring, cqe* cqe) noexcept
{
    io_uring_cqe_seen(ring, cqe);
}

inline void enable_rings(ring* ring)
{
    int ret;
    ret = io_uring_enable_rings(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_enable_rings");
    }
}

inline int enter(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsinged_int flags, sigset_t* sig)
{
    int ret;
    ret = io_uring_enter(fd, to_submit, min_complete, flags, sig);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_enter");
    }
    return ret;
}

inline int enter2(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, void* arg, size_t sz)
{
    int ret;
    ret = io_uring_enter2(fd, to_submit, min_complete, flags, arg, sz);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_enter2");
    }
    return ret;
}

inline void free_buf_ring(ring* ring, buf_ring* br, unsigned int nentries, int bgid)
{
    int ret;
    ret = io_uring_free_buf_ring(ring, br, nentries, bgid);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_free_buf_ring");
    }
}

inline void free_probe(probe* probe) noexcept
{
    io_uring_free_probe(probe);
}

inline void free_reg_wait(ring* ring, unsigned nentries)
{
    io_uring_free_reg_wait(ring, nentries);
}

inline void get_events(ring* ring)
{
    int ret;
    ret = io_uring_get_events(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_get_events");
    }
}

inline probe* get_probe()
{
    probe* output;
    output = io_uring_get_probe();
    if (output == nullptr) {
        throw std::runtime_error("io_uring_get_probe failed");
    }
    return output;
}

inline sqe* get_sqe(ring* ring)
{
    sqe* output;
    output = io_uring_get_sqe(ring);
    if (output == nullptr) {
        throw std::runtime_error("SQ ring full");
    }
    return output;
}

inline int major_version() noexcept
{
    return io_uring_major_version();
}

inline int minor_version() noexcept
{
    return io_uring_minor_version();
}

inline bool opcode_supported(probe* probe, int opcode) noexcept
{
    return static_cast<bool>(io_uring_opcode_supported(probe, opcode));
}

inline void peek_batch_cqe(ring* ring, cqe** cqe_ptrs, unsigned count)
{
    int ret;
    ret = io_uring_peek_batch_cqe(ring, cqe_ptrs, count);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_peek_batch_cqe");
    }
}

inline void peek_cqe(ring* ring, cqe** cqe_ptr)
{
    int ret;
    ret = io_uring_peek_cqe(ring, cqe_ptr);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_peek_cqe");
    }
}

inline void prep_accept(sqe* sqe, int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) noexcept
{
    io_uring_prep_accept(sqe, sockfd, addr, addrlen, flags);
}

inline void prep_accept_direct(sqe* sqe, int sockfd, sockaddr* addr, socklen_t* addrlen, int flags, unsigned int file_index) noexcept
{
    io_uring_prep_accept_direct(sqe, sockfd, addr, addrlen, flags, file_index);
}

inline void prep_bind(sqe* sqe, int sockfd, sockaddr* addr, socklen_t addrlen) noexcept
{
    io_uring_prep_bind(sqe, sockfd, addr, addrlen);
}

inline void prep_cancel(sqe* sqe, void* user_data, unsigned int flags) noexcept
{
    io_uring_prep_cancel(sqe, user_data, flags);
}

inline void prep_cancel64(sqe* sqe, std::uint64_t user_data, int flags) noexcept
{
    io_uring_prep_cancel64(sqe, user_data, flags);
}

inline void prep_cancel_fd(sqe* sqe, int fd, unsigned int flags) noexcept
{
    io_uring_prep_cancel_fd(sqe, fd, flags);
}

inline void prep_close(sqe* sqe, int fd) noexcept
{
    io_uring_prep_close(sqe, fd);
}

inline void prep_close_direct(sqe* sqe, unsigned file_index) noexcept
{
    io_uring_prep_close_direct(sqe, file_index);
}

inline void prep_cmd_sock(sqe* sqe, int cmd_op, int fd, int level, int optname, void* optval, int optlen) noexcept
{
    io_uring_prep_cmd_sock(sqe, cmd_op, fd, level, optname, optval, optlen);
}

inline void prep_cmd_discard(sqe* sqe, int fd, std::uint64_t offset, std::uint64_t nbytes) noexcept
{
    io_uring_prep_cmd_discard(sqe, fd, offset, nbytes);
}

inline void prep_connect(sqe* sqe, int sockfd, const sockaddr* addr, socklen_t addrlen) noexcept
{
    io_uring_prep_connect(sqe, sockfd, addr, addrlen);
}

inline void prep_fadvise(sqe* sqe, int fd, std::uint64_t offset, std::uint32_t len, int advice) noexcept
{
    io_uring_prep_fadvise(sqe, fd, offset, len, advice);
}

inline void prep_fadvise64(sqe* sqe, int fd, std::uint64_t offset, off_t len, int advice) noexcept
{
    io_uring_prep_fadvise64(sqe, fd, offset, len, advice);
}

inline void prep_fallocate(sqe* sqe, int fd, int mode, std::uint64_t offset, std::uint64_t len) noexcept
{
    io_uring_prep_fallocate(sqe, fd, mode, offset, len);
}

inline void prep_fgetxattr(sqe* sqe, int fd, const char* name, char* value, unsigned int len) noexcept;
{
    io_uring_prep_fgetxattr(sqe, fd, name, value, len);
}

inline void prep_files_update(sqe* sqe, int* fds, unsigned nr_fds, int offset) noexcept
{
    io_uring_prep_files_update(sqe, fds, nr_fds, offset);
}

}
