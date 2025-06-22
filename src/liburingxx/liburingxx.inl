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

template<auto Func>
requires requires(cqe* c)
{
    { Func(c) } noexcept -> std::same_as<void>;
}
inline unsigned for_each_cqe(ring* ring, cqe* cqe)
{
    unsigned head;
    unsigned i = 0;
    io_uring_for_each_cqe(ring, head, cqe) {
        Func(cqe);
        i++;
    }
    return i;
}

template<auto Func>
requires requires(cqe* c)
{
    { Func(c) } noexcept -> std::same_as<void>;
}
inline void handle_cqes(ring* ring, cqe* cqr)
{
    unsigned i;
    i = for_each_cqe<Func>(ring, cqe);
    cq_advance(ring, i);
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

inline void prep_fixed_fd_install(sqe* sqe, int fd, unsigned int flags) noexcept
{
    io_uring_prep_fixed_fd_install(sqe, fd, flags);
}

inline void prep_fsetxattr(sqe* sqe, int fd, const char* name, const char* value, int flags, unsigned int len) noexcept
{
    io_uring_prep_fsetxattr(sqe, fd, name, value, flags, len);
}

inline void prep_fsync(sqe* sqe, int fd, unsigned flags) noexcept
{
    io_uring_prep_fsync(sqe, fd, flags);
}

inline void prep_ftruncate(sqe* sqe, int fd, loff_t len) noexcept
{
    io_uring_prep_ftruncate(sqe, fd, len);
}

inline void prep_futex_wait(sqe* sqe, std::uint32_t* futex, std::uint64_t val, std::uint64_t mask, std::uint32_t futex_flags, unsigned int flags) noexcept
{
    io_uring_prep_futex_wait(sqe, futex, val, mask, futex_flags, flags);
}

inline void prep_futex_waitv(sqe* sqe, futex_waitv* futexv, std::uint32_t nr_futex, unsigned int flags) noexcept
{
    io_uring_prep_futex_waitv(sqe, futexv, nr_futex, flags);
}

inline void prep_futex_wake(sqe* sqe, std::uint32_t* futex, std::uint64_t val, std::uint64_t mask, std::uint32_t futex_flags, unsigned int flags) noexcept
{
    io_uring_prep_futex_wake(sqe, futex, val, mask, futex_flags, flags);
}

inline void prep_getxattr(sqe* sqe, const char* name, char* value, const char* path, unsigned int len) noexcept
{
    io_uring_prep_getxattr(sqe, name, value, path, len);
}

inline void prep_link(sqe* sqe, const char* oldpath, const char* newpath, int flags) noexcept
{
    io_uring_prep_link(sqe, oldpath, newpath, flags);
}

inline void prep_link_timeout(sqe* sqe, kernel_timespec* ts, unsigned flags) noexcept
{
    io_uring_prep_link_timeout(sqe, ts, flags);
}

inline void prep_linkat(sqe* sqe, int olddirfd, const char* oldpath, int newdirfd, const char* newpath, int flags) noexcept
{
    io_uring_prep_linkat(sqe, olddirfd, oldpath, newdirfd, newpath, flags);
}

inline void prep_listen(sqe* sqe, int sockfd, int backlog) noexcept
{
    io_uring_prep_listen(sqe, sockfd, backlog);
}

inline void prep_madvise(sqe* sqe, void* addr, std::uint32_t len, int advice) noexcept
{
    io_uring_prep_madvise(sqe, addr, len, advice);
}

inline void prep_madvise64(sqe* sqe, void* addr, off_t len, int advise) noexcept
{
    io_uring_prep_madvise64(sqe, addr, len, advise);
}

inline void prep_mkdir(sqe* sqe, const char* path, mode_t mode) noexcept
{
    io_uring_prep_mkdir(sqe, path, mode);
}

inline void prep_mkdirat(sqe* sqe, int dirfd, const char* path, mode_t mode) noexcept
{
    io_uring_prep_mkdirat(sqe, dirfd, path, mode);
}

inline void prep_msg_ring(sqe* sqe, int fd, unsigned int len, std::uint64_t data, unsigned int flags, unsigned int cqe_flags) noexcept
{
    io_uring_prep_msg_ring(sqe, fd, len, data, flags, cqe_flags);
}

inline void prep_msg_ring_cqe_flags(sqe* sqe, int fd, unsigned int len, std::uint64_t data, unsigned int flags, unsigned int cqe_flags) noexcept
{
    io_uring_prep_msg_ring_cqe_flags(sqe, fd, len, data, flags, cqe_flags);
}

inline void prep_msg_ring_fd(sqe* sqe, int fd, int source_fd, int target_fd, std::uint64_t data, unsigned int flags) noexcept
{
    io_uring_prep_msg_ring_fd(sqe, fd, source_fd, target_fd, data, flags);
}

inline void prep_msg_ring_fd_alloc(sqe* sqe, int fd, int source_fd, std::uint64_t data, unsigned int flags) noexcept
{
    io_uring_prep_msg_ring_fd_alloc(sqe, fd, source_fd, data, flags);
}

inline void prep_multishot_accept(sqe* sqe, int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) noexcept
{
    io_uring_prep_multishot_accept(sqe, sockfd, addr, addrlen, flags);
}

inline void prep_multishot_accept_direct(sqe* sqe, int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) noexcept
{
    io_uring_prep_multishot_accept_direct(sqe, sockfd, addr, addrlen, flags);
}

inline void prep_nop(sqe* sqe) noexcept
{
    io_uring_prep_nop(sqe);
}

inline void prep_open(sqe* sqe, const char* path, int flags, mode_t mode) noexcept
{
    io_uring_prep_open(sqe, path, flags, mode);
}

inline void prep_open_direct(sqe* sqe, const char* path, int flags, mode_t mode, unsigned file_index) noexcept
{
    io_uring_prep_open_direct(sqe, path, flags, mode, file_index);
}

inline void prep_openat(sqe* sqe, int dfd, const char* path, int flags, mode_t mode) noexcept
{
    io_uring_prep_openat(sqe, dfd, path, flags, mode);
}

inline void prep_openat2(sqe* sqe, int dfd, const char* path, open_how* how) noexcept
{
    io_uring_prep_openat2(sqe, dfd, path, how);
}

inline void prep_openat2_direct(sqe* sqe, int dfd, const char* path, open_how* how, unsigned file_index) noexcept
{
    io_uring_prep_openat2_direct(sqe, dfd, path, how, file_index);
}

inline void prep_openat_direct(sqe* sqe, int dfd, const char* path, int flags, mode_t mode, unsigned file_index) noexcept
{
    io_uring_prep_openat_direct(sqe, dfd, path, flags, mode, file_index);
}

inline void prep_poll_add(sqe* sqe, int fd, unsigned poll_mask) noexcept
{
    io_uring_prep_poll_add(sqe, fd, poll_mask);
}

inline void prep_poll_multishot(sqe* sqe, int fd, unsigned poll_mask) noexcept
{
    io_uring_prep_poll_multishot(sqe, fd, poll_mask);
}

template<>
inline void prep_poll_remove<std::uint64_t>(sqe* sqe, std::uint64_t user_data) noexcept
{
    return io_uring_prep_poll_remove(sqe, user_data);
}

template<typename T>
requires (sizeof(T) < sizeof(std::uint64_t))
inline void prep_poll_remove(sqe* sqe, T user_data) noexcept
{
    std::uint64_t data = 0;
    std::memcpy(&data, &user_data, sizeof(T));
    prep_poll_remove<std::uint64_t>(sqe, data);
}

template<typename T>
requires (sizeof(T) == sizeof(std::uint64_t))
inline void prep_poll_remove(sqe* sqe, T user_data) noexcept
{
    prep_poll_remove<std::uint64_t>(sqe, std::bit_cast<std::uint64_t>(user_data));
}

template<>
inline void prep_poll_remove<void>(sqe* sqe, void* user_data) noexcept
{
    prep_poll_remove<std::uint64_t>(sqe, std::bit_cast<std::uint64_t>(user_data));
}

template<typename T>
inline void prep_poll_remove(sqe* sqe, T* user_data) noexcept
{
    prep_poll_remove(sqe, static_cast<void*>(user_data));
}

//inline void prep_poll_update(sqe* sqe, std::uint64_t old_user_data, std::uint64_t new_user_data, unsigned poll_mask, unsigned flags) noexcept

template<>
inline void prep_poll_update<std::uint64_t, std::uint64_t>(
    sqe* sqe, std::uint64_t old_user_data, std::uint64_t new_user_data, unsigned poll_mask, unsigned flags) noexcept
{
    io_uring_prep_poll_update(sqe, old_user_data, new_user_data, poll_mask, flags);
}

template<typename T, typename U>
requires (sizeof(T) == sizeof(std::uint64_t) && sizeof(U) == sizeof(stduint64_t))
inline void prep_poll_update(sqe* sqe, T old_user_data, U new_user_data, unsigned poll_mask, unsigned flags) noexcept
{
    prep_poll_update<std::uint64_t, std::uint64_t>(
        sqe,
        std::bit_cast<std::uint64_t>(old_user_data),
        std::bit_cast<std::uint64_t>(new_user_data),
        poll_mask,
        flags
    );
}

template<typename T, typename U>
requires (sizeof(T) == sizeof(std::uint64_t) && sizeof(U) < sizeof(stduint64_t))
inline void prep_poll_update(sqe* sqe, T old_user_data, U new_user_data, unsigned poll_mask, unsigned flags) noexcept
{
    std::uint64_t new_data = 0;
    std::memcpy(&new_data, &new_user_data, sizeof(U));
    prep_poll_update(sqe, old_user_data, new_data, poll_mask, flags);
}

template<typename T, typename U>
requires (sizeof(T) < sizeof(std::uint64_t) && sizeof(U) == sizeof(stduint64_t))
inline void prep_poll_update(sqe* sqe, T old_user_data, U new_user_data, unsigned poll_mask, unsigned flags) noexcept
{
    std::uint64_t old_data = 0;
    std::memcpy(&old_data, &new_user_data, sizeof(T));
    prep_poll_update(sqe, old_data, new_user_data, poll_mask, flags);
}

template<typename T, typename U>
requires (sizeof(T) < sizeof(std::uint64_t) && sizeof(U) < sizeof(stduint64_t))
inline void prep_poll_update(sqe* sqe, T old_user_data, U new_user_data, unsigned poll_mask, unsigned flags) noexcept
{
    std::uint64_t new_data = 0;
    std::memcpy(&new_data, &new_user_data, sizeof(U));
    std::uint64_t old_data = 0;
    std::memcpy(&old_data, &new_user_data, sizeof(T));
    prep_poll_update(sqe, old_data, new_data, poll_mask, flags);
}

template<typename T, typename U>
requires (sizeof(U) <= sizeof(std::uint64_t))
inline void prep_poll_update(sqe* sqe, T* old_user_data, U new_user_data, unsigned poll_mask, unsigned flags) noexcept
{
    uint64_t old_data = std::bit_cast<std::uint64_t>(old_user_data);
    prep_poll_update<T, U>(sqe, old_data, new_user_data, poll_mask, flags);
}

template<typename T, typename U>
requires (sizeof(T) <= sizeof(std::uint64_t))
inline void prep_poll_update(sqe* sqe, T old_user_data, U* new_user_data, unsigned poll_mask, unsigned flags) noexcept
{
    uint64_t new_data = std::bit_cast<std::uint64_t>(new_user_data);
    prep_poll_update<T, U>(sqe, old_user_data, new_data, poll_mask, flags);
}

template<typanem T, typename U>
inline void prep_poll_update(sqe* sqe, T* old_user_data, U* new_user_data, unsigned poll_mask, unsigned flags) noexcept
{
    uint64_t old_data = std::bit_cast<std::uint64_t>(old_user_data);
    uint64_t new_data = std::bit_cast<std::uint64_t>(new_user_data);
    prep_poll_update<T, U>(sqe, old_data, new_data, poll_mask, flags);
}

inline void prep_provide_buffers(sqe* sqe, void* addr, int len, int nr, int bgid, int bid) noexcept
{
    io_uring_prep_provide_buffers(sqe, addr, len, nr, bgid, bid);
}

inline void prep_read(sqe* sqe, int fd, void* buf, unsigned nbytes, std::uint64_t offset) noexcept
{
    io_uring_prep_read(sqe, fd, buf, nbytes, offset);
}

inline void prep_read_fixed(sqe* sqe, int fd, void* buf, unsigned nbytes, std::uint64_t offset, int buf_index) noexcept
{
    io_uring_prep_read_fixed(sqe, fd, buf, nbytes, offset, buf_index);
}

inline void prep_read_multishot(sqe* sqe, int fd, unsigned nbytes, std::uint64_t offset, int buf_group) noexcept
{
    io_uring_prep_read_multishot(sqe, fd, nbytes, offset, buf_group);
}

inline void prep_readv(sqe* sqe, int fd, const iovec* iovecs, unsigned nr_vecs, std::uint64_t offset) noexcept
{
    io_uring_prep_readv(sqe, fd, iovecs, nr_vecs, offset);
}

inline void prep_readv2(sqe* sqe, int fd, const iovec* iovecs, unsigned nr_vecs, std::uint64_t offset, int flags) noexcept
{
    io_uring_prep_readv2(sqe, fd, iovecs, nr_vecs, offset, flags);
}

inline void prep_recv(sqe* sqe, int sockfd, void* buf, size_t len, int flags) noexcept
{
    io_uring_prep_recv(sqe, sockfd, buf, len, flags);
}

inline void prep_recv_multishot(sqe* sqe, int sockfd, void* buf, size_t len, int flags) noexcept
{
    io_uring_prep_recv_multishot(sqe, sockfd, buf, len, flags);
}

inline void prep_recvmsg(sqe* sqe, int fd, msghdr* msg, unsigned flags) noexcept
{
    io_uring_prep_recvmsg(sqe, fd, msg, flags);
}

inline void prep_recvmsg_multishot(sqe* sqe, int fd, msghdr* msg, unsigned flags) noexcept
{
    io_uring_prep_recvmsg_multishot(sqe, fd, msg, flags);
}

inline void prep_remove_buffers(sqe* sqe, int nr, int bgid) noexcept
{
    io_uring_prep_remove_buffers(sqe, nr, bgid);
}

inline void prep_rename(sqe* sqe, const char* oldpath, const char* newpath) noexcept
{
    io_uring_prep_rename(sqe, oldpath, newpath);
}

inline void prep_renameat(sqe* sqe, int olddirfd, const char* oldpath, int newdirfd, const char* newpath, unsigned int flags) noexcept
{
    io_uring_prep_renameat(sqe, olddirfd, oldpath, newdirfd, newpath, flags);
}

inline void prep_send(sqe* sqe, int sockfd, const void* buf, size_t len, int flags) noexcept
{
    io_uring_prep_send(sqe, sockfd, buf, len, flags);
}

inline void prep_send_bundle(sqe* sqe, int sockfd, size_t len, int flags) noexcept
{
    io_uring_prep_send_bundle(sqe, sockfd, len, flags);
}

inline void prep_send_set_addr(sqe* sqe, const sockaddr* dest_addr, std::uint16_t addr_len) noexcept
{
    io_uring_prep_send_set_addr(sqe, dest_addr, addr_len);
}

inline void prep_send_zc(sqe* sqe, int sockfd, const void* buf, size_t len, int flags, unsinged zc_flags) noexcept
{
    io_uring_prep_send_zc(sqe, sockfd, buf, len, flags, zc_flags);
}

inline void prep_send_zc_fixed(sqe* sqe, int sockfd, const void* buf, size_t len, int flags, unsigned zc_flags, unsigned buf_index) noexcept
{
    io_uring_prep_send_zc_fixed(sqe, sockfd, buf, len, flags, zc_flags, buf_index);
}

inline void prep_sendmsg(sqe* sqe, int fd, const msghdr* msg, unsigned flags) noexcept
{
    io_uring_prep_sendmsg(sqe, fd, msg, flags);
}

inline void prep_sendmsg_zc(sqe* sqe, int fd, const msghdr* msg, unsigned flags) noexcept
{
    io_uring_prep_sendmsg_zc(sqe, fd, msg, flags);
}

inline void prep_sendto(sqe* sqe, int sockfd, const void* buf, size_t len, int flags, const sockaddr* addr, socklen_t addrlen) noexcept
{
    io_uring_prep_sendto(sqe, sockfd, buf, len, flags, addr, addrlen);
}

inline void prep_setxattr(sqe* sqe, const char* name, const char* value, const char* path, int flags, unsigned int len) noexcept
{
    io_uring_prep_setxattr(sqe, name, value, path, flags, len);
}

inline void prep_shutdown(sqe* sqe, int sockfd, int how) noexcept
{
    io_uring_prep_shutdown(sqe, sockfd, how);
}

inline void prep_socket(sqe* sqe, int domain, int type, int protocol, unsigned int flags) noexcept
{
    io_uring_prep_socket(sqe, domain, type, protocol, flags);
}

inline void prep_socket_direct(sqe* sqe, int domain, int type, int protocol, unsigned int file_index, unsigned int flags) noexcept
{
    io_uring_prep_socket_direct(sqe, domain, type, protocol, file_index, flags);
}

inline void prep_socket_direct_alloc(sqe* sqe, int domain, int type, int protocol, unsigned int flags) noexcept
{
    io_uring_prep_socket_direct_alloc(sqe, domain, type, protocol, flags);
}

inline void prep_splice(sqe* sqe, int fd_in, std::int64_t off_in, int fd_out, std::int64_t off_out, unsigned int nbytes, unsigned int splice_flags) noexcept
{
    io_uring_prep_splice(sqe, fd_in, off_in, fd_out, off_out, nbytes, splice_flags);
}

inline void prep_statx(sqe* sqe, int dirfd, const char* path, int flags, unsigned mask, statx* statxbuf) noexcept
{
    io_uring_prep_statx(sqe, dirfd, path, flags, mask, statxbuf);
}

inline void prep_symlink(sqe* sqe, const char* target, const char* linkpath) noexcept
{
    io_uring_prep_symlink(sqe, target, linkpath);
}

inline void prep_symlinkat(sqe* sqe, const char* target, int newdirfd, const char* linkpath) noexcept
{
    io_uring_prep_symlinkat(sqe, target, newdirfd, linkpath);
}

inline void prep_sync_file_range(sqe* sqe, int fd, unsigned len, std::uint64_t offset, int flags) noexcept
{
    io_uring_prep_sync_file_range(sqe, fd, len, offset, flags);
}

inline void prep_tee(sqe* sqe, int fd_in, int fd_out, unsigned int nbytes, unsigned int splice_flags) noexcept
{
    io_uring_prep_tee(sqe, fd_in, fd_out, nbytes, splice_flags);
}

inline void prep_timeout(sqe* sqe, kernel_timespec* ts, unsigned count, unsigned flags) noexcept
{
    io_uring_prep_timeout(sqe, ts, count, flags);
}

//inline void prep_timeout_remove(sqe* sqe, std::uint64_t user_data, unsigned flags) noexcept

template<>
inline void prep_timeout_remove<std::uint64_t>(sqe* sqe, std::uint64_t user_data, unsigned flags) noexcept
{
    io_uring_prep_timeout_remove(sqe, user_data, flags);
}

template<typename T>
requires (sizeof(T) < sizeof(std::uint64_t))
inline void prep_timeout_remove(sqe* sqe, T user_data, unsigned flags) noexcept
{
    std::uint64_t data = 0;
    std::memcpy(&data, &user_data, sizeof(T));
    prep_timeout_remove<std::uint64_t>(sqe, data, flags);
}

template<typename T>
requires (sizeof(T) == sizeof(std::uint64_t))
inline void prep_timeout_remove(sqe* sqe, T user_data, unsigned flags) noexcept
{
    std::uint64_t data = std::bit_cast<std::uint64_t>(user_data);
    prep_timeout_remove<std::uint64_t>(sqe, data, flags);
}

template<typename T>
inline void prep_timeout_remove(sqe* sqe, T* user_data, unsigned flags) noexcept
{
    std::uint64_t data = std::bitcast<std::uint64_t>(user_data);
    prep_timeout_remove<std::uint64_t>(sqe, data, flags);
}

template<>
inline void prep_timeout_update<std::uint64_t>(sqe* sqe, kernel_timespec* ts, std::uint64_t user_data, unsigned flags) noexcept
{
    io_uring_prep_timeout_update(sqe, ts, user_data, flags);
}

template<typename T>
requires (sizeof(T) < sizeof(std::uint64_t))
inline void prep_timeout_update(sqe* sqe, kernel_timespec* ts, T user_data, unsigned flags) noexcept
{
    std::uint64_t data = 0;
    std::memcpy(&data, &user_data, sizeof(T));
    prep_timeout_update<std::uint64_t>(sqe, ts, data, flags);
}

template<typename T>
requires (sizeof(T) == sizeof(std::uint64_t))
inline void prep_timeout_update(sqe* sqe, kernel_timespec* ts, T user_data, unsigned flags) noexcept
{
    std::uint64_t data = std::bit_cast<std::uint64_t>(user_data);
    prep_timeout_update<std::uint64_t>(sqe, ts, data, flags);
}

template<typename T>
inline void prep_timeout_update(sqe* sqe, kernel_timespec* ts, T* user_data, unsigned flags) noexcept
{
    std::uint64_t data = std::bit_cast<std::uint64_t>(user_data);
    prep_timeout_update<std::uint64_t>(sqe, ts, data, flags);
}

inline void prep_unlink(sqe* sqe, const char* path, int flags) noexcept
{
    io_uring_prep_unlink(sqe, path, flags);
}

inline void prep_unlinkat(sqe* sqe, int dirfd, const char* path, int flags) noexcept
{
    io_uring_prep_unlinkat(sqe, dirfd, path, flags);
}

inline void prep_waitid(sqe* sqe, idtype_t idtype, id_t id, siginfo_t* infop, int options, unsigned int flags) noexcept
{
    io_uring_prep_waitid(sqe, idtype, id, infop, options, flags);
}

inline void prep_write(sqe* sqe, int fd, const void* buf, unsigned nbytes, std::uint64_t offset) noexcept
{
    io_uring_prep_write(sqe, fd, buf, nbytes, offset);
}

inline void prep_write_fixed(sqe* sqe, int fd, const void* buf, unsigned nbytes, std::uint64_t offset, int buf_index) noexcept
{
    io_uring_prep_write_fixed(sqe, fd, buf, nbytes, offset, buf_index);
}

inline void prep_writev(sqe* sqe, int fd, const iovec* iovecs, unsigned nr_vecs, std::uint64_t offset) noexcept
{
    io_uring_prep_writev(sqe, fd, iovecs, nr_vecs, offset);
}

inline void prep_writev2(sqe* sqe, int fd, const iovec* iovecs, unsigned nr_vecs, std::uint64_t offset, int flags) noexcept
{
    io_uring_prep_writev2(sqe, fd, iovecs, nr_vecs, offset, flags);
}

inline void queue_exit(ring* ring) noexcept
{
    io_uring_queue_exit(ring);
}

inline void queue_init(unsigned entries, ring* ring, unsigned flags)
{
    int ret;
    ret = io_uring_queue_init(entries, ring, flags);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_queue_init");
    }
}

inline int queue_init_mem(unsigned entries, ring* ring, ring_params* params, void* buf, size_t buf_size)
{
    int ret;
    ret = io_uring_queue_init_mem(entries, ring, params, buf, buf_size);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_queue_init_mem");
    }
    return ret;
}

inline void queue_init_params(unsigned entries, ring* ring, ring_params* params, void* buf, size_t buf_size)
{
    int ret;
    ret = io_uring_queue_init_params(entries, ring, flags);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_queue_init_params");
    }
}

inline cmsghdr* recvmsg_cmsg_firsthdr(recvmsg_out* o, msghdr* msgh) noexcept
{
    return io_uring_recvmsg_cmsg_firsthdr(o, msgh);
}

inline cmsghdr* recvmsg_cmsg_nexthdr(recvmsg_out* o, msghdr* msgh, cmsghdr* cmsg) noexcept
{
    return io_uring_recvmsg_cmsg_nexthdr(o, msgh, cmsg);
}

inline void* recvmsg_name(recvmsg_out* o) noexcept
{
    return io_uring_recvmsg_name(o);
}

inline void* recvmsg_payload(recvmsg_out* o, msghdr* msgh) noexcept
{
    return io_uring_recvmsg_payload(o, msgh);
}

inline int recvmsg_payload_length(recvmsg_out* o, int buf_len, msghdr* msgh) noexcept
{
    return io_uring_recvmsg_payload_length(o, buf_len, msgh);
}

inline recvmsg_out* recvmsg_validate(void* buf, int buf_len, msghdr* msgh)
{
    recvmsg_out* out;
    out = io_uring_recvmsg_validate(buf, buf_len, msgh);
    if (out == nullptr) {
        throw std::runtime_error("failed to validate received msg");
    }
    return out;
}

inline int register_resource(unsigned int fd, unsigned int opcode, void* arg, unsigned int nr_args)
{
    int ret;
    ret = io_uring_register(fd, opcode, arg, ne_args);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register");
    }
    return ret;
}

inline void register_buf_ring(ring* ring, buf_reg* reg, unsigned int flags)
{
    int ret;
    ret = io_uring_buf_ring(ring, reg, flags);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_buf_ring");
    }
}

inline void register_buffers(ring* ring, const iovec* iovecs, unsigned nr_iovecs)
{
    int ret;
    ret = io_uring_register_buffers(ring, iovecs, nr_iovecs);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_buffers");
    }
}

inline void register_buffers_sparse(ring* ring, unsigned nr_iovecs)
{
    int ret;
    ret = io_uring_register_buffers_sparse(ring, nr_iovecs);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_buffers_sparse");
    }
}

inline void register_buffers_tags(ring* ring, const iovec* iovecs, const std::uint64_t* tags, unsigned nr)
{
    int ret;
    ret = io_uring_register_buffers_tags(ring, iovecs, tags, nr);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_buffers_tags");
    }
}

inline int register_buffers_update_tag(ring* ring, unsigned off, const iovec* iovecs, const std::uint64_t* tags, unsigned nr)
{
    int ret;
    ret = io_uring_register_buffers_update_tag(ring, off, iovecs, tags, nr);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_buffers_update_tag");
    }
    return ret;
}

inline void register_clock(ring* ring, clock_register* arg)
{
    int ret;
    ret = io_uring_register_clock(ring, arg);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_clock");
    }
}

inline void register_eventfd(ring* ring, int fd)
{
    int ret;
    ret = io_uring_register_eventfd(ring, fd);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_eventfd");
    }
}

inline void register_eventfd_async(ring* ring, int fd)
{
    int ret;
    ret = io_uring_register_eventfd_async(ring, fd);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_eventfd_async");
    }
}

inline void register_file_alloc_range(ring* ring, unsigned off, unsigned len)
{
    int ret;
    ret = io_uring_register_alloc_range(ring, off, len);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_alloc_range");
    }
}

inline void register_files(ring* ring, const int* files, unsigned nr_files)
{
    int ret;
    ret = io_uring_register_files(ring, files, nr_files);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_files");
    }
}

inline void register_files_sparse(ring* ring, unsigned nr_files)
{
    int ret;
    ret = io_uring_register_files_sparse(ring, nr_files);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_files_sparse");
    }
}

inline void register_files_tags(ring* ring, const int* files, const std::uint64_t* tags, unsigned nr)
{
    int ret;
    ret = io_uring_register_files_tags(ring, files, tags, nr);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_files_sparse");
    }
}

inline int register_files_update(ring* ring, unsigned off, const int* files, unsigned nr_files)
{
    int ret;
    ret = io_uring_register_files_update(ring, off, files, nr_files);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_files_update");
    }
    return ret;
}

inline int register_files_update_tag(ring* ring, unsigned off, const int* files, const std::uint64_t* tags, unsigned nr_files)
{
    int ret;
    ret = io_uring_register_files_update_tag(ring, off, files, tags, nr_files);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_files_update_tag");
    }
    return ret;
}

inline void register_iowq_aff(ring* ring, size_t cpusz, const cpu_set_t* mask)
{
    int ret;
    ret = io_uring_register_iowq_aff(ring, cpusz, mask);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_iowq_aff");
    }
}

inline void register_iowq_max_workers(ring* ring, unsigned int* values)
{
    int ret;
    ret = io_uring_register_iowq_max_workers(ring, values);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_iowq_max_workers");
    }
}

inline void register_napi(ring* ring, napi* napi)
{
    int ret;
    ret = io_uring_register_napi(ring, napi);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_napi");
    }
}

inline void register_reg_wait(ring* ring, reg_wait* reg)
{
    int ret;
    ret = io_uring_register_reg_wait(ring, reg);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_reg_wait");
    }
}

inline void register_ring_fd(ring* ring)
{
    int ret;
    ret = io_uring_register_ring_fd(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_ring_fd");
    }
}

inline int register_sync_cancel(ring* ring, sync_cancel_reg* reg)
{
    int ret;
    ret = io_uring_register_sync_cancel(ring, reg);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_register_sync_cancel");
    }
    return ret;
}

inline void resize_rings(ring* ring, ring_params* p)
{
    int ret;
    ret = io_uring_resize_rings(ring, p);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_resize_rings");
    }
}

inline int setup(std::int32_t entries, ring_params* params)
{
    int ret;
    ret = io_uring_setup(entries, params);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_setup");
    }
    return ret;
}

inline buf_ring* setup_buf_ring(ring* ring, unsigned int nentries, int bgid, unsigned int flags, int* err) noexcept
{
    return io_uring_setup_buf_ring(ring, nentries, bgid, flags, err);
}

inline buf_ring* setup_buf_ring(ring* ring, unsigned int nentries, int bgid, unsigned int flags)
{
    int err = 0;
    buf_ring* out;
    out = setup_buf_ring(ring, nentries, bgid, flags, &err);
    if (err < 0) {
        throw std::system_error(-err, std::system_category(), "io_uring_setup_buf_ring");
    }
}

inline reg_wait* setup_reg_wait(ring* ring, unsigned nentries, int* err) noexcept
{
    return io_uring_setup_reg_wait(ring, nentries, err);
}

inline reg_wait* setup_reg_wait(ring* ring, unsigned nentries)
{
    int err = 0;
    reg_wait* out;
    out = setup_reg_wait(ring, nentries, &err);
    if (err < 0) {
        throw std::system_error(-err, std::system_category(), "io_uring_setup_reg_wait");
    }
}

inline unsigned sq_ready(const ring* ring) noexcept
{
    return io_uring_sq_ready(ring);
}

inline unsigned sq_space_left(const ring* ring) noexcept
{
    return io_uring_sq_space_left(ring);
}

inline void sqe_set_buf_group(sqe* sqe, int bgid) noexcept
{
    io_uring_sqe_set_buf_group(sqe, bgid);
}

template<>
inline void sqe_set_data<void>(sqe* sqe, void* user_data) noexcept
{
    io_uring_sqe_set_data(sqe, user_data);
}

template<typename T>
inline void sqe_set_data(sqe* sqe, T* user_data) noexcept
{
    sqe_set_data<void>(sqe, static_cast<void*>(user_data));
}

template<>
inline void sqe_set_data64<std::uint64_t>(sqe* sqe, std::uint64_t data) noexcept
{
    io_uring_sqe_set_data64(sqe, data);
}

template<typename T>
requires (sizeof(T) < sizeof(std::uint64_t))
inline void sqe_set_data64(sqe* sqe, T data) noexcept
{
    std::uint64_t d = 0;
    std::memcpy(&d, &data, sizeof(T));
    sqe_set_data64<std::uint64_t>(sqe, d);
}

template<typename T>
requires (sizeof(T) == sizeof(std::uint64_t))
inline void sqe_set_data64(sqe* sqe, T data) noexcept
{
    sqe_set_data64<std::uint64_t>(sqe, std::bit_cast<std::uint64_t>(data));
}

inline void sqe_set_flags(sqe* sqe, unsigned flags) noexcept
{
    io_uring_sqe_set_flags(sqe, flags);
}

inline int sqring_wait(ring* ring)
{
    int ret;
    ret = io_uring_sqring_wait(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_sqring_wait");
    }
    return ret;
}

inline int submit(ring* ring)
{
    int ret;
    ret = io_uring_submit(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_submit");
    }
    return ret;
}

inline int submit_and_get_events(ring* ring)
{
    int ret;
    ret = io_uring_sumit_and_get_events(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_submit_and_get_events");
    }
    return ret;
}

inline int submit_and_wait(ring* ring, unsigned wait_nr)
{
    int ret;
    ret = io_uring_submit_and_wait(ring, wait_nr);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_submit_nad_wait");
    }
    return ret;
}

inline int submit_and_wait_min_timeout(ring* ring, cqe** cqe_ptr, unsigned wait_nr, kernel_timespec* ts, unsigned int min_wait_usec, sigset_t* sigmask)
{
    int ret;
    ret = io_uring_submit_and_wait_min_timeout(ring, cqe_ptr, wait_nr, ts, min_wait_usec, sigmask);
    if (ret == -ETIME) {
        return -1;
    } else if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_submit_and_wait_min_timeout");
    }
    return ret;
}

inline int submit_and_wait_reg(ring* ring, cqe** cqe_ptr, unsigned wait_nr, int reg_index)
{
    int ret;
    ret = io_uring_submit_and_wait_reg(ring, cqe_ptr, wait_nr, reg_index);
    if (ret == -ETIME) {
        return -1;
    } else if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_submit_and_wait_reg");
    }
    return ret;
}

inline int submit_and_wait_timeout(ring* ring, cqe** cqe_ptr, unsigned wait_nr, kernel_timespec* ts, sigset_t* sigmask)
{
    int ret;
    ret = io_uring_submit_and_wait_timeout(ring, cqe_ptr, wait_nr, ts, sigmask);
    if (ret == -ETIME) {
        return -1;
    } else if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_submit_and_wait_timeout");
    }
    return ret;
}

inline void unregister_buf_ring(ring* ring, int bgid)
{
    int ret;
    ret = io_uring_unregister_buf_ring(ring, bgid);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_unregister_buf_ring");
    }
}

inline int unregister_buf_ring_no_except(ring* ring, int bgid)
{
    return io_uring_unregister_buf_ring(ring, bgid);
}

inline void unregister_buffers(ring* ring)
{
    int ret;
    ret = io_uring_unregister_buffers(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_unregister_buffers");
    }
}

inline int unregister_buffers_no_except(ring* ring) noexcept
{
    return io_uring_unregister_buffers(ring);
}

inline void unregister_eventfd(ring* ring)
{
    int ret;
    ret = io_uring_unregister_eventfd(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_unregister_eventfd");
    }
}

inline int unregister_eventfd_no_except(ring* ring) noexcept
{
    return io_uring_unregister_eventfd(ring);
}

inline void unregister_files(ring* ring)
{
    int ret;
    ret = io_uring_unregister_files(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_unregsiter_files");
    }
}

inline int unregister_files_no_except(ring* ring) noexcept
{
    return io_uring_unregister_files(ring);
}

inline void unregister_iowq_aff(ring* ring)
{
    int ret;
    ret = io_uring_unregister_iowq_aff(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_unregister_iowq_aff");
    }
}

inline int unregister_iowq_aff_no_except(ring* ring) noexcept
{
    return io_uring_unregister_iowq_aff(ring);
}

inline void unregister_napi(ring* ring, napi* napi)
{
    int ret;
    ret = io_uring_unregister_napi(ring, napi);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_unregister_napi");
    }
}

inline int unregister_napi_no_except(ring* ring, napi* napi) noexcept
{
    return io_uring_unregister_napi(ring, napi);
}

inline void unregister_ring_fd(ring* ring)
{
    int ret;
    ret = io_uring_unregister_ring_fd(ring);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_unregister_ring_fd");
    }
}

inline int unregister_ring_fd_no_except(ring* ring) noexcept
{
    return io_uring_unregister_ring_fd(ring);
}

inline void wait_cqe(ring* ring, cqe** cqe_ptr)
{
    int ret;
    ret = io_uring_wait_cqe(ring, cqe_ptr);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_wait_cqe");
    }
}

inline void wait_cqe_nr(ring* ring, cqe** cqe_ptr, unsigned wait_nr)
{
    int ret;
    ret = io_uring_wait_cqe_nr(ring, cqe_ptt, wait_nr);
    if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_wait_cqe_nr");
    }
}

inline int wait_cqe_timeout(ring* ring, cqe** cqe_ptr, kernel_timespec* ts)
{
    int ret;
    ret = io_uring_wait_cqe_timeout(ring, cqe_ptr, ts);
    if (ret == -ETIME) {
        return -1;
    } else if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_wait_cqe_timeout");
    }
    return 0;
}

inline int wait_cqes(ring* ring, cqe** cqe_ptr, unsigned wait_nr, kernel_timespec* ts, sigset_t* sigmask)
{
    int ret;
    ret = io_uring_wait_cqes(ring, cqe_ptr, wait_nr, ts, sigmask);
    if (ret == -ETIME) {
        return -1;
    } else if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_wait_cqes");
    }
    return 0;
}

inline int wait_cqes_min_timeout(ring* ring, cqe** cqe_ptr, unsigned wait_nr, kernel_timespec* ts, unsigned int min_wait_usec, sigset_t* sigmask)
{
    int ret;
    ret = io_uring_wait_cqes_min_timeout(ring, cqe_ptr, wait_nr, ts, min_wait_usec, sigmask);
    if (ret == -ETIME) {
        return -1;
    } else if (ret < 0) {
        throw std::system_error(-ret, std::system_category(), "io_uring_wait_cqes_min_timeout");
    }
    return 0;
}

}
