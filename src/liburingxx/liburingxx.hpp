#pragma once

#include <liburing.h>
#include <cstdint>

namespace io_uring {

using ring = struct io_uring;

using sqe = struct io_uring_sqe;

using cqe = struct io_uring_cqe;

using buf_ring = struct io_uring_buf_ring;

using probe = struct io_uring_probe;

using sockaddr = struct sockaddr;

using iovec = struct iovec;

inline void __buf_ring_cq_advance(ring* ring, buf_ring* br, int cq_count, int buf_count) noexcept;

inline void buf_ring_add(buf_ring* br, void* addr, unsigned int len, unsigned short bid, int mask, int buf_offset) noexcept;

inline void buf_ring_advance(buf_ring* br, int count) noexcept;

inline int buf_ring_available(ring* ring, buf_ring* br, unsigned short bgid);

inline void buf_ring_cq_advance(ring* ring, buf_ring* br, int count) noexcept;

inline void buf_ring_init(buf_ring* br) noexcept;

inline int buf_ring_mask(std::uint32_t ring_entries) noexcept;

inline bool check_version(int major, int minor) noexcept;

inline void clone_buffers(ring* dst, ring* src);

inline void clone_buffers_offset(ring* dst, ring* src, unsigned int dst_off, unsigned int src_off, unsigned int nr, unsigned int flags);

inline void close_ring_fd(ring* ring);

inline void cq_advance(ring* ring, unsigned nr) noexcept;

inline bool cq_has_overflow(const ring* ring) noexcept;

inline unsigned cq_ready(const ring* ring) noexcept;

template<typename T>
inline T* cqe_get_data(cqe* cqe) noexcept;

template<typename T>
inline T cqe_get_data64(cqe* cqe) noexcept;

inline void cqe_seen(ring* ring, cqe* cqe) noexcept;

inline void enable_rings(ring* ring);

inline int enter(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsinged_int flags, sigset_t* sig);

inline int enter2(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, sigset_t* sig, size_t sz);

inline void free_buf_ring(ring* ring, buf_ring* br, unsigned int nentries, int bgid);

inline void free_probe(probe* probe) noexcept;

inline void free_reg_wait(ring* ring, unsigned nentries);

inline void get_events(ring* ring);

inline probe* get_probe();

inline sqe* get_sqe(ring* ring);

inline int major_version() noexcept;

inline int minor_version() noexcept;

inline bool opcode_supported(probe* probe, int opcode) noexcept;

inline void peek_batch_cqe(ring* ring, cqe** cqe_ptrs, unsigned count);

inline void peek_cqe(ring* ring, cqe** cqe_ptr);

inline void prep_accept(sqe* sqe, int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) noexcept;

inline void prep_accept_direct(sqe* sqe, int sockfd, sockaddr* addr, socklen_t* addrlen, int flags, unsigned int file_index) noexcept;

inline void prep_bind(sqe* sqe, int sockfd, sockaddr* addr, socklen_t addrlen) noexcept;

inline void prep_cancel(sqe* sqe, int fd, unsigned int flags) noexcept;

inline void prep_cancel64(sqe* sqe, std::uint64_t user_data, int flags) noexcept;

inline void prep_cancel_fd(sqe* sqe, int fd, unsigned int flags) noexcept;

inline void prep_close(sqe* sqe, int fd) noexcept;

inline void prep_close_direct(sqe* sqe, unsigned file_index) noexcept;

inline void prep_cmd_sock(sqe* sqe, int cmd_op, int fd, int level, int optname, void* optval, int optlen) noexcept;

inline void prep_cmd_discard(sqe* sqe, int fd, std::uint64_t offset, std::uint64_t nbytes) noexcept;

inline void prep_connect(sqe* sqe, int sockfd, const sockaddr* addr, socklen_t addrlen) noexcept;

inline void prep_fadvise(sqe* sqe, int fd, std::uint64_t offset, std::uint32_t len, int advice) noexcept;

inline void prep_fadvise64(sqe* sqe, int fd, std::uint64_t offset, off_t len, int advice) noexcept;

inline void prep_fallocate(sqe* sqe, int fd, int mode, std::uint64_t offset, std::uint64_t len) noexcept;

inline void prep_fgetxattr(sqe* sqe, int fd, const char* name, char* value, unsigned int len) noexcept;

inline void prep_files_update(sqe* sqe, int* fds, unsigned nr_fds, int offset) noexcept;

}

#include <liburingxx/liburingxx.inl>
