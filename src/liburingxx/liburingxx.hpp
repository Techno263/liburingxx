#pragma once

#include <liburing.h>
#include <cstdint>
#include <concepts>

namespace io_uring {

using ring = struct io_uring;

using ring_params = struct io_uring_params;

using sqe = struct io_uring_sqe;

using cqe = struct io_uring_cqe;

using buf_ring = struct io_uring_buf_ring;

using probe = struct io_uring_probe;

using buf_reg = struct io_uring_buf_reg;

using clock_register = struct io_uring_clock_register;

using napi = struct io_uring_napi;

using req_wait = struct io_uring_reg_wait;

using sync_cancel_reg = struct io_uring_sync_cancel_reg;

using sockaddr = struct sockaddr;

using futex_waitv = struct futex_waitv;

using iovec = struct iovec;

using kernel_timespec = struct __kernel_timespec;

using open_how = struct open_how;

using msghdr = struct msghdr;

using epoll_event = struct epoll_event;

using statx = struct statx;

using cmsghdr = struct cmsghdr;

using recvmsg_out = struct io_uring_recvmsg_out;

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

inline int enter2(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, void* arg, size_t sz);

template<auto Func>
requires requires(cqe* c)
{
    { Func(c) } noexcept -> std::same_as<void>;
}
inline void for_each_cqe(ring* ring, cqe* cqe);

template<auto Func>
requires requires(cqe* c)
{
    { Func(c) } noexcept -> std::same_as<void>;
}
inline void handle_cqes(ring* ring, cqe* cqe);

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

inline void prep_cancel(sqe* sqe, void* user_data, unsigned int flags) noexcept;

inline void prep_cancel64(sqe* sqe, std::uint64_t user_data, int flags) noexcept;

inline void prep_cancel_fd(sqe* sqe, int fd, unsigned int flags) noexcept;

inline void prep_close(sqe* sqe, int fd) noexcept;

inline void prep_close_direct(sqe* sqe, unsigned file_index) noexcept;

inline void prep_cmd_discard(sqe* sqe, int fd, std::uint64_t offset, std::uint64_t nbytes) noexcept;

inline void prep_cmd_sock(sqe* sqe, int cmd_op, int fd, int level, int optname, void* optval, int optlen) noexcept;

inline void prep_connect(sqe* sqe, int sockfd, const sockaddr* addr, socklen_t addrlen) noexcept;

inline void prep_epoll_wait(sqe* sqe, int fd, epoll_event* events, int maxevents, unsigned flags);

inline void prep_fadvise(sqe* sqe, int fd, std::uint64_t offset, std::uint32_t len, int advice) noexcept;

inline void prep_fadvise64(sqe* sqe, int fd, std::uint64_t offset, off_t len, int advice) noexcept;

inline void prep_fallocate(sqe* sqe, int fd, int mode, std::uint64_t offset, std::uint64_t len) noexcept;

inline void prep_fgetxattr(sqe* sqe, int fd, const char* name, char* value, unsigned int len) noexcept;

inline void prep_files_update(sqe* sqe, int* fds, unsigned nr_fds, int offset) noexcept;


inline void prep_fixed_fd_install(sqe* sqe, int fd, unsigned int flags) noexcept;

inline void prep_fsetxattr(sqe* sqe, int fd, const char* name, const char* value, int flags, unsigned int len) noexcept;

inline void prep_fsync(sqe* sqe, int fd, unsigned flags) noexcept;

inline void prep_ftruncate(sqe* sqe, int fd, loff_t len) noexcept;

inline void prep_futex_wait(sqe* sqe, std::uint32_t* futex, std::uint64_t val, std::uint64_t mask, std::uint32_t futex_flags, unsigned int flags) noexcept;

inline void prep_futex_waitv(sqe* sqe, futex_waitv* futexv, std::uint32_t nr_futex, unsigned int flags) noexcept;

inline void prep_futex_wake(sqe* sqe, std::uint32_t* futex, std::uint64_t val, std::uint64_t mask, std::uint32_t futex_flags, unsigned int flags) noexcept;

inline void prep_getxattr(sqe* sqe, const char* name, char* value, const char* path, unsigned int len) noexcept;

inline void prep_link(sqe* sqe, const char* oldpath, const char* newpath, int flags) noexcept;

inline void prep_link_timeout(sqe* sqe, kernel_timespec* ts, unsigned flags) noexcept;

inline void prep_linkat(sqe* sqe, int olddirfd, const char* oldpath, int newdirfd, const char* newpath, int flags) noexcept;

inline void prep_listen(sqe* sqe, int sockfd, int backlog) noexcept;

inline void prep_madvise(sqe* sqe, void* addr, std::uint32_t len, int advice) noexcept;

inline void prep_madvise64(sqe* sqe, void* addr, off_t len, int advise) noexcept;

inline void prep_mkdir(sqe* sqe, const char* path, mode_t mode) noexcept;

inline void prep_mkdirat(sqe* sqe, int dirfd, const char* path, mode_t mode) noexcept;

inline void prep_msg_ring(sqe* sqe, int fd, unsigned int len, std::uint64_t data, unsigned int flags, unsigned int cqe_flags) noexcept;

inline void prep_msg_ring_cqe_flags(sqe* sqe, int fd, unsigned int len, std::uint64_t data, unsigned int flags, unsigned int cqe_flags) noexcept;

inline void prep_msg_ring_fd(sqe* sqe, int fd, int source_fd, int target_fd, std::uint64_t data, unsigned int flags) noexcept;

inline void prep_msg_ring_fd_alloc(sqe* sqe, int fd, int source_fd, std::uint64_t data, unsigned int flags) noexcept;

inline void prep_multishot_accept(sqe* sqe, int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) noexcept;

inline void prep_multishot_accept_direct(sqe* sqe, int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) noexcept;

inline void prep_nop(sqe* sqe) noexcept;

inline void prep_open(sqe* sqe, const char* path, int flags, mode_t mode) noexcept;

inline void prep_open_direct(sqe* sqe, const char* path, int flags, mode_t mode, unsigned file_index) noexcept;

inline void prep_openat(sqe* sqe, int dfd, const char* path, int flags, mode_t mode) noexcept;

inline void prep_openat2(sqe* sqe, int dfd, const char* path, open_how* how) noexcept;

inline void prep_openat2_direct(sqe* sqe, int dfd, const char* path, open_how* how, unsigned file_index) noexcept;

inline void prep_openat_direct(sqe* sqe, int dfd, const char* path, int flags, mode_t mode, unsigned file_index) noexcept;

inline void prep_poll_add(sqe* sqe, int fd, unsigned poll_mask) noexcept;

inline void prep_poll_multishot(sqe* sqe, int fd, unsigned poll_mask) noexcept;

template<typename T>
inline void prep_poll_remove(sqe* sqe, T user_data) noexcept;

template<typename T>
inline void prep_poll_remove(sqe sqe, T* user_data) noexcept;

template<typename T, typename U>
inline void prep_poll_update(sqe* sqe, T old_user_data, U new_user_data, unsigned poll_mask, unsigned flags) noexcept;

template<typename T, typename U>
inline void prep_poll_update(sqe* sqe, T* old_user_data, U new_user_data, unsigned poll_mask, unsigned flags) noexcept;

template<typename T, typename U>
inline void prep_poll_update(sqe* sqe, T old_user_data, U* new_user_data, unsigned poll_mask, unsigned flags) noexcept;

template<typename T, typename U>
inline void prep_poll_update(sqe* sqe, T* old_user_data, U* new_user_data, unsigned poll_mask, unsigned flags) noexcept;

inline void prep_provide_buffers(sqe* sqe, void* addr, int len, int nr, int bgid, int bid) noexcept;

inline void prep_read(sqe* sqe, int fd, void* buf, unsigned nbytes, std::uint64_t offset) noexcept;

inline void prep_read_fixed(sqe* sqe, int fd, void* buf, unsigned nbytes, std::uint64_t offset, int buf_index) noexcept;

inline void prep_read_multishot(sqe* sqe, int fd, unsigned nbytes, std::uint64_t offset, int buf_group) noexcept;

inline void prep_readv(sqe* sqe, int fd, const iovec* iovecs, unsigned nr_vecs, std::uint64_t offset) noexcept;

inline void prep_readv2(sqe* sqe, int fd, const iovec* iovecs, unsigned nr_vecs, std::uint64_t offset, int flags) noexcept;

inline void prep_recv(sqe* sqe, int sockfd, void* buf, size_t len, int flags) noexcept;

inline void prep_recv_multishot(sqe* sqe, int sockfd, void* buf, size_t len, int flags) noexcept;

inline void prep_recvmsg(sqe* sqe, int fd, msghdr* msg, unsigned flags) noexcept;

inline void prep_recvmsg_multishot(sqe* sqe, int fd, msghdr* msg, unsigned flags) noexcept;

inline void prep_remove_buffers(sqe* sqe, int nr, int bgid) noexcept;

inline void prep_rename(sqe* sqe, const char* oldpath, const char* newpath) noexcept;

inline void prep_renameat(sqe* sqe, int olddirfd, const char* oldpath, int newdirfd, const char* newpath, unsigned int flags) noexcept;

inline void prep_send(sqe* sqe, int sockfd, const void* buf, size_t len, int flags) noexcept;

inline void prep_send_bundle(sqe* sqe, int sockfd, size_t len, int flags) noexcept;

inline void prep_send_set_addr(sqe* sqe, const sockaddr* dest_addr, std::uint16_t addr_len) noexcept;

inline void prep_send_zc(sqe* sqe, int sockfd, const void* buf, size_t len, int flags, unsinged zc_flags) noexcept;

inline void prep_send_zc_fixed(sqe* sqe, int sockfd, const void* buf, size_t len, int flags, unsigned zc_flags, unsigned buf_index) noexcept;

inline void prep_sendmsg(sqe* sqe, int fd, const msghdr* msg, unsigned flags) noexcept;

inline void prep_sendmsg_zc(sqe* sqe, int fd, const msghdr* msg, unsigned flags) noexcept;

inline void prep_sendto(sqe* sqe, int sockfd, const void* buf, size_t len, int flags, const sockaddr* addr, socklen_t addrlen) noexcept;

inline void prep_setxattr(sqe* sqe, const char* name, const char* value, const char* path, int flags, unsigned int len) noexcept;

inline void prep_shutdown(sqe* sqe, int sockfd, int how) noexcept;

inline void prep_socket(sqe* sqe, int domain, int type, int protocol, unsigned int flags) noexcept;

inline void prep_socket_direct(sqe* sqe, int domain, int type, int protocol, unsigned int file_index, unsigned int flags) noexcept;

inline void prep_socket_direct_alloc(sqe* sqe, int domain, int type, int protocol, unsigned int flags) noexcept;

inline void prep_splice(sqe* sqe, int fd_in, std::int64_t off_in, int fd_out, std::int64_t off_out, unsigned int nbytes, unsigned int splice_flags) noexcept;

inline void prep_statx(sqe* sqe, int dirfd, const char* path, int flags, unsigned mask, statx* statxbuf) noexcept;

inline void prep_symlink(sqe* sqe, const char* target, const char* linkpath) noexcept;

inline void prep_symlinkat(sqe* sqe, const char* target, int newdirfd, const char* linkpath) noexcept;

inline void prep_sync_file_range(sqe* sqe, int fd, unsigned len, std::uint64_t offset, int flags) noexcept;

inline void prep_tee(sqe* sqe, int fd_in, int fd_out, unsigned int nbytes, unsigned int splice_flags) noexcept;

inline void prep_timeout(sqe* sqe, kernel_timespec* ts, unsigned count, unsigned flags) noexcept;

template<typename T>
inline void prep_timeout_remove(sqe* sqe, T user_data, unsigned flags) noexcept;

template<typename T>
inline void prep_timeout_remove(sqe* sqe, T* user_data, unsigned flags) noexcept;

template<typename T>
inline void prep_timeout_update(sqe* sqe, kernel_timespec* ts, T user_data, unsigned flags) noexcept;

template<typename T>
inline void prep_timeout_update(sqe* sqe, kernel_timespec* ts, T* user_data, unsigned flags) noexcept;

inline void prep_unlink(sqe* sqe, const char* path, int flags) noexcept;

inline void prep_unlinkat(sqe* sqe, int dirfd, const char* path, int flags) noexcept;

inline void prep_waitid(sqe* sqe, idtype_t idtype, id_t id, siginfo_t* infop, int options, unsigned int flags) noexcept;

inline void prep_write(sqe* sqe, int fd, const void* buf, unsigned nbytes, std::uint64_t offset) noexcept;

inline void prep_write_fixed(sqe* sqe, int fd, const void* buf, unsigned nbytes, std::uint64_t offset, int buf_index) noexcept;

inline void prep_writev(sqe* sqe, int fd, const iovec* iovecs, unsigned nr_vecs, std::uint64_t offset) noexcept;

inline void prep_writev2(sqe* sqe, int fd, const iovec* iovecs, unsigned nr_vecs, std::uint64_t offset, int flags) noexcept;

inline void queue_exit(ring* ring) noexcept;

inline void queue_init(unsigned entries, ring* ring, unsigned flags);

inline int queue_init_mem(unsigned entries, ring* ring, ring_params* params, void* buf, size_t buf_size);

inline void queue_init_params(unsigned entries, ring* ring, ring_params* params, void* buf, size_t buf_size);

inline cmsghdr* recvmsg_cmsg_firsthdr(recvmsg_out* o, msghdr* msgh) noexcept;

inline cmsghdr* recvmsg_cmsg_nexthdr(recvmsg_out* o, msghdr* msgh, cmsghdr* cmsg) noexcept;

inline void* recvmsg_name(recvmsg_out* o) noexcept;

inline void* recvmsg_payload(recvmsg_out* o, msghdr* msgh) noexcept;

inline int recvmsg_payload_length(recvmsg_out* o, int buf_len, msghdr* msgh) noexcept;

inline recvmsg_out* recvmsg_validate(void* buf, int buf_len, msghdr* msgh);

inline int register(unsigned int fd, unsigned int opcode, void* arg, unsigned int nr_args);

inline void register_buf_ring(ring* ring, buf_reg* reg, unsigned int flags);

inline void register_buffers(ring* ring, const iovec* iovecs, unsigned nr_iovecs);

inline void register_buffers_sparse(ring* ring, unsigned nr_iovecs);

inline void register_buffers_tags(ring* ring, const iovec* iovecs, const std::uint64_t* tags, unsigned nr);

inline int register_buffers_update_tag(ring* ring, unsigned off, const iovec* iovecs, const std::uint64_t* tags, unsigned nr);

inline void register_clock(ring* ring, clock_register* arg);

inline void register_eventfd(ring* ring, int fd);

inline void register_eventfd_async(ring* ring, int fd);

inline void register_file_alloc_range(ring* ring, unsigned off, unsigned len);

inline void register_files(ring* ring, const int* files, unsigned nr_files);

inline void register_files_sparse(ring* ring, unsigned nr_files);

inline void register_files_tags(ring* ring, const int* files, const std::uint64_t* tags, unsigned nr);

inline int register_files_update(ring* ring, unsigned off, const int* files, unsigned nr_files);

inline int register_files_update_tag(ring* ring, unsigned off, const int* files, const std::uint64_t* tags, unsigned nr_files);

inline void register_iowq_aff(ring* ring, size_t cpusz, const cpu_set_t* mask);

inline void register_iowq_max_workers(ring* ring, unsigned int* values);

inline void register_napi(ring* ring, napi* napi);

inline void register_reg_wait(ring* ring, reg_wait* reg);

inline void register_ring_fd(ring* ring);

inline int register_sync_cancel(ring* ring, sync_cancel_reg* reg);

inline void resize_rings(ring* ring, ring_params* p);

inline int setup(std::int32_t entries, ring_params* params);

inline buf_ring* setup_buf_ring(ring* ring, unsigned int nentries, int bgid, unsigned int flags, int* err) noexcept;

inline buf_ring* setup_buf_ring(ring* ring, unsigned int nentries, int bgid, unsigned int flags);

inline reg_wait* setup_reg_wait(ring* ring, unsigned nentries, int* err) noexcept;

inline reg_wait* setup_reg_wait(ring* ring, unsigned nentries);

inline unsigned sq_ready(const ring* ring) noexcept;

inline unsigned sq_space_left(const ring* ring) noexcept;

inline void sqe_set_buf_group(sqe* sqe, int bgid) noexcept;

template<typename T>
inline void sqe_set_data(sqe* sqe, T* user_data) noexcept;

template<typename T>
inline void sqe_set_data64(sqe* sqe, T data) noexcept;

inline void sqe_set_flags(sqe* sqe, unsigned flags) noexcept;

inline int sqring_wait(ring* ring);

inline int submit(ring* ring);

inline int submit_and_get_events(ring* ring);

inline int submit_and_wait(ring* ring, unsigned wait_nr);

inline int submit_and_wait_min_timeout(ring* ring, cqe** cqe_ptr, unsigned wait_nr, kernel_timespec* ts, unsigned int min_wait_usec, sigset_t* sigmask);

inline int submit_and_wait_reg(ring* ring, cqe** cqe_ptr, unsigned wait_nr, int reg_index);

inline int submit_and_wait_timeout(ring* ring, cqe** cqe_ptr, unsigned wait_nr, kernel_timespec* ts, sigset_t* sigmask);

inline void unregister_buf_ring(ring* ring, int bgid);

inline int unregister_buf_ring_no_except(ring* ring, int bgid) noexcept;

inline void unregister_buffers(ring* ring);

inline int unregister_buffers_no_except(ring* ring) noexcept;

inline void unregister_eventfd(ring* ring);

inline int unregister_eventfd_no_except(ring* ring) noexcept;

inline void unregister_files(ring* ring);

inline int unregister_files_no_except(ring* ring) noexcept;

inline void unregister_iowq_aff(ring* ring);

inline int unregister_iowq_aff_no_except(ring* ring) noexcept;

inline void unregister_napi(ring* ring, napi* napi);

inline int unregister_napi_no_except(ring* ring, napi* napi) noexcept;

inline void unregister_ring_fd(ring* ring);

inline int unregister_ring_fd_no_except(ring* ring) noexcept;

inline void wait_cqe(ring* ring, cqe** cqe_ptr);

inline void wait_cqe_nr(ring* ring, cqe** cqe_ptr, unsigned wait_nr);

inline int wait_cqe_timeout(ring* ring, cqe** cqe_ptr, kernel_timespec* ts);

inline void wait_cqes(ring* ring, cqe** cqe_ptr, unsigned wait_nr, kernel_timespec* ts, sigset_t* sigmask);

inline int wait_cqes_min_timeout(ring* ring, cqe** cqe_ptr, unsigned wait_nr, kernel_timespec* ts, unsigned int min_wait_usec, sigset_t* sigmask);

}

#include <liburingxx/liburingxx.inl>
