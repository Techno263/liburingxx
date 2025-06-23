namespace io_uring {



user_data_manager::user_data_manager(std::uint32_t entries)
    : user_data(entries),
    use_map(entries, False),
    versions(entries)
{
    
}

}
