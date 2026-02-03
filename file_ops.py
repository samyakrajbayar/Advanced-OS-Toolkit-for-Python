from advanced_os_toolkit import FileManager

file_manager = FileManager()

# Secure file copy with verification
success, message = file_manager.secure_copy('source.txt', 'destination.txt')

# Find files with filters
files = file_manager.find_files(
    '/path/to/search',
    pattern='*.py',
    min_size=1024,  # 1KB minimum
    max_size=1048576  # 1MB maximum
)

# Compare directories
comparison = file_manager.compare_directories('/dir1', '/dir2')
