# FileCloakingRootkit
Hooks the getdents system call such that the struct linux_dirent* buffer you return to the calling process does not include any dirent's for filenames that start with magic_prefix.
