#include "seccomp.h"

int main(int argc, char **argv)
{
	struct sock_fprog  prog_allow = { 0 };
	struct sc_seccomp_file_header hdr = {0};
	const char *profile_path = argv[1];
	if (argc != 2)
	{
		die("needs seccomp profile as first argument");
	}
	FILE *file = sc_must_read_and_validate_header_from_file(profile_path, &hdr);
    if (file == NULL)
	{
        die("Failed to open seccomp profile: %s", profile_path);
    }
    sc_must_read_filter_from_file(file, hdr.len_filter, &prog_allow);
    fclose(file);
    sc_apply_seccomp_filter(&prog_allow);
    free(prog_allow.filter);
    return 0;
}
