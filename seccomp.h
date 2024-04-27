#ifndef X_SECCOMP_H
#define X_SECCOMP_H


#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

struct sc_seccomp_file_header
{
	char header[2];
	uint8_t version;
	uint8_t unrestricted;

	uint32_t len_filter;
	uint8_t reserved2[16];
};

void sc_must_read_filter_from_file(FILE *file, uint32_t len_bytes, struct sock_fprog *prog);
FILE* sc_must_read_and_validate_header_from_file(const char *profile_path, struct sc_seccomp_file_header *hdr);
void sc_apply_seccomp_filter(struct sock_fprog *prog);

void die(const char *fmt, ...);

#endif
