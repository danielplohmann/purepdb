/* What the CRT would normally supply for TLS, written out here because this
 * fixture links with /nodefaultlib.
 *
 * `_tls_index` is the slot the compiler indirects through, the two `.tls$`
 * markers bracket the range the linker collapses into the .tls section, and
 * `_tls_used` is the IMAGE_TLS_DIRECTORY64 that lld-link finds by name and
 * writes into the TLS data directory.
 */

unsigned long _tls_index = 0;

#pragma section(".tls", long, read, write)
#pragma section(".tls$ZZZ", long, read, write)

__declspec(allocate(".tls")) char _tls_start = 0;
__declspec(allocate(".tls$ZZZ")) char _tls_end = 0;

const void *const _tls_callbacks[] = {0};

const struct {
    unsigned long long raw_start, raw_end, index_addr, callbacks;
    unsigned long zero_fill, characteristics;
} _tls_used = {
    (unsigned long long)&_tls_start,
    (unsigned long long)&_tls_end,
    (unsigned long long)&_tls_index,
    (unsigned long long)&_tls_callbacks,
    0, 0,
};
