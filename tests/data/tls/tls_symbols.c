/* Thread-local storage: the record kinds no other fixture here carries.
 *
 * A TLS variable with external linkage becomes S_GTHREAD32 (0x1113) and one
 * with internal linkage S_LTHREAD32 (0x1112). Both spellings appear below --
 * Microsoft's __declspec(thread) and C11 _Thread_local, which is what C++
 * thread_local lowers to for a constant-initialised scalar -- because they
 * produce the same two records and the fixture should show that.
 *
 * The plain globals beside them are the contrast: S_GDATA32/S_LDATA32 in the
 * same file, so a test can require that a listing separates the two.
 */

/* An enum and a named struct, so this file also carries S_CONSTANT and S_UDT
 * records. Without them the golden rows for `constants()` and `udts()` would
 * be 0 and 0, which passes against an accessor stubbed to return nothing. */
enum tls_limits {
    TLS_SLOT_COUNT = 4,
    TLS_SCALE_MAX = 31,
};

typedef struct tls_pair {
    int counter;
    int scale;
} tls_pair;

__declspec(thread) int tls_global_counter = 7;
_Thread_local int tls_global_scale = 13;

static __declspec(thread) int tls_static_counter = 11;
static _Thread_local int tls_static_scale = 17;

int plain_global = 3;
static int plain_static = 5;

int bump(int n)
{
    volatile tls_pair pair;

    tls_global_counter += n;
    tls_static_counter += n * tls_global_scale;
    tls_static_scale += n;
    plain_static += n;

    pair.counter = tls_global_counter + tls_static_counter;
    pair.scale = (tls_static_scale % TLS_SCALE_MAX) * TLS_SLOT_COUNT;
    return pair.counter + pair.scale + plain_global + plain_static;
}

void start(void)
{
    bump(1);
}
