/* Generated probe. Not an original image file and not the synthetic
 * binder PIE. It links the image's libbinder_ndk.so and libc.so.
 *
 *   libbinder-ping serve NAME   addService and serve one increment
 *   libbinder-ping call NAME    one Parcel call; prints value and pids
 *
 * The ELF checked in beside this source is what
 * `bionic-smoke --prepare-servicemanager` installs. Rebuilding it needs
 * clang --target=aarch64-linux-android34 and ld.lld
 * (-pie -s --build-id=none -z max-page-size=16384 -z now,
 * interpreter /system/bin/linker64, -nostdlib -nostartfiles,
 * libbinder_ndk.so and the apex libc.so). The Mac harness does not
 * compile it.
 *
 * stdout is a pipe, so bionic fully buffers it. _start then uses
 * exit_group, which does not flush. On dd8d4fb the caller still exited 0
 * after BR_REPLY: fstat(1), an anonymous mmap for the buffer, then
 * exit_group(0), and no write of fd 1. main flushes before returning.
 */

typedef int binder_status_t;
typedef int binder_exception_t;
typedef unsigned transaction_code_t;
typedef struct AIBinder AIBinder;
typedef struct AIBinder_Class AIBinder_Class;
typedef struct AParcel AParcel;
typedef void *(*on_create_fn)(void *);
typedef void (*on_destroy_fn)(void *);
typedef binder_status_t (*on_transact_fn)(AIBinder *, transaction_code_t, const AParcel *, AParcel *);

AIBinder_Class *AIBinder_Class_define(const char *, on_create_fn, on_destroy_fn, on_transact_fn);
AIBinder *AIBinder_new(const AIBinder_Class *, void *);
binder_status_t AIBinder_prepareTransaction(AIBinder *, AParcel **);
binder_status_t AIBinder_transact(AIBinder *, transaction_code_t, AParcel **, AParcel **, unsigned);
int AIBinder_associateClass(AIBinder *, const AIBinder_Class *);
binder_status_t AParcel_readInt32(const AParcel *, int *);
binder_status_t AParcel_writeInt32(AParcel *, int);
void AParcel_delete(AParcel *);
binder_exception_t AServiceManager_addService(AIBinder *, const char *);
AIBinder *AServiceManager_checkService(const char *);
int ABinderProcess_setThreadPoolMaxThreadCount(unsigned);
void ABinderProcess_joinThreadPool(void);
int printf(const char *, ...);
int fflush(void *);
int strcmp(const char *, const char *);
int getpid(void);

static void *on_create(void *args) { return args; }
static void on_destroy(void *data) { (void)data; }

static binder_status_t on_transact(AIBinder *binder, transaction_code_t code, const AParcel *in, AParcel *out) {
    int v;
    (void)binder;
    if (code != 1 || AParcel_readInt32(in, &v) != 0) return -74;
    if (AParcel_writeInt32(out, v + 1) != 0) return -74;
    return AParcel_writeInt32(out, getpid());
}

static AIBinder_Class *cls(void) {
    return AIBinder_Class_define("dev.aim.IPing", on_create, on_destroy, on_transact);
}

static int serve(const char *name) {
    AIBinder *b;
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    b = AIBinder_new(cls(), 0);
    if (b == 0 || AServiceManager_addService(b, name) != 0) {
        printf("binder serve failed %s\n", name);
        return 1;
    }
    printf("serving %s pid=%d\n", name, getpid());
    fflush(0);
    ABinderProcess_joinThreadPool();
    return 1;
}

static int call(const char *name) {
    AIBinder *b = AServiceManager_checkService(name);
    AParcel *in = 0;
    AParcel *out = 0;
    int value = 0, server = 0;
    binder_status_t st;
    if (b == 0) {
        printf("binder missing: %s\n", name);
        return 1;
    }
    if (!AIBinder_associateClass(b, cls())) {
        printf("binder class mismatch: %s\n", name);
        return 1;
    }
    if (AIBinder_prepareTransaction(b, &in) != 0) return 1;
    AParcel_writeInt32(in, 1);
    st = AIBinder_transact(b, 1, &in, &out, 0);
    if (st != 0) {
        printf("binder transact failed: %d\n", st);
        return 1;
    }
    st = AParcel_readInt32(out, &value);
    if (st == 0) st = AParcel_readInt32(out, &server);
    AParcel_delete(out);
    if (st != 0) {
        printf("binder parcel failed: %d\n", st);
        return 1;
    }
    printf("binder reply: value=%d server_pid=%d caller_pid=%d\n", value, server, getpid());
    return value == 2 ? 0 : 1;
}

int main(int argc, char **argv) {
    int rc;
    if (argc == 3 && strcmp(argv[1], "serve") == 0) rc = serve(argv[2]);
    else if (argc == 3 && strcmp(argv[1], "call") == 0) rc = call(argv[2]);
    else {
        printf("usage: libbinder-ping serve NAME | call NAME\n");
        rc = 2;
    }
    /* exit_group does not flush. The reply line has to reach the pipe. */
    fflush(0);
    return rc;
}
