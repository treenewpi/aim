/* Generated probe. Not an original image file. It links the image's
 * libc.so and calls __system_property_get and __system_property_wait_any.
 * The Mac harness does not compile it.
 *
 *   property-wait NAME VALUE
 *
 * stdout is a pipe, and _start uses exit_group, which does not flush.
 * main flushes before returning.
 */

typedef unsigned int uint32_t;

int __system_property_get(const char *, char *);
uint32_t __system_property_area_serial(void);
void __system_property_wait_any(uint32_t);
int printf(const char *, ...);
int fflush(void *);
int strcmp(const char *, const char *);

int main(int argc, char **argv) {
    char value[92];
    int n;
    if (argc != 3) {
        printf("usage: property-wait NAME VALUE\n");
        fflush(0);
        return 2;
    }
    for (;;) {
        n = __system_property_get(argv[1], value);
        if (n > 0 && strcmp(value, argv[2]) == 0) {
            printf("property wait: %s=%s\n", argv[1], value);
            fflush(0);
            return 0;
        }
        __system_property_wait_any(__system_property_area_serial());
    }
}
