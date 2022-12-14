#include "../ft_ssl.h"

void put_hex(u_int8_t *a, int size) {
    char base[16] = "0123456789abcdef";
    for (int i = 0; i < size; i++) {
        write(1, &base[a[i] >> 4], 1);
        write(1, &base[a[i] & 0xf], 1);
    }
}

void put_hex_n(u_int64_t a, int size) {
    char base[16] = "0123456789abcdef";
    for (int i = 0; i < size / 4; i++) {
        write(1, &base[(a >> (size - (i + 1) * 4)) & 0xf], 1);
    }
}

void putb(u_int64_t n) {
    if (n > 1) putb(n>>1);
    write(1, &"01"[n&1], 1);
}

void putb_n(u_int64_t n, int size) {
    for (int i = size - 1; i >= 0; i--) {
        write(1, &"01"[(n >> i) & 1], 1);
    }
}


int help() {
    PUT("Usage:\n");
    PUT("  ft_ssl command [command opts] [command args]\n");
    PUT("\nMessage Digest commands:\n");
    PUT("  md5\n");
    PUT("  sha224\n");
    PUT("  sha256\n");
    PUT("  sha384\n");
    PUT("  sha512\n");
    PUT("\nMessage Digest options:\n");
    PUT("  -s  print the sum of the given string.\n");
    PUT("  -p  echo STDIN to STDOUT and append the checksum to STDOUT.\n");
    PUT("  -r  reverse the format of the output.\n");
    PUT("  -q  quiet mode.\n");
    PUT("\nCipher commands:\n");
    PUT("  base64\n");
    PUT("  des\n");
    PUT("  des-ecb\n");
    PUT("  des-cbc\n");
    PUT("\nCipher options:\n");
    PUT("  -a  encrypt/decrypt in base64\n");
    PUT("  -d  decrypt\n");
    PUT("  -e  encrypt\n");
    PUT("  -i  input file\n");
    PUT("  -k  key in hex\n");
    PUT("  -o  output file\n");
    PUT("  -p  password\n");
    PUT("  -s  salt\n");
    PUT("  -v  initialization vector\n");

    return (0);
}

t_command *find_command(char *name, t_command *commands, size_t commands_size) {
    for (size_t i = 0; i < commands_size / sizeof(t_command); i++)
        if (!ft_strcmp(name, commands[i].name))
            return commands + i;

    return NULL;
}

void push_hash_args(t_hash_args **args) {
    t_hash_args *new = malloc(sizeof(t_hash_args)); 
    *new = (t_hash_args){0, 0, 0, (*args ? *args : NULL)};
    *args = new;
}

u_int64_t str_to_u64(char *s) {
    char *base = "0123456789abcdef";
    u_int64_t ret = 0;
    for (int i = 0; s[i]; i++) {
        char *p = ft_strchr(base, s[i]);
        if (!p) throw("Invalid char in str_to_u64\n");
        ret = ret * 16 + (p - base);
    }
    return ret;
}

char *ft_to_str(void *n, size_t size) {
    char *ret = ft_malloc(size + 1);
    for (size_t i = 0; i < size; i++)
        ret[i] = ((u_int8_t *)n)[size - i - 1];
    ret[size] = 0;
    return ret;
}

u_int8_t *read_fd(int fd, size_t *len) {

    if (fd == 0) {
        char *ret = NULL;
        char buf[BUFF_SIZE];

        int status;
        while ((status = read(fd, buf, BUFF_SIZE + 1))) {
            if (status == -1)
                throw("Error while reading");
            if (len) *len += status;
            buf[status] = 0;
            ret = ft_join(ret, buf);
        }
        return (u_int8_t *)ret;
    }

    struct stat buf;
    int status;
    status = fstat(fd, &buf);
    if (status < 0)
        throw("Error while reading");

    if (len) *len = buf.st_size;

    char *ret; 

    if (buf.st_size == 0)
        ret = ft_join("", NULL);
    else 
        ret = mmap(NULL, buf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    

    if (ret == MAP_FAILED) {
        throw("Error while reading");
    }
    return (u_int8_t *)ret;

}

void ft_memcpy(void *dst, void *src, size_t size) {
    for (size_t i = 0; i < size; i++)
        ((u_int8_t *)dst)[i] = ((u_int8_t *)src)[i];
}


void put_hex_fd(u_int8_t *n, int size, int fd) {
    char *base = "0123456789ABCDEF";
    if (n[0] == 0) {
        if (size == 1) {
            write(fd, "0", 1);
            return ;
        } else {
            n++;
            size--;
        }
    }
    for (int i = 0; i < size; i++) {
        write(fd, &base[n[i] >> 4], 1);
        write(fd, &base[n[i] & 0xf], 1);
    }
}

void put_num_fd(__uint128_t n, int fd) {
    if (n > 9) put_num_fd(n / 10, fd);
    write(fd, &"0123456789"[n % 10], 1);
}

u_int64_t atoi_ll(u_int8_t *s, size_t len) {
    u_int64_t ret = 0;
    for (size_t i = 0; i < len; i++)
        ret = ret * 10 + s[i] - '0';
    return ret;
}