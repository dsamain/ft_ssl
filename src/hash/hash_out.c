#include "../../ft_ssl.h"

void show_hash(t_command command, t_hash_args args, int flags) {

    if (flags & FLAG_Q) {
        put_hex(args.output, command.output_size);
    } else if (flags & FLAG_R) {
        put_hex(args.output, command.output_size);
        args.source[ft_strlen(args.source) - 1] = 0;
        PUT(" ");
        PUT(args.source + 1);
    } else {
        PUT(args.source);
        PUT("= ");
        put_hex(args.output, command.output_size);
    }
    PUT("\n");
}
