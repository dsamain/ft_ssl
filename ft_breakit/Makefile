
NAME = ft_breakit

SRCS =  ft_breakit.c $(addprefix ../src/, \
			common.c str.c parse.c  \
			$(addprefix rsa/, genrsa.c rsa.c rsautl.c prime.c asn1_parse.c asn1_build.c) \
			$(addprefix cipher/, base64.c des.c) \
			$(addprefix hash/, md5.c sha224.c sha256.c sha384.c sha512.c padding.c pbkdf2.c hash_out.c) \
			$(addprefix garbage_collector/, gc.c)) \
		

OBJS = $(SRCS:.c=.o)

CC = gcc
#CFLAGS = -Wall -Wextra -Werror

%.o: %.c
	gcc -c -o $@ $(CFLAGS) $<


all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS)

run: $(NAME)
	./$(NAME)

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)
	rm -Rf bin

re: fclean all

.PHONY: all clean fclean re