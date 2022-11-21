
NAME = ft_ssl

SRCS =  $(addprefix src/, \
			main.c common.c str.c parse.c  \
			$(addprefix rsa/, genrsa.c rsa.c prime.c asn1.c) \
			$(addprefix cipher/, base64.c des.c) \
			$(addprefix hash/, md5.c sha224.c sha256.c sha384.c sha512.c padding.c pbkdf2.c hash_out.c)) 
#SRCS = $(addprefix src/, main.c common.c str.c parse.c $(addprefix cipher/, base64.c des.c) $(addprefix hash/,$ sha256.c padding.c pbkdf2.c)) 

OBJS = $(SRCS:.c=.o)

CC = gcc

CFLAGS = -Wall -Wextra -Werror

%.o: %.c
	gcc -c -o $@ $(CFLAGS) $<


all: $(NAME)

dbg: $(OBJS) 
	$(CC) $(CFLAGS) -D DEBUG -o $(NAME) $(SRCS) 

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS)

run: $(NAME)
	./$(NAME)

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re