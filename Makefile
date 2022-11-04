
NAME = ft_ssl

SRCS = $(addprefix src/, main.c common.c str.c parse.c $(addprefix cipher/, base64.c des.c) $(addprefix hash/, md5.c sha224.c sha256.c sha384.c sha512.c padding.c)) 

OBJS = $(SRCS:.c=.o)

CC = gcc

%.o: %.c
	gcc -c -o $@ $<

#CFLAGS = -Wall -Wextra -Werror

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