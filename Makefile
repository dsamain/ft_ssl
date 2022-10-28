
NAME = ft_ssl

SRCS = $(addprefix src/, main.c fun.c) 

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