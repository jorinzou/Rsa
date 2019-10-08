CC=gcc

OBJ=Rsa
all:$(OBJ)

HERE=$(shell pwd)
POLARSSL_INC=$(HERE)/lib/mbedtls-1.3.14/include/
incs=-I$(HERE)
incs+=-I$(POLARSSL_INC)

POLARSSL_LIB_DIR=$(HERE)/lib/mbedtls-1.3.14/library/
files:=$(HERE)/src/main.c
files+=$(foreach dir,$(POLARSSL_LIB_DIR),$(wildcard $(POLARSSL_LIB_DIR)/*.c))

OBJS_C := $(patsubst %.c,%.o,$(files))


CFLAGS=-O0 -g 
CFLAGS+=$(incs) 

#LDFLAGS=-lpthread 
#LDFLAGS+=-lm
#LDFLAGS+=-ldl

$(OBJ):$(OBJS_C)
	$(CC)  $(LDFLAGS) -o $@ $^ 
			
$(OBJS_C):%.o:%.c
	$(CC) $(CFLAGS)  -c $< -o $@

clean:
	rm -rf $(HERE)/*.o
	rm -rf $(POLARSSL_LIB_DIR)/*.o
	rm -rf $(HERE)/$(OBJ)

