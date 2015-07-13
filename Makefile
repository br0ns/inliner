#!/bin/sh
CC      = gcc
PY      = python
# CFLAGS  = -pedantic -Wall -Wextra -march=native
CFLAGS  = -Wall -Wextra -march=native
TARGET  = inliner
SOURCES = $(shell echo *.c)

ifeq ($(DEBUG), 1)
	CFLAGS += -g -DDEBUG -O0
else
	CFLAGS += -O9
endif

all: $(TARGET) libstatus

$(TARGET):
	echo $(CONFIG)
ifndef CONFIG
	$(error must set config with "CONFIG=...")
endif
	$(PY) compileconfig.py $(CONFIG) config.h
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

libstatus:
	$(CC) $(CFLAGS) -fPIC -shared -o libstatus/libstatus.so libstatus/libstatus.c

clean:
	rm -f $(TARGET) *.pyc config.h

.PHONY: clean $(TARGET) libstatus