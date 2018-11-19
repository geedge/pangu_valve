#!/bin/sh
valgrind --tool=memcheck --leak-check=full --undef-value-errors=yes --leak-resolution=high --malloc-fill=AA --free-fill=FE --log-file=valgrind.log $1
