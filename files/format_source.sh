#!/bin/sh

for f in `find ../src-*|grep [.][ch]$`
do
    clang-format-6.0 -style=file -i $f
done
