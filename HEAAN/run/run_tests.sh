#!/bin/bash

# 사용자 수 배열
users=(1 10 20 50 100)
# iid_mode 값 배열
iid_modes=(1 0)

# make clean, make
make clean
make

# 각 사용자 수와 iid_mode에 대해 프로그램 실행
for user in "${users[@]}"
do
  for iid_mode in "${iid_modes[@]}"
  do
    echo "Running ./TestHEAAN final $user $iid_mode"
    ./TestHEAAN final $user $iid_mode
  done
done

