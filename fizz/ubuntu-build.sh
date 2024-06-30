#!/bin/sh

#install all dependencies needed
sudo apt-get install \
g++ \
cmake \
libboost-all-dev \
libevent-dev \
libdouble-conversion-dev \
libgoogle-glog-dev \
libgflags-dev \
libiberty-dev \
liblz4-dev \
liblzma-dev \
libsnappy-dev \
make \
zlib1g-dev \
binutils-dev \
libjemalloc-dev \
libssl-dev \
pkg-config \
libunwind-dev \
libsodium-dev \
git \
libzstd-dev \
libgmock-dev \
libgtest-dev   

#build and install fmt (folly dependency)
git clone https://github.com/fmtlib/fmt.git
mkdir fmt/_build && cd fmt/_build
cmake ..
make -j$(nproc)
sudo make install

cd ../..

#build and install folly
git clone https://github.com/facebook/folly.git
mkdir folly/_build && cd folly/_build
cmake ..  
make -j $(nproc)
sudo make install

cd ../..

#build and install fizz
git clone https://github.com/facebookincubator/fizz
mkdir fizz/fizz/build_ && cd fizz/fizz/build_
cmake ..  
make -j $(nproc)
sudo make install
