# Introduction

FixDtbSmartio reorders device tree nodes such that the the ones with the biggest "trenz.biz,buffer-size" property values come first. This in turn determines the order of smartio probes and helps against memory fragmentation.

The file is expected to be in image.ub format (FIT image).

# Usage

fix-dtb-smartio image.ub

# Building

Required packages:
* libcrypto++-dev
* cmake


Complete list of steps to build Debian packages:
```
sudo apt install libcrypto++-dev
git clone git@github.com:Trenz-Electronic/fix-dtb-smartio.git
cd fix-dtb-smartio
git submodule init .
git submodule update
mkdir build
cd build
cmake ..
cmake --build .
cpack -G DEB
```


