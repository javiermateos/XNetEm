# XNetEm - Network Emulator

This project is based on the [xdp-tools repository](https://github.com/xdp-project/xdp-tools)

- The `xdp-netem` folder contains original code developed by me as part of my master's thesis.
- The remaining code comes from the original xdp-tools repository and maintains its original license.

To compile, first run `./configure`, then simply type `make`. Make sure you
that your Linux kernel version includes the required patch for running XNetEm,
see [Linux Kernel Tree](https://git.kernel.org/pub/scm/linux/kernel/git/toke/linux.git/log/?h=xdp-queueing-08).
