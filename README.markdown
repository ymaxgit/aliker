Introduction
============

Alibaba Kernel is originated by [Alibaba](http://en.wikipedia.org/wiki/Alibaba_Group), the largest e-commerce website in Asia. It is based on RHEL6 source codes and included some updates and new features need by Alibaba.
For more information and documentation, please refer to
http://kernel.taobao.org

BRANCH EXPLANATION
master branch is the source codes we are using in our production system.
dev branch is where we are doing kernel development.
So you can say that master is much much stable than the dev branch. :)
Features
========

* All features of RHEL6U2 kernel, source code version is 2.6.32-220.23.1.
* netoops to enable you collect data from the panic server, https://lwn.net/Articles/414031/.
* bigalloc and inline data support for ext4. https://lwn.net/Articles/469805/
* overlayfs which can deploy one fs over another. Please refer to http://lwn.net/Articles/447650/.
* flashcache embedded support.
* cpu accounting support for containers.
* dio overwrite nolock support for fast SSDs.
* Perf jit to enable you use perf to trace a java program.
* Enable different memory management policy.
* ...

RPMS
========
If you want to build an kernel rpm for your server, please refer to https://github.com/alibaba/ali_kernel_rpm.
