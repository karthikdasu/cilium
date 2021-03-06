![Cilium Logo](https://cdn.rawgit.com/cilium/cilium/master/Documentation/images/cilium.svg)
# BPF & XDP for containers

[![Build Status](https://jenkins.cilium.io/job/cilium/job/cilium/job/master/badge/icon)](https://jenkins.cilium.io/job/cilium/job/cilium/job/master/)
[![Go Report Card](https://goreportcard.com/badge/github.com/cilium/cilium)](https://goreportcard.com/report/github.com/cilium/cilium)
[![GoDoc](https://godoc.org/github.com/cilium/cilium?status.svg)](https://godoc.org/github.com/cilium/cilium)
[![Read the Docs](https://readthedocs.org/projects/docs/badge/?version=latest)](http://cilium.readthedocs.io/en/latest/)
[![Apache licensed](https://img.shields.io/badge/license-Apache-blue.svg)](https://github.com/cilium/cilium/blob/master/LICENSE)
[![GPL licensed](https://img.shields.io/badge/license-GPL-blue.svg)](https://github.com/cilium/cilium/blob/master/bpf/COPYING)
[![Join the Cilium slack channel](https://cilium.herokuapp.com/badge.svg)](https://cilium.herokuapp.com/)

Cilium provides fast in-kernel networking and security policy enforcement for
containers based on eBPF programs generated on the fly. It is an experimental
project aiming at enabling emerging kernel technologies such as BPF and XDP
for containers.

<p align="center">
   <img src="Documentation/images/cilium-arch.png" />
</p>

## Components:
  * **Cilium Daemon**: Agent written in Go. Generates & compiles the BPF
    programs, manages the BPF maps, and interacts with the local container
    runtime.
  * **BPF programs**:
    * **container**: Container connectivity
    * **netdev**: Integration with L3 networks (physical/virtual)
    * **overlay**: Integration with overlay networks (VXLAN, Geneve)
    * **load balancer**: Fast L3/L4 load balancer with direct server return.
  * **Integration**: CNI, Kubernetes, Docker

## Getting Started

 * 5-min Quickstart: [Using the prebuilt docker images](examples/docker-compose/README.md)
 * For Developers: [Setting up a vagrant environment](Documentation/vagrant.rst)
 * Manual installation: [Detailed installation instructions](Documentation/installation.rst)
 * Frequently Asked Questions: [FAQ](https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=is%3Aissue%20label%3Aquestion%20)

## Demo Tutorials

The following are video tutorials showcasing how to use Cilium:

 * [Networks & simple policies](https://asciinema.org/a/83373)
 * [Debugging a connectivity issue](https://asciinema.org/a/83376)
 * [Examine networking configuration of container](https://asciinema.org/a/83372)

## What is eBPF and XDP?

Berkley Packet Filter (BPF) is a bytecode interpreter orignially introduced
to filter network packets, e.g. tcpdump and socket filters. It has since been
extended to with additional data structures such as hashtable and arrays as
well as additional actions to support packet mangling, forwarding,
encapsulation, etc. An in-kernel verifier ensures that BPF programs are safe
to run and a JIT compiler converts the bytecode to CPU architecture specifc
instructions for native execution efficiency. BPF programs can be run at
various hooking points in the kernel such as for incoming packets, outgoing
packets, system call level, kprobes, etc.

<p align="center">
   <img src="Documentation/images/bpf-overview.png" width="508" />
</p>

XDP is a further step in evolution and enables to run a specific flavour of
BPF programs from the network driver with direct access to the packet's DMA
buffer.

## What are the benefits of Cilium's use of BPF?

 * **simple:**
   Every container is assigned a unique IPv6 address. An IPv4 address can be
   assigned optionally. There is no concept of networks, all containers are
   connected to a single virtual space. Isolation among containers is defined
   based on container labels.
 * **ipv6-focused**
   IPv6 is considered the primary addressing model with IPv4 support provided
   for backwards compatibility based on either native integration or with
   NAT46.
 * **extendable:**
   Users can extend and customize any aspect of the BPF programs. Forwarding
   logic and policy enforcement is not limited to the capabilities of a
   specific Linux kernel version. This may include the addition of additional
   statistics not provided by the Linux kernel, support for additional protocol
   parsers, modifications of the connection tracker or policy layer, additional
   forwarding logic, etc.
 * **fast:**
   The BPF JIT compiler integrated into the Linux kernel guarantees for
   efficient execution of BPF programs. A separate BPF program is generated for
   each individual container on the fly which allows to automatically reduce the
   code size to the minimal, similar to static linking.
 * **hotfixable:**
   Updates to the kernel forwarding path can be applied without restarting the
   kernel or any of the running containers.
 * **debuggable:**
   A highly efficient monitoring subsystem is integrated and can be enabled on
   demand at runtime. It provides visibility into the network activity of
   containers under high network speeds without disruption or introduction of
   latency.

## Prerequisites

The easiest way to meet the prerequisites is to use the provided vagrant box
which provides all prerequisites in a sandbox environment. Please see the
[vagrant guide](doc/vagrant.md) for more details.

In order to meet the prerequisites for an installation outside of vagrant,
the following components must be installed in at least the version specified:

 * Linux kernel (http://www.kernel.org/)
    * Minimum: >= 4.8.0
    * Recommended: >= 4.9.17. Use of a 4.9.17 kernel or later will ensure
      compatibility with clang > 3.9.x
 * clang+LLVM >=3.7.1. Please note that in order to use clang 3.9.x, the
   kernel version requirement is >= 4.9.17
 * iproute2 >= 4.8.0: https://www.kernel.org/pub/linux/utils/net/iproute2/

Cilium will make use of later kernel versions if available. It will probe
for the availability of the functionality automatically. It is therefore
perfectly acceptable to use a distribution kernel which has the required
functionality backported.

## Installation

See the [installation instructions](Documentation/installation.md).

## Integration

Cilium provides integration plugins for the following orchestration systems:
  * CNI (Kubernetes/Mesos) [Installation instructions](examples/kubernetes/README.md)
  * libnetwork (Docker) [Installation instructions](Documentation/docker.md)

## Contributions

We are eager to receive feedback and contributions. Please see the
[contributing guide](Documentation/contributing.md) for further instructions and ideas
on how to contribute.

## Presentations

 * Docker Distributed Systems Summit, Berlin, Oct 2016: [Slides](http://www.slideshare.net/Docker/cilium-bpf-xdp-for-containers-66969823), [Video](https://www.youtube.com/watch?v=TnJF7ht3ZYc&list=PLkA60AVN3hh8oPas3cq2VA9xB7WazcIgs&index=7)
 * NetDev1.2, Tokyo, Sep 2016 - cls_bpf/eBPF updates since netdev 1.1: [Slides](http://borkmann.ch/talks/2016_tcws.pdf), [Video](https://youtu.be/gwzaKXWIelc?t=12m55s)
 * NetDev1.2, Tokyo, Sep 2016 - Advanced programmability and recent updates with tc’s cls_bpf: [Slides](http://borkmann.ch/talks/2016_netdev2.pdf), [Video](https://www.youtube.com/watch?v=GwT9hRiqdUo)
 * ContainerCon NA, Toronto, Aug 2016 - Fast IPv6 container networking with BPF & XDP: [Slides](http://www.slideshare.net/ThomasGraf5/cilium-fast-ipv6-container-networking-with-bpf-and-xdp)
 * NetDev1.1, Seville, Feb 2016 - On getting tc classifier fully programmable with cls_bpf: [Slides](http://borkmann.ch/talks/2016_netdev.pdf), [Video](https://www.youtube.com/watch?v=KHXxSN5vwHY)

## Podcasts

 * Software Gone Wild by Ivan Pepelnjak, Oct 2016: [Blog](http://blog.ipspace.net/2016/10/fast-linux-packet-forwarding-with.html), [MP3](http://media.blubrry.com/ipspace/stream.ipspace.net/nuggets/podcast/Show_64-Cilium_with_Thomas_Graf.mp3)
 * OVS Orbit by Ben Pfaff, May 2016: [Blog](https://ovsorbit.benpfaff.org/#e4), [MP3](https://ovsorbit.benpfaff.org/episode-4.mp3)

## Blog posts

 * Cilium, BPF and XDP, Google Open Source Blog, Nov 2016: [Blog](https://opensource.googleblog.com/2016/11/cilium-networking-and-security.html)

## Contact

If you have any questions feel free to contact us on [Slack](https://cilium.herokuapp.com/)

## License

The cilium user space components are licensed under the
[Apache License, Version 2.0](LICENSE). The BPF code templates are licensed
under the [General Public License, Version 2.0](bpf/COPYING).
