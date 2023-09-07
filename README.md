# Extended-Implementation-of-eBPF-Bootstrap
This is an extended implementation of the bootstrap example in the libbpf official repository. ([libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap.git))

This extended implementation is named as **tracer**.

### Development Info
**version**: trace 0.0
**contact**: <yang.gao@some.ox.ac.uk> *legit till 2025*
**function**: It traces process start and exits and shows associated 
information (start time, filename, process duration, PID and PPID, etc).

### Usage
``` console
$ git clone --recurse-submodules https://github.com/yanggao04/Extended-Implementation-of-eBPF-Bootstrap.git
$ cd src
```
to download.

``` console
$ make
```
to compile everything. (including other examples)

``` console
$ make tracer
```
to compile *tracer* exclusively.

Run `$ ./tracer` to start the program. 
Try `$ ./tracer -d <min-duration-ms>` as well.

### How does it work
The official repository has already provided the environment, including *libbpf*, *vmlinux*, *bpf*, which is essential for any CO-RE (Compile Once, Run Everywhere) eBPF program based on *libbpf-bootstrap*.

By running `$ make` or `$ make tracer`, the compiler first construct the environment of *libbpf*. Then it compiles `~.bpf.c`, which provides the kernel space source code, into `~.bpf.o`, then `~.skel.h`, which is an overview of the `~.bpf.c` file for the convenience of user space program. Then `~.c` into `~.o`, like what normal gcc does, and finally link everything together, generating the binary program.

When running the program, it will first load the kernel space programs into corresponding hooks/probes, then communicates with them via bpf map in user space program.

### tracer vs bootstrap
*tracer* seems to have very similar results as *bootstrap*. Indeed, the only difference is that *tracer* can still generate the execution program names when a minimum duration is given, though not in chronological order, while *boostrap* doesn't.
However, to implement this functionality, there are lots of supplementary patches made and the flow of logic has changed dramatically.
For *bootstrap*, the program simply skip all *execution* processes detected when given a minimum duration. While in *tracer*, all executions detected are passed on to the user space program. They will be pre-processed in the user space program and saved in a new bpf map. When a process with the same pid is detected to exit, the kernel space will filter out the processes that are not elligble, if a duration is given. This makes the *tracer* more flexible and further development can be made to generate various functionalities.