LowFat: Lean C/C++ Bounds Checking with Low-Fat Pointers
========================================================

LowFat is a new bounds checking system for the `x86-64` based on the idea
*low-fat pointers*.  LowFat is designed to detect object *out-of-bounds*
errors (OOB-errors), such as buffer overflows (or underflows), that are a
common source of crashes, security vulnerabilities, and other program
misbehavior.  LowFat is designed to have low overheads, especially memory,
compared to other bounds checking systems.

The basic idea of *low-fat pointers* is to encode bounds information (size and
base) directly into the native bit representation of a pointer itself.  This
bounds information can then retrieved at runtime, and be checked whenever the
pointer is accessed, thereby preventing OOB-errors.  Low-fat pointers have
several advantages compared to existing bounds checking systems, namely:

* *Memory Usage*: Since object bounds information is stored directly in
  pointers (and not is some other meta data region), the memory overheads of
  LowFat is very low.
* *Compatibility*: Since low-fat pointers are also ordinary pointers, LowFat
  achieves high binary compatibility.
* *Speed*: Low-fat pointers are fast relative to other bounds-checking systems.

The LowFat system uses the low-fat pointer encoding described in papers [1]
and [2].  The basic idea is to subdivide the programs virtual address space
into several large *region*s, where each region is responsible for the
allocation of objects of a given fixed size range, as illustrated by the
diagram below.

<p align="center">
<img src="https://www.comp.nus.edu.sg/~gregory/lowfat/layout.png" width="60%"
alt="LowFat memory layout" border="1">
</p>

The first region contains the programs `text`, `data`, `bss`, etc., segments
as usual.  The subsequent regions are used for low-fat pointer allocation.
For example, region #1 is used for allocations of size 1-16bytes, region #2
for allocations of size 17-32bytes, etc.  Furthermore, all LowFat allocated
objects are aligned to allocation-size boundaries.  Using these properties,
the object's bounds information can be reconstructed based on the pointer
value.  As an example, consider the allocation:

        p = malloc(10);

The LowFat system will allocation `p = 0x8997f2820` (or similar value).
Under the default LowFat configuration, addresses `0x800000000-0xfffffffff`
are reserved for objects of size `1-16` bytes (the original allocation size of
10bytes is "rounded up" to 16bytes, as is common practice with `malloc`
implementations).

Given the pointer `q = p + 5 = 0x8997f2825`, we can reconstruct the size and
base of the object pointed to by `q` by working backwards:

* Since `q` is within the range (`0x800000000..0xfffffffff`) we know that the
  allocation size of the object pointed to by `q` is 16bytes.
* Since `q - (q mod 16) = 0x8997f2820` we know that he base address of
  the object pointed to by `q` is `0x8997f2820`.

Next, consider the following (trivial) function:

        char get(char *q, int i)
        {
            return q[i];
        }

The LowFat system will instrument the function into something like the
following:

        char get(char *q, int i)
        {
            char *q_base = base(q);
            size_t q_size = size(q);
            char *r = q + i;
            if (r < q_base || r >= q_base + q_size)
                report_oob_error();
            return *r;
        }

Here the `size` and `base` operations are implemented as described above.  If
we consider the function call `get(q, 20)`, then this will be detected as an
OOB-error since the read object is outside the object bounds
(`0x8997f2820..0x8997f282f`).  LowFat will report the error and abort the
program:

        LOWFAT ERROR: out-of-bounds error detected!
                operation = read
                pointer   = 0x8997f2825 (heap)
                base      = 0x8997f2820
                size      = 16
                overflow  = +20

In addition to heap objects, the LowFat system can also protect stack and
global objects.  The description above is only a very high-level overview.  In
reality there are many other issues and technical details, see [1] and [2] for
more information.

Building
--------

To build LowFat from source just run the `build.sh` script.

        $ tar xvfz lowfat-src.tar.gz
        $ cd lowfat-src
        $ ./build.sh

Note that building LowFat may take some time since it seems to build a
modified LLVM-4.0 system.  If `clang-4.0` is not already installed
the build script will attempt to bootstrap a version.

After the build is complete, LowFat can be used by invoking a modified version
of `clang-4.0` in the `build/bin/` sub-directory:

        build/bin/clang
        build/bin/clang++

Note that the modified `clang` can be invoked directly.  There is no need to
install it on your system (but you can if you want to).

Usage
-----

LowFat is implemented as a modified version of `clang-4.0`.  To compile a
program (`prog.c`) with LowFat instrumentation enabled, simply compile as
follows:

        $ /path/to/lowfat/build/bin/clang -fsanitize=lowfat -O2 -c prog prog.c

C++ is also supported:

        $ /path/to/lowfat/build/bin/clang++ -fsanitize=lowfat -O2 -c prog prog.cpp

LowFat supports several command line options that are listed below.
Note that to pass an option to LowFat it must be preceded by `-mllvm` on the
`clang` command-line, e.g. (`-mllvm -lowfat-no-check-reads`), etc.

* `-lowfat-no-check-reads`: Do not OOB-check reads
* `-lowfat-no-check-writes`: Do not OOB-check writes
* `-lowfat-no-check-escapes`: Do not OOB-check pointer escapes
  (of any kind)
* `-lowfat-no-check-memset`: Do not OOB-check memset
* `-lowfat-no-check-memcpy`: Do not OOB-check memcpy or memmove
* `-lowfat-no-check-escape-call`: Do not OOB-check pointer call escapes
* `-lowfat-no-check-escape-return`: Do not OOB-check pointer return escapes
* `-lowfat-no-check-escape-store`: Do not OOB-check pointer store escapes
* `-lowfat-no-check-escape-ptr2int`: Do not OOB-check pointer 
   pointer-to-int escapes
* `-lowfat-no-check-escape-insert`: Do not OOB-check pointer vector insert
  escapes
* `-lowfat-no-check-fields`: Do not OOB-check field access (reduces the
  number of checks)
* `-lowfat-check-whole-access`: OOB-check the whole pointer access
  `ptr..ptr+sizeof(*ptr)` as opposed to just `ptr`
  (increases the number and cost of checks). 
* `-lowfat-no-replace-malloc`: Do not replace malloc() with LowFat
  `malloc()` (disables heap protection)
* `-lowfat-no-replace-alloca`: Do not replace stack allocation (`alloca`)
   with LowFat stack allocation (disables stack protection)
* `-lowfat-no-replace-globals`: Do not replace globals with LowFat globals
   (disables global variable protection)
* `-lowfat-no-check-blacklist blacklist.txt`: Do not OOB-check the
  functions/modules specified in `blacklist.txt`
* `-lowfat-no-abort`: Do not abort the program if an OOB memory error
  occurs

The LowFat distribution also includes a (`lowfat-ptr-info`) tool that can
print information about a given pointer value.  For example:

        $ /path/to/lowfat/build/bin/lowfat-ptr-info 0x8997f2825
        ptr    = 0x8997f2825
        type   = heap
        region = #1 (0x800000000)
        base   = 0x8997f2820
        size   = 16 (0x10)
        magic  = 1152921504606846977 (0x1000000000000001)
        offset = 5

Experiments
-----------

We experimentally evaluate LowFat against the SPEC2006 benchmark suite.
The results for the default configuration are shown below.

<p align="center">
<img src="https://www.comp.nus.edu.sg/~gregory/lowfat/results.png" width="60%"
alt="LowFat SPEC2006 timings">
</p>

Overall we see that LowFat introduces a 64% performance overhead.

We can also optimize LowFat for *software hardening*, i.e., preventing buffer
overflows in production software.  To do this it is important to optimize the
overhead versus protection ratio, since the default overhead of 64% is
generally too costly for many applications.  We can enable several options that
lower the overheads of LowFat at the expensive of also lowering runtime
protections:

* `-lowfat-no-check-reads`: Most (but not all) security exploits require a
  memory write operation.  We can significantly lower overheads by not
  bounds checking memory reads.
* `-lowfat-no-check-escapes`: Most (but not all) OOB-pointer escapes
  occur in conjunction with an OOB-memory access.  We can lower overheads
  by not bounds checking pointer escapes.
* `-lowfat-no-check-fields`: OOB-errors due to (non-array) field access are
  less common than those caused by array/buffer overflows.  We can lower
  overheads by only bounds checking array/buffer access.

After applying these optimizations, we see that overall overhead LowFat is
significantly reduced to ~9.8% overall:

<p align="center">
<img src="https://www.comp.nus.edu.sg/~gregory/lowfat/results_opt.png"
width="60%" alt="Optimized LowFat SPEC2006 timings">
</p>

Note that optimized LowFat can even make some benchmarks go faster.  This is
because the LowFat heap allocator happens to be faster than the default
`malloc` for these examples.  The overhead can also be further reduced by
forcing object sizes to be powers-of-two, meaning that LowFat can use
bit-masking operations to calculate an object's base address as opposed to the
default fixed point arithmetic.  However, enabling this mode requires a
recompilation:

        rm -rf build/
        ./build.sh sizes2.cfg 32

The overhead further drops to ~7.8% overall.

Since LowFat does not explicitly store bounds information in separate meta
data, the memory overheads of LowFat are very low (~3%) for SPEC2006 [2].  If
powers-of-two sizes are used, memory overhead increases to (~12%).

Caveats
-------

There are a few caveats with the LowFat system, and are listed below:

* **Sub-Object versus Object versus Allocation Bounds**:
During allocation, LowFat may "round-up" the requested allocation size (a.k.a.
object size) to some larger value (allocation size).  The space left at the
end of the object will be unused "padding".  LowFat protects allocation bounds
only, and thus cannot detect overflows into this unused padding.  Similarly
LowFat offers no protection against sub-object bounds overflows and any
related attacks.
* **Escaping Pointers**:
By default, LowFat prevents OOB-pointers being *accessed* (written to or read
from) or *escaping* (passed to another function, returned, stored in memory,
or cast to an integer).  Escaping pointers are disallowed since they can
disguise OOB-errors, e.g. reading from an OOB-pointer passed to another
function.  Bounds checking of pointer escapes can be disabled using the
(`-mllvm -lowfat-no-check-escapes`) options.
* **Global Variables**:
LowFat can only protect global variables that occur in the main executable,
and not any that occur in dynamically linked libraries.  This is because the
dynamic linker does not support `section` directives and the linker scripts
required to place global objects in the correct LowFat positions.
(Note that the program will still compile and run, only that overflows in
 such globals will not be detected.)
Another caveat is that LowFat must move global objects outside of the first
4GB of the virtual address space.  To support this, the executable must be
compiled using the *large* code model (`-mcmodel=large`), which usually incurs
a performance penalty.  The *large* code model is automatically enabled
whenever the `-fsanitize=lowfat` option is passed to `clang`.  LowFat also
does not protect globals with exotic linkage, custom section, or annotated
with an incompatible alignment attribute.
* **NULL overflows**:
Currently LowFat does not protect against NULL pointer overflows, e.g.
`NULL[idx]` can access any address.  There are some ideas but this is left
as future work.
* **Operating System**: The current LowFat implementation supports Linux only.
In principle, LowFat could be ported to other systems such as Windows, but
this requires some developer effort, and thus is not supported by the
current release.
* **Modern 64bit CPUs**:
In order to run "full" LowFat you need a reasonably modern 64bit CPU that
supports `lzcnt`, `bmi` and `bmi2`.
* **Stack Object Ordering**:
Some programs assume stack objects are ordered, i.e., more recently allocated
objects occur at lower addresses than older objects (for stack-grows-down).
LowFat will break these assumptions.
Note that the low-fat stack allocator can be disabled by the
(`-mllvm -lowfat-no-replace-alloca`) command-line options.
* **Custom Stacks**:
Custom stacks (e.g., `sigaltstack` or some `pthread_create` configurations)
are not currently supported by LowFat instrumented code.
* **Fork and Clone**:
The LowFat stack uses shared memory as an optimization (see [2] for details).
This also causes a problem with `fork` and `clone` meaning that the parent and
child will share the same stack memory (usually leading to a crash).  To
prevent this, the LowFat runtime intercepts `fork` and manually copies the
stack, which makes LowFat `fork` somewhat slower than native `fork`.  Also,
programs that call `clone` directly or any other `fork`-like functions are not
currently supported.
* **UglyGEPs**:
The `clang` optimization pipeline may create OOB-pointers that are detected
by LowFat.  To prevent false positives, such pointers are currently ignored
for pointer-to-integer escape instrumentation.
A better solution to this problem is left as future work.
* **LowFat Runtime Hardening**: The LowFat runtime itself has not been hardened.
By design, some internal tables may overflow (read) for large invalid pointer
values.
* **Spectre**:
LowFat cannot prevent OOB-reads due to speculative execution on vulnerable
CPUs.  For more information, see the
[Spectre](https://spectreattack.com/spectre.pdf) paper.  We believe this bug
similarly affects other bounds-check instrumentation systems.
* **Low Level Hacks**:
The LowFat runtime system uses a few very low-level hacks to try and implement
necessary functionality, such as moving the program stack and cleaning up stacks
on thread exit.  These hacks are likely fragile.  Finding better solutions
is left as future work.

Most of these caveats (such as NULL overflows, the operating system, custom
stacks, `clone`, runtime hardening and low-level hacks) are implementation
issues that may be addressed by future updates.

FAQ
---

**Q: Does LowFat handle one-past-end-of-the-array pointers allowable under the
C standard?**

A: Yes is does.  LowFat handles this case by always "rounding up" object sizes
by at least one byte, meaning that the pointer to the end of an object (a.k.a.
one-past-end-of-the-array) is always within the allocation bounds.  This trick
was "borrowed" from the Boehm conservative garbage collector, which must also
handle such pointers to avoid erroneously collecting live objects.

**Q: Why do we need LowFat when we already have AddressSanitizer?**

LowFat and AddressSanitizer are similar tools in that both can detect
OOB-memory errors.  The main difference between the two tools is the
underlying technology, and each approach has its pros and cons.  
AddressSanitizer inserts "poisoned redzones" between objects and detects
overflows into these zones.  The main advantages of AddressSanitizer over
LowFat are:

* Better at detecting off-by-one errors (LowFat does not detect overflows
  into padding).
* Can also detect use-after-free errors.

The main disadvantages of AddressSanitizer over LowFat are:

* High performance and very high memory overheads.
* Overflows that "skip" redzones cannot be detected.

The latter makes AddressSanitizer less suitable for program hardening for
cases where the attacker can control the offset.

**Q: Why do we need LowFat when we already have SoftBound/MPX?**

A: Both SoftBound and MPX have the advantage that they are designed to detect
sub-object bounds overflows, something which LowFat does not do directly
(however, see below).  However, both SoftBound and MPX have
compatibility problems, namely by changing the ABI (SoftBound) and with
multi-threaded code (shared state in contention).

**Q: Can LowFat detect other types of errors, such as:**

* **Accurate (i.e., no "rounding up") object bounds overflows**
* **Sub-object bounds overflows**
* **Use-after-free, or**
* **Type confusion errors?**

A: Yes with the suitable extensions.  We plan to release an extended system
sometime in 2018.

Versions
--------

The released version of LowFat differs from the prototype evaluated in [1] and
[2].  To replicate the results of [2] as closely as possible, (1) ensure that
LowFat has been built with `lzcnt` support, and (2) compile your program with
the following options:

        -fsanitize=lowfat -O2 -mllvm -lowfat-no-replace-globals

With these options enabled, the performance overhead of LowFat reduces to 59%,
which is comparable to the (_+alias_) results reported in [2].

Thanks
------

This research was partially supported by a grant from
the National Research Foundation, Prime Minister's Office,
Singapore under its National Cybersecurity R&D Program
(TSUNAMi project, No. NRF2014NCR-NCR001-21) and administered
by the National Cybersecurity R&D Directorate.

This research was partially supported by the UK EPSRC research grant
EP/L022710/1.

Bugs
----

LowFat should be considered beta quality software.
It has not yet been extensively tested on software other than the
SPEC2006 benchmark suite.

Please submit bug reports to
[https://github.com/GJDuck/LowFat/issues](https://github.com/GJDuck/LowFat/issues).

Bibliography
------------

[1] Gregory J. Duck, Roland H. C. Yap, [Heap Bounds Protection with Low Fat
Pointers](https://www.comp.nus.edu.sg/~gregory/papers/cc16lowfatptrs.pdf),
International Conference on Compiler Construction, 2016

[2] Gregory J. Duck, Roland H. C. Yap, Lorenzo Cavallaro, [Stack Bounds
Protection with Low Fat Pointers](https://www.comp.nus.edu.sg/~gregory/papers/ndss17stack.pdf),
The Network and Distributed System Security Symposium, 2017

