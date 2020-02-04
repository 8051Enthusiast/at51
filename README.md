# at51

[![Build Status](https://travis-ci.org/8051Enthusiast/at51.svg?branch=master)](https://travis-ci.org/8051Enthusiast/at51)
[![Crates.io](https://img.shields.io/crates/v/at51)](https://crates.io/crates/at51)

A bunch of applications for the purpose of reverse engineering 8051 firmware.
Currently, there are four applications:
* `stat`, which gives blockwise statistical information about how similar a given file's opcode distribution is to normal 8051 code
* `base`, which determines the load address of a 8051 firmware file
* `libfind`, which reads library files and scans the firmware file for routines from those files (right now, only OMF51 files supported, which are used by PL/M-51 and more importantly C51)
* `kinit`, which reads a specific init data structure generated by the C51 compiler

The output of each subcommand can also be used in other programs via JSON.

### stat
This subprogram is useful for determining which regions of a file are probably 8051.
If you want to determine the architecture of a file in general, a useful tool might be [cpu_rec](https://github.com/airbus-seclab/cpu_rec).

This subcommand does some statistics on the firmware.
It steps through the file as if it was a continuous instruction stream and does some tests on those instructions.
The image is divided into equal-sized blocks and the value of the test for each block (which by default has a size of 512) is given back.
That means it is normally more suited for bigger images (in this context, something like >4kB) where you want to know which regions are probably 8051 codes and which are data.

By default, it calculates the aligned jump test, which gives the percentage of relative jump instructions where the jump target is not on a start of an instructions.
This has a value of 0 to 1, where 0 is better and it generally works well, but has a lot of NaN on streams of 0s and similiar repeated instructions, as there are no jumps in those blocks.
If the location is entirely 8051 code, it should have a value of 0 (although someone might do some hacks with unaligned jumps), but it can contain small jump tables and therefore is sometimes not exactly zero, but still should be fairly low (<0.1).
One can additionally show the number of jumps used with the `-n` flag to know how certain the value is.
Furthermore, two other flags `-A` and `-O` exist, where the first one also includes absolute jumps in the calculation (useful if the file is already aligned and there are not enough jumps) and the second one includes jumps to outside the firmware image as misses (useful with `-A` if one knows there is no code outside the firmware and the firmware file does not cover the whole address space).

It can also do a blockwise Kullback-Leibler divergence on the distribution on the opcodes, which means each block has a value from 0 to 1, 0 being the most 8051-like.
With that metric, <0.06 usually means it is 8051 code, 0.06-0.12 means it is probably either 8051 with some data in it (like a jump table) or it is unusual (maybe a small set of instructions repeated a lot of times).
Note that random data is only at roughly 0.25, so the Kullback-Leibler might not be very reliable.

An alternative is a chi squared test on the distribution of opcodes, which is can have a value bigger than 1 and is not constrained in its values.
But as a downside, it is harder to say what ranges usually are 8051 code, as that changes for example with blocksize.
It is useful for comparing the 8051-ness of different blocks and is normally more reliable thatn Kullback-Leibler divergence in that case.
Also note that I have no experience in statistics so I maybe doing things wrong.

I normally do not need the second or third option (Kullback-Leibler or chi squared) and they exist mostly because I didn't implement the first test until later.

One can use the output as the input for gnuplot, for example with
```bash
at51 stat path/to/firmware | gnuplot -p -e "plot '-' with lines"
```
### base
This application tries to determine the load address of a firmware image (which in the best case only includes the actual firmware that will be on the device).
It loads the first 64k of a given file and for each offset determines how many `ljmp`s/`lcall`s jump right behind `ret` instructions, as that is the place where new functions normally starts.
The offset is interpreted cyclically inside the 16-bit space, which means that at offset 0xffe0, the first 0x20 bytes are loaded at 0xffe0-0xffff and the rest is then loaded at the start of the address space.
The likeliness of the output is the amount of jumps and calls that target instructions right behind `ret`s, as in this example:
```
Index by likeliness:
	1: 0x3fe0 with 218
	2: 0xc352 with 89
	3: 0xd096 with 87
```
Here the most likely load location is 0x3fe0, as it has 218 fitting `ljmp`/`lcall` instructions, in contrast to the only 89 instructions or 87 instructions of the second and third case.
In the example given, the load location of this particular 0x3fe0 address is caused by a 0x20 byte header and the code itself starts at 0x4000.

Normally, `acall`/`ajmp` are ignored since this introduces a lot of noise by non-code data (1/16th of the 8051's instruction set is `acall`/`ajmp`) and can be enabled with the `-a` flag, but make sure that noisy/non-8051 parts of the files (as detectable with entrpoy and the `stat` application) are zeroed-out.

One can also use multiple firmware images where one knows that they are loaded at the same location (useful for smaller images where also different revisions exist), in which case the arithmetic mean of the fitting instructions on each offset is calculated.
### libfind
This application loads some libraries given by the user and tries to find the standard library functions inside the firmware.
Right now, OMF-51 libraries from C51 (which is the compiler of most firmwares in my experience) and sdld libraries from sdcc are supported

In general, library files contains some bytes of the library functions and then some "fixup" locations which are changed at linking time and are often targets of jumps.
They are normally divided into different segments and each segment can have public symbols defined for itself and each fixup location can reference other segments by id or public symbol.

For each segment, the occurences of it are found by comparing the bytes of the non-fixup locations against each possible location in the firmware.
It then tries to verify that it is actually the segment by following the fixups (which can be done by reading the values in the firmware that are at the fixup location) and determining if the referenced segments are at the targets referenced by the firmware.

The public symbols of each matching segment is then output, along with its location and sometimes a description.
If some referenced segment is not there, it is output in square brackets to signify that.
On the other hand, if a segment is referenced but not actually there, that is output in parentheses (this is mostly useful for finding main, as it cannot be included in the libraries, but is referenced).
If there are multiple segments matching, but one matches better (nothing > square brackets > parentheses), only the ones that match best are output.

For C51, the relevant libraries are of the form C51\*.LIB (not C[XHD]51\*.LIB) and can currently be found on the internet just by searching for them (one name that might pop up is C51L.LIB), but you can of course also try to download the trial version of C51 to get the libraries from there.

When searching for functions in a C51-compiled firmware, one thing that will often pop up is a `[?C_START]` and a `(MAIN)`.
This is because the compiler inserts a function called `?C_START` before main which loads variable variable from a data structure, which can be read by `at51 kinit`.
`?C_START` is in square brackets because it references `MAIN`, which of course is not a library function, which is the same reason `(MAIN)` is in parentheses.

For sdcc, the relevant libraries are normally found at `/usr/share/sdcc/lib/{small,small-stack-auto,medium,large,huge}/` if you have a linux sdcc installation.
Note that noise with sdcc libraries might be higher, as the fixup locations in the library files do not specify whether the target is in the code, imem etc. address space.

It is recommended to align the file to its load address before using this, since absolute locations may fail to verify otherwise.
Segments shorter than 4 bytes are not output, since they provide much noise and don't really add any info.

Example (on some random wifi firmware):

With `at51 libfind some_random_firmware /path/to/lib/dir/`:
```
Address | Name                 | Description
0x4220    ?C?CLDOPTR             char (8-bit) load from general pointer with offset
0x424d    ?C?CSTPTR              char (8-bit) store to general pointer
0x425f    ?C?CSTOPTR             char (8-bit) store to general pointer with offset
0x4281    ?C?IILDX              
0x4297    ?C?ILDPTR              int (16-bit) load from general pointer
0x42c2    ?C?ILDOPTR             int (16-bit) load from general pointer with offset
0x42fa    ?C?ISTPTR              int (16-bit) store to general pointer
0x4319    ?C?ISTOPTR             int (16-bit) store to general pointer with offset
0x4346    ?C?LOR                 long (32-bit) bitwise or
0x4353    ?C?LLDXDATA            long (32-bit) load from xdata
0x435f    ?C?OFFXADD            
0x436b    ?C?PLDXDATA            general pointer load from xdata
0x4374    ?C?PLDIXDATA           general pointer post-increment load from xdata
0x438b    ?C?PSTXDATA            general pointer store to xdata
0x4394    ?C?CCASE              
0x43ba    ?C?ICASE              
0x46f5    [?C_START]            
0x50e1    (MAIN)                
```

For some symbol names, which are in a general form, there are descriptions available.

### kinit
This application is very specific to C51 generated code in that it decodes a specific data structure used to initialize memory values on startup.
The structure is read by the `?C_START` procedure and the location of the structure can therefore usually be found by running libfind and looking at the two bytes after the start of `?C_START` (since it starts with a `mov dptr, #structure_address`).
When `(?C_START)` is in parentheses, this is probably not the case, as `?C_START` is referenced by the `ljmp` at location 0 in the keil libraries, which happens to be the instruction at the start of most 8051 firmwares even if there is no `?C_START` function.

Example:

With `at51 kinit -o offset some_random_firmware`:
```
bit 29.6 = 0
idata[0x5a] = 0x00
xdata[0x681] = 0x00
xdata[0x67c] = 0x00
xdata[0x692] = 0x00
xdata[0x6aa] = 0x01
xdata[0x46f] = 0x00
bit 27.2 = 0
bit 27.0 = 0
bit 26.3 = 0
bit 26.1 = 0
xdata[0x47d] = 0x00
xdata[0x40c] = 0x00
bit 25.3 = 0
xdata[0x46d] = 0x00
idata[0x5c] = 0x00
xdata[0x403..0x40a] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
xdata[0x467] = 0x00
```

## INSTALL
With cargo one can install it with `cargo install at51`.

Alternatively, to install from source, do
```
git clone 'https://github.com/8051Enthusiast/at51.git'
cargo install --path at51
```

