# ELK: Effective Lock-and-Key Technique for Temporal Memory Safety on Embedded Devices in ARMv8-M

Jeonghwan Kang, Kyounghwan Kim, and Donghyun Kwon (School of Computer Science and Engineering, Pusan National University)

This is the repository of our paper presented at the ACSAC 2025.

**Paper**: (to appear)

## Abstract

The artifacts submitted for our paper include a prototype of ELK, as described in the design (Section 6) and implementation (Section 7). ELK is comprised of two major components. A runtime library (RIOT-OS) and an LLVM pass to instrument the C source codes. The current implementation is based on the MPU and TT features (Armv8-M). To support these features, a development board based on the Armv8-M architecture is required. ELK has been tested on the NUCLEO-L552ZE-Q development board by STMicroelectronics. The current implementation uses a cross-compilation approach. The input to the ELK instrumentation pass is an LLVM bitcode file, and the output is an instrumented ELF binary.

## Contents

| File | Description |
|------|-------------|
| `examples` | Example C programs to test the basic functionality of ELK |
| `llvm-project-15` | Modified LLVM 15.0 for compiler instrumentation |
| `riot-os-2022` | Modified RIOT-OS 2022.10 for ELK runtime library |
| `env.sh` | Script to configure the running environment |
| `install-llvm.sh` | Script to automatically install modified LLVM for ELK |
| `pyterm.sh` | Script to connect the development board using pyterm |

## Dependencies

* Development boards NUCLEO-L552ZE-Q by STMicroelectronics (Available 8 MPU Regions, 256 KB SRAM)
* Ubuntu 22.04 LTS
* Embedded ARM cross-compiler toolchain

```
$ sudo apt install gcc-arm-none-eabi
$ pip3 install pyserial
```

## How to install

```
$ git clone https://github.com/kbhetrr/ELK
$ cd ELK
```

Let's install LLVM. Building LLVM can take some time.

```
$ ./install-llvm.sh
```

Then, load the environment in your current shell:

```
$ source env.sh
```

## Test if ELK is working

To check the test results of ELK, the development board must be connected to the terminal as shown below.

In a new terminal, enter the following:

```
$ ./pyterm.sh
```

* Expected output:
```
2025-09-08 10:59:22,561 # Connect to serial port /dev/ttyACM0
Welcome to pyterm!
Type '/exit' to exit.
```

Compile the example programs in the `examples` directory.

**use-after-free**

```
$ cd examples/use-after-free
$ make flash
```

* Expected output:
```
2025-09-08 11:10:35,736 # obj allocated at: 0x20006000
2025-09-08 11:10:35,739 # obj 0x20006000 has been deallocated
2025-09-08 11:10:35,740 # use after free...
2025-09-08 11:10:35,742 # [ELK] Use After Free Detected!
```

**double-free**

```
$ cd examples/double-free
$ make flash
```

* Expected output:
```
2025-09-08 11:06:52,065 # allocated: 0x20004000
2025-09-08 11:06:52,067 # freed once: 0x20004000
2025-09-08 11:06:52,069 # [ELK] Double Free Detected!
```

**invalid-free**

```
$ cd examples/invalid-free
$ make flash
```

* Expected output:
```
2025-09-08 11:04:33,627 # base: 0x20004000, interior: 0x20004008
2025-09-08 11:04:33,633 # [ELK] Invalid Free Detected! (Free of Pointer not at Start of Buffer)
```

---

To check whether ELK's instrumentation pass works correctly when compiling a C program, enter the following command:

```
$ cd examples/use-after-free
$ clang -emit-llvm -S use_after_free.c -o test.ll
$ cat test.ll
```

Afterward, you can confirm that the instrumentation code has been inserted as shown below:

```
...
  %arrayidx = getelementptr inbounds i8, i8* %3, i64 0
  %4 = call i8* @check_and_translation(i8* %arrayidx)
  %5 = load i8, i8* %4, align 1
...
```

## Citation

If you use this work or parts of it, please cite our paper as follows:

```
@inproceedings {

}
```