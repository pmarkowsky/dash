# Dash -- the quick dash assembler / disassembler

A simple web assembler / disassembler

Dash is a simple flask based web application for editing and 

Think of it as a [REPL](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop) for assembly languages.

# Installation

Dash depends on [capstone](http://www.keystone-engine.org/) and [keystone](http://www.keystone-engine.org/). So first things first install those as per the docs on their sites.

Once you've installed capstone and keystone, use pip to install all of the flask requirements. 

`pip install -r requirements.txt`

This will install flask-restful. 

# Usage

To start from the command line where you've checked out dash go run

`python webasm.py`

This will start the server on port 5555,browse there and away you go. 

## Writing Basic Assembly

To write assembly simply click on the *mnemonic* field and type in the mnemoic and hit enter e.g. XOR eax, eax. On x86 only right now if you start an instruction with a jmp or a call it will attempt to offer you auto-completion suggestions for labels.

For example if you add a label to an instruction called *myLabel* and then later start typing `JMP M` Dash will attempt to make auto-complete suggestions for you. 

## Adding Comments

Simply edit the comments field to keep

## Editing Bytes

The opcodes column is directly editable as well. Here you need to enter in each byte as a hexadecimal number. This will cause dash to disassemble. 

## Changing Processor Modes

You can change which processor mode dash works in, when this happens it will disassemble all of the bytes in the opcodes fields of each row in the new mode. This could be useful if you want to look at things like [polyglot shellcode](http://hyperpolyglot.org/unix-shells).

Changing Dash's configuration is accomplish using the three dropdown menus in the upper right hand corner.

These are:
  * ARCH: The CPU architechture to operate in
  * MODE: Right now this is just 16-bit, 32-bit, or 64-bit
  * ENDIANESS: which is tells dash to assemble instructions as big endian or little endian
  
Supported Configurations are:
 * x86 16-bit Little Endian
 * x86 32-bit Little Endian
 * x86 64-bit Little Endian
 * ARM 16-bit mode Big or Little Endian (This is Thumb)
 * ARM 32-bit mode Big or Little Endian (This is just ARMv7)
 * ARM64 64-bit mode Little Endian (This is AArch64)
 * MIPS 32-bit Big or Little Endian

*Note* dash will not change modes to an unsupported configuration e.g. Big Endian X86.
