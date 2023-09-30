# IDA Pro SigMaker
Signature Maker Plugin for IDA Pro 8.3

## Requirements
- IDA Pro Plugin SDK 8.3. Previous versions >= 8.0 might work as well though.

## Installation
Drop into plugins folder of your IDA installation.

## Usage
In disassembly view, select a line you want to generate a signature for, and press 
**CTRL+ALT+S**
![](https://i.imgur.com/et8zumy.png)

The generated signature will be printed to the output console, as well as copied to the clipboard:
![](https://i.imgur.com/bYPiyvF.png)

___

| Signature type | Example preview |
| --- | ----------- |
| IDA Signature | E8 ? ? ? ? 45 33 F6 66 44 89 34 33 |
| x64Dbg Signature | E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33 |
| C Byte Array Signature + String mask | \xE8\x00\x00\x00\x00\x45\x33\xF6\x66\x44\x89\x34\x33 x????xxxxxxxx |
| C Raw Bytes Signature + Bitmask | 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33  0b1111111100001 |

___

Generating code Signatures by data or code xrefs and finding the shortest ones is also supported:
![](https://i.imgur.com/P0VRIFQ.png)
