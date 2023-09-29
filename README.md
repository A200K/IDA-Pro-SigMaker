# IDA Pro SigMaker
Signature Maker Plugin for IDA Pro 8.3

## Requirements
- IDA Pro Plugin SDK 8.3. Previous versions >= 8.0 might work as well though.

## Installation
Drop into plugins folder of your IDA installation.

## Usage
In disassembly view, select a line you want to generate a signature for, and press 
**CTRL+ALT+S**
![](https://i.imgur.com/cKQJVam.png)

The generated signature will be printed to the output console, as well as copied to the clipboard:
![](https://i.imgur.com/3YCQ2nn.png)

___

| Signature type | Example preview |
| --- | ----------- |
| IDA Signature | E8 ? ? ? ? EB ? 45 33 C0 48 2B |
| x64Dbg Signature | E8 ?? ?? ?? ?? EB ?? 45 33 C0 48 2B |
| C Signature + String mask | \xE8\x00\x00\x00\x00\xEB\x00\x45\x33\xC0\x48\x2B\xC2 x????x?xxxxxx |
| C Byte Array Signature + Bitmask | 0xE8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x00, 0x45, 0x33, 0xC0, 0x48, 0x2B, 0xC2 0b1111110100001 |

___

Generating code Signatures by data or code xrefs and finding the shortest ones is also supported:
![](https://i.imgur.com/P0VRIFQ.png)
