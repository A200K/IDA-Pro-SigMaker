# IDA Pro SigMaker
Signature Maker Plugin for IDA Pro 8 and 9

Plugin downloads are in the [Releases](https://github.com/A200K/IDA-Pro-SigMaker/releases/) section

## Installation
Drop into plugins folder of your IDA installation.

`%AppData%\Hex-Rays\IDA Pro\plugins`

## Usage
In disassembly view, select a line you want to generate a signature for, and press 
**CTRL+ALT+S**
![](https://i.imgur.com/KeeUaTG.png)

The generated signature will be printed to the output console, as well as copied to the clipboard:
![](https://i.imgur.com/5xU091M.png)

___

| Signature type | Example preview |
| --- | ----------- |
| IDA Signature | E8 ? ? ? ? 45 33 F6 66 44 89 34 33 |
| x64Dbg Signature | E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33 |
| C Byte Array Signature + String mask | \xE8\x00\x00\x00\x00\x45\x33\xF6\x66\x44\x89\x34\x33 x????xxxxxxxx |
| C Raw Bytes Signature + Bitmask | 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33  0b1111111100001 |

___
### Finding XREFs
Generating code Signatures by data or code xrefs and finding the shortest ones is also supported:
![](https://i.imgur.com/P0VRIFQ.png)

___
### Signature searching
Searching for Signatures works for supported formats:

![](https://i.imgur.com/lD4Zfwb.png)

Just enter any string containing your Signature, it will automatically try to figure out what kind of Signature format is being used:

![](https://i.imgur.com/oWMs7LN.png)

Currently, all output formats you can generate are supported.

Match(es) of your signature will be printed to console:

![](https://i.imgur.com/Pe4REkX.png)

___
### Other
This plugin uses qis's AVX2-optimized signature searching library: https://github.com/qis/signature

If the CPU doesn't support AVX2, it will fallback to the slow builtin IDA functions.

___
## Building

### Requirements
- IDA Pro Plugin SDK 8 / 9

### Setup
For your convenience, here are the steps to get started:
```git
git clone git@github.com:A200K/IDA-Pro-SigMaker.git
cd IDA-Pro-SigMaker/
git submodule init
git submodule update
```
Then, 
- drop the IDA SDK into the according ```SDK/8``` or ```SDK/9``` path
- open the project with Visual Studio
