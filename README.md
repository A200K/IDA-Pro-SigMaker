# IDA Pro SigMaker
Signature Maker Plugin for IDA Pro 8.2

## Requirements
- IDA Pro Plugin SDK 8.2. Previous versions might work as well though.

## Installation
Drop into plugins folder of your IDA installation.

## Usage
In disassembly view, select a line you want to generate a signature for, and press 
**CTRL+ALT+S**
![](https://i.imgur.com/cKQJVam.png)

The generated signature will be printed to the output console, as well as copied to the clipboard:
![](https://i.imgur.com/3YCQ2nn.png)
___

Generating code Signatures by data or code xrefs and finding the shortest ones is also supported:
![](https://i.imgur.com/P0VRIFQ.png)
