# Variable-Terminal-Shared

## Overview

This software is a collection of shared libraries for project Variable-Terminal.

Most package names of the shared libraries are shaded whenever possible.

## Building from sources

The minimum required java version to build from sources is at least JDK 1.5.

The included scripts "build.bat" and "build.sh" perform the build process<br>
using ant and the file "build.xml" is an ant build file for this software.

After running the ant build file, the packaged application distributions can be<br>
found in the "dist" folder.

## Used libraries

Those are the third party libraries used in this software:

* MindTerm by AppGate, for circular buffer pipe stream
* JZlib by Atsuhiko Yamanaka, for pure java zlib compression
* jpountz lz4-java by Adrien Grand, for lz4 compression and xxhash checksum
* Java Native Access by Todd Fast/Timothy Wall/Liang Chen, for native calls
* jsocks by Kirill Kouzoubov/Robert Simac, for SOCKS proxy tunneling
* JSAP by Martian Software, for command parsing
* ARGBPixelGrabber by pumpernickel, for image data extraction
* UPNPLib by sbbi, for UPnP NAT port forwarding support
* TomP2P by Thomas Bocek, for NAT-PMP NAT port forwarding support
* JSpeex by Horizon Wimba, for Speex audio communication
* Concentus Java by Logan Stromberg, for Opus audio communication
* client-side Throttle by James Edwards, for network data rate limiter
* DirectRobot by Killer99 from rune-server.ee, for better screen capture
* PortMapper by Kasra Faghihi(offbynull) for PCP port forwarding support
* Lanterna by mabe02 for graphical console
* Sixlegs Java PNG Decoder for PNG decoding
* bouncycastle by Legion of the Bouncy Castle for encryption
* airlift-aircompressor by Martin Traverso for zstd and lzo compression
* nanohttpd-1.1 by elonen, for HTTP proxy tunneling
* commons-httpclient by Apache Software Foundation, for HTTP proxy client
* commons-rng by Apache Software Foundation, for splitmix64 prng
* Base85 by Sheep-y, for backported Base85 encoder/decoder
* PngEncoder by Looklet, for better PNG image encoding
* MinimalFTP by Guilherme Chaguri, for FTP server tunneling
* BeanShell by Pat Niemeyer for alternative shell
* XXH3 by Infinispan for xxh3 64 bit hashing

## License

<pre>This software is under MIT license

Copyright (c) AD 2025 William Kendi Nishio

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.</pre>