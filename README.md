# Pcap Capture and Read
 This program can capture on network and read on exist pcap file from UDP, TCP , ICMP packets


# About
 This project power on [PcapPlusPlus](https://pcapplusplus.github.io/)

# How to build and run this project 
 This project have different dependencies for different operating system.
* Windows
    * Download [WinPcap Development](https://www.winpcap.org/devel.htm)
    * Download [PcapPlusPlus](https://pcapplusplus.github.io/docs/install) 
        * If you use visual studio use for install this [doc](https://pcapplusplus.github.io/docs/install/build-source/vs)
        * If you use mingw use for install this [doc](https://pcapplusplus.github.io/docs/install/build-source/mingw)
    * You should use for build Makefile.windows.mk but first you have to change include path
    * Finally use make mingw32-make.exe -f Makefile.windows.mk for build and for run [**your program name, default name is pcapplusplus.exe**]
* Linux
    * sudo apt-get install libpcap-dev
    * Run main directory of PcapPlusPlus ./configure-linux.sh
    * Run make all then run make install
    * Check this [doc](https://pcapplusplus.github.io/docs/install/build-source/linux) 
    * You should use for build Makefile.linux.mk but first you have to change include path
    * Finally use make -f Makefile.linux.mk for build and for run ./[**your pragram name or default name is pcapplusplus**]
