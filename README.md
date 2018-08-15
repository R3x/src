# Kernel Address Sanitizer
This is the official github repository GSOC' 18 project "Integrating Kernel Address Sanitizer with the NetBSD kernel" 

Below are the reports that I have written about the same:

 - [Kernel Address Sanitizer, part 1](http://blog.netbsd.org/tnf/entry/gsoc_2018_reports_kernel_address)
 - [Kernel Address Sanitizer, part 2](http://blog.netbsd.org/tnf/entry/gsoc_2018_report_kernel_address)
 - [Kernel Address Sanitizer, part 3](http://blog.netbsd.org/tnf/entry/kernel_address_sanitizer_part_3)

## Branch - kasan
This is the main branch I have been working on. 
The code for KASan has been added in sys/kern. The following are the  files that have been added during the course of the project.

 - kern_asan.c ( Contains a major portion of the code for the KASan )
 - kern_asan_report.c ( Contains the reporting infrastructure for Bugs )
 - kern_asan_quarantine.c ( Contains the code for the quarantine list )
 - kern_asan_init.c ( Contains the code for initialisation of kasan during boot )
 - kasan.h ( Header file for KASan )

## Aditional work that I did as a part of GSoC
There are a few other tasks that I completed during the GSoC time period - which were helpful with respect to the project.

 
 - ATF tests for testing userland Asan for C and C++ programs ( Merged with main branch ) ( Commit [1](https://github.com/NetBSD/src/commit/e1c700be195789b84a971bf3db1d38b07b5dd971#diff-e98083658db8be5d33cec79dd58b7a7c), [2](https://github.com/NetBSD/src/commit/eddf6c479f88381caa7ddd9ed7bb498dbb9c935d#diff-e98083658db8be5d33cec79dd58b7a7c), [3](https://github.com/NetBSD/src/commit/4346dccf276c37a2bccfd3564e862641312709c9#diff-d6cfcc76f871c885609e4de13828ee59) ) ( [Blog](https://r3xnation.wordpress.com/2018/04/10/how-to-write-atf-tests-for-netbsd/) )
 - Example Kernel Module for adding a sysctl node ( Merged with main branch )  ( [Commit](https://github.com/NetBSD/src/commit/8348f4a8349be58e9c8d727257db0e162a1825c5#diff-2260bab32fff03c8311a5c7ebeb00055) )
 - Example Kernel Module for writing a MPSAFE kernel module ( Merged with main branch ) ( [Commit](https://github.com/NetBSD/src/commit/12fb4456c14bf75e00e653b6be0bc9a5fd8837d2#diff-2260bab32fff03c8311a5c7ebeb00055) )
 - Example Kernel Module for basic implementation of callout and RUN_ONCE ( Merged with the main branch ) ( [Commit](https://github.com/NetBSD/src/commit/e923d0a954a8c07633c6211d0ce5e4ea9aa8a1e6#diff-2260bab32fff03c8311a5c7ebeb00055) )
 - A bootoption for userland without ASLR ( [Branch](https://github.com/R3x/src/tree/boot_config/) )
 - Example Kernel Module for printing the kernel mappings  ( [File](https://github.com/R3x/src/tree/kasan/sys/modules/examples/kernel_map) )
