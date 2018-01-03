# UxStyle #

## Important Note ##
UxStyle is now in read-only mode and will not be updated. There are known compatibility issues with Windows 10 Creators Update (and above) that have will not be resolved due to lack of interest, use, and time.

## About ##

UxStyle is a bit of software that relaxes Windows theme signature requirements to enable third-party customization. Specifically, UxStyle consists of a tiny system service and a kernel driver that are loaded into memory where they hang out until reboot. No file system changes are made.

(First introduced on March 19, 2009.)

## Operating System Support ##

* Windows codenamed "Whistler" (escrow builds)
* Windows XP
* Windows Vista
* Windows 7
* Windows 8
* Windows 8.1
* Windows Server 2003
* Windows Server 2008
* Windows Server 2008 R2
* Windows Server 2012
* Windows Server 2012 R2
* Windows codenamed "Threshold"
* Windows 10 Technical Preview

## Building ##

### Required software ##

* Visual Studio 2013
* [Windows Driver Kit (WDK) for Windows 8.1](http://msdn.microsoft.com/en-us/library/windows/hardware/dn249725)
* [Windows Software Development Kit for Windows 8.1](http://msdn.microsoft.com/en-us/windows/desktop/bg162891.aspx)
* [WiX Toolset v3.8](https://wix.codeplex.com/releases/view/115492) (untested with newer)

### Note about code signing ###

Starting with Windows Vista, the kernel-mode code signing policy controls whether a kernel-mode driver will be loaded. The signing requirements depend on the version of the Windows operating system and on whether the driver is being signed for public release or by a development team during the development and test of a driver.

More information can be found via the resources below:

* [Kernel-Mode Code Signing Requirements](http://msdn.microsoft.com/en-us/library/windows/hardware/ff548239)
* [Cross-Certificates for Kernel Mode Code Signing](http://msdn.microsoft.com/en-us/library/windows/hardware/dn170454)
* [Driver Signing Policy](http://msdn.microsoft.com/en-us/library/windows/hardware/ff548231)

**Legacy Windows users:** Pay particular attention to the hashing algorithm used in your code signing certificate. Windows 7 and below do not support the loading of kernel drivers signed with newer SHA-2-based certificates.

More information can be found in [Microsoft Security Advisory 2880823](https://technet.microsoft.com/library/security/2880823).

### Fuzzy step-by-step ###

1. Open UxStyle.sln and start a Batch Build for the following project configurations:
	* UnsignedThemes (x64, Release)
	* UnsignedThemes (x86, Release)
	* UxPatch (x86, Win 8 Release)
	* UxPatch (x64, Win 8 Release)

2. Manually sign build artifacts:
	* \bin\x86\Release\UnsignedThemes.exe
	* \bin\x64\Release\UnsignedThemes.exe
	* \bin\driver\x86\uxstyle.sys
	* \bin\driver\amd64\uxstyle.sys

3. Return to Visual Studio and Batch Build the following project configurations:
	* Installer (x64, Release)
	* Installer (x86, Release)

4. (optional) Manually sign build artifacts:
 	* \bin\x86\Release\Installer.msi
 	* \bin\x64\Release\Installer.msi

5. Return to Visual Studio and build Bundle (x86, Release).

6. Manually sign build artifact \bin\bundle\Release\UxStyle_Bundle.exe
