# BearSSL-PS3

A project which will initialise a vcxproj file which can then be used to build BearSSL for the PS3. Utilises the official PS3 SDK and NOT PSL1GHT.  
This project also includes a test application for the same, which has a decent example of what you need to do in order to implement BearSSL in your own PS3 project.

BearSSL can be found here : https://www.bearssl.org/

## Using this Project

These instructions will go through the process of building BearSSL as a static linked library, along with the test application

### Prerequisites

Requirements for the software and other tools to build, test and push 
- [Visual Studio (2013 or greater)](https://visualstudio.microsoft.com/downloads/)
- PS3 SDK Version 4.75
- [Git](https://git-scm.com/downloads)
- [libpsutil](https://github.com/skiff/libpsutil/releases/tag/1.0.5) - May be required, not tested

I would use this guide to get everything setup if you don't have it setup already - https://www.youtube.com/watch?v=j7Mgl4oVACM

### Setting Up

Clone this git repository

    git clone https://github.com/Protract-123/BearSSL-PS3

change your working directory via the command below

    cd .\BearSSL-PS3\BearSSL

Run the included powershell script

    .\init_vcxproj.ps1

These steps will initialize the vcxproj for the BearSSL library itself.

### Building the Solution

1. Open the solution file, which will be in the root of the cloned repo
2. Change the build configuration of the solution to "Release" through the toolbar
3. Build the entire solution

This will create the PS3_Release folder in the root of the cloned git repository. This should contain BearSSL.a and BearSSL-Test.self.  
The test application can then be run, and it should print a variety of logs which can be viewed through a tool like ProDG.

I suggest copying the built static linked library and the "inc" folder to somewhere in usr\local\cell so it can be easily used in your projects.
