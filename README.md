# BearSSL-PS3

A project which will initialise a vcxproj file which can then be used to build BearSSL for the PS3. Utilises the official PS3 SDK and NOT PSL1GHT

BearSSL can be found here : https://www.bearssl.org/

## Using this Project

These instructions will build BearSSL as a static linked library which can then be used in your PS3 homebrew projects.

### Prerequisites

Requirements for the software and other tools to build, test and push 
- [Visual Studio (2013 or greater)](https://visualstudio.microsoft.com/downloads/)
- PS3 SDK Version 4.75

### Installing

Clone this git repository

    git clone sample

CD into the repository

    cd ./BearSSL-PS3

Run the included powershell script

    ./init_vcxproj.ps1

Now you can open BearSSL.vcxproj and build the library which will be built into a seperate directory.  
I suggest copying your static linked library and the "inc" folder to somewhere else for easier usage.