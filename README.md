# BearSSL-PS3

A project that will initialize a vcxproj file, which can then be used to build BearSSL for the PS3. Utilizes the official PS3 SDK and NOT PSL1GHT.

This project also includes a test application for the same, which has a decent example of what you need to do in order to implement BearSSL in your own PS3 project.

BearSSL can be found here : https://www.bearssl.org/

If you notice something wrong with the readme, some issue with the compiled BearSSL library, or any other problem, please make an issue describing the problem.

## Using this Project

These instructions will go through the process of building BearSSL as a static linked library, along with the test application.

### Prerequisites

Requirements for the software and other tools to build, test, and push 

- [Visual Studio (2013 or greater)](https://visualstudio.microsoft.com/downloads/)

- PS3 SDK Version 4.75

- [Git](https://git-scm.com/downloads)

- [libpsutil](https://github.com/skiff/libpsutil/releases)

I would use this guide to get everything set up if you don't have it set up already: https://www.youtube.com/watch?v=j7Mgl4oVACM

### Setting Up

Clone this Git repository.

    git clone https://github.com/Protract-123/BearSSL-PS3

Change your working directory via the command below.

    cd .\BearSSL-PS3\BearSSL

Run the included PowerShell script.

    .\init_vcxproj.ps1

These steps will initialize the vcxproj for the BearSSL library itself.

### Building the Solution

1. Open the solution file, which will be in the root of the cloned repo.

2. Change the build configuration of the solution to "Release" through the toolbar.

3. Build the entire solution.

This will create the PS3_Release folder in the root of the cloned Git repository. This should contain BearSSL.a and BearSSL-Test.self.

The test application can then be run, and it should print a variety of logs that can be viewed through a tool like ProDG.

Please note that there may be an error when building using a fresh copy of the PS3 SDK. If you go to the source of the file that has the issue, there should be multiple "noexcept" that can be removed to fix the error. No idea if this is good practice, but it's what worked for me.

I suggest copying the built static linked library and the "inc" folder to somewhere in usr\local\cell so it can be easily used in your projects.

## SSL Info

The SSL results can be found [here](ssl_info.json). They were generated through https://www.howsmyssl.com/a/check via the test app included in this repository.

## License

This project uses the MIT License, which can be found [here](LICENSE)

