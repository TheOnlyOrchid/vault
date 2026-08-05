<div align="center">

# Vault
### A lean, local password manager written in C++

</div>

<table> 
  <tr> 
    <td width="50%" align="center"> 
      <img src="https://github.com/user-attachments/assets/389671b4-0c28-4b2c-bdaf-082bf483866e" alt="Unlocking an encrypted Vault" width="100%" > 
    </td> 
    <td width="50%" align="center"> 
      <img src="https://github.com/user-attachments/assets/0ca377a2-7939-48f3-a339-ae1be96dfb34" alt="Managing credentials and adding an entry" width="100%" > 
    </td> 
  </tr> 
  <tr> 
    <td align="center">
      <strong>
        Unlocking an encrypted vault
      </strong>
    </td> 
      <td align="center">
        <strong>
          Managing credentials
        </strong>
    </td> 
  </tr> 
</table>

## Selling points

**Completely local** - No accounts, no servers, nothing! No external party can compromise your passwords without accessing your machine.

**Secure encryption and hashing** - See security model below!

**Easy to use** - Very simple interface with self explanatory controls!

**Simple authentication** - One singular master password, nothing more to expose further attack vectors!

**Native C++ interface** - No web app bloat, just a pure ImGui, GLFW and OpenGL!

## Security model

Vault protects the entire contents of vault.dat as one singular encrypted blob. The master password is never written directly to this vault file - instead we combine it with a random salt, and process it through password based key derivation to produce an encrypted key!

When vault saves data - we serialise the vault entries to JSON in memory, encrypt the JSON and then write the resulting blob to disk. When vault opens an existing file - it derives the same key from the entered master password and salt stored in the file header, then authenticates and decrypts the blob!

Whenever we have to write plaintext passwords into memory - for stuff like GUIs, we use OpenSSL to try and make sure that the memory is zeroed as soon as it is no longer useful.

### What we use for different tasks

**Key derivation** - PBKDF2-HMAC-SHA-256 for converting the master password into an encryption key.

**Salt** - 16 pseudorandom bytes.

**Encryption** - AES-256-GCM for encrypting the vault, and verifying it is untouched.


# Building
Vault has been tested on both Windows and Linux. I however only have one Linux machine, if any issues arise, feel free to open an issue!

Requirements:
- A C++20 compiler
- CMAKE 3.20 or newer
- OpenSSL
- GLFW 3
- OpenGL

Both sets of build instructions assume you have downloaded the source code - and are located in the root folder of the project when starting.

## Windows

### 1. Get C++ Dependencies
Ensure Visual Studio (2022 is the one I have tested) with the C++ desktop development package is installed. 

### 2. Get VCPKG
Setup and install VCPKG, refer to https://github.com/microsoft/vcpkg for more information.

### 3. Install project dependencies with VCPKG
Set VCPKG_ROOT for the current powershell session:
```powershell
$env:VCPKG_ROOT = "C:/example/vcpkg"
```

### 4. Build Vault

Ensure you are running this from the root project directory.

```bash
cmake -S . -B build -A x64 ` -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
```

```bash
cmake --build build --config Release
```

### 5. Run!

Your exe should be located in ./build/Release/PasswordManager.exe


## Linux

### 1. Install dependencies
This will vary by distro - the command below is for Debian based distributions, as that is the most common type.

```bash
sudo apt update 

sudo apt install
  \ build-essential
  \ cmake
  \ git
  \ libssl-dev
  \ libglfw3-dev
  \ libgl1-mesa-dev
```

### 2. Build Vault
```bash
cmake -S . -B build -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
```

```bash
cmake --build build --parallel
```

### 3. Run!
Your executable should be located in ./build/PasswordManager


