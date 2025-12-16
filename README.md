# CIFERA

A normal encryption algorithm utilizing and combining some current strong algorithms + small stuff to obfuscate it a tiny bit more...
im just.. dumb...

## Traits

- Encrypt and decrypt text files
- Easy to use
- Contains well known algorithms such as RSA-2048, AES-256-CBC, and HMAC-SHA256.
- Decoy messages (4 decoys 1 real, currently)

## Cloning and Usage

Clone the repository:

```bash
git clone https://github.com/svetlyi223/cifera.git
cd cifera
```

Make sure you have `make` and `OpenSSL` installed:

### Linux

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y make openssl libssl-dev

# Fedora
sudo dnf check-update
sudo dnf install -y make openssl-devel

# CentOS / RHEL
sudo yum check-update
sudo yum install -y make openssl-devel

# Arch / Manjaro
sudo pacman -Syu
sudo pacman -S make openssl
```

### MacOS
```bash
brew install make openssl
```

### Windows (Using Chocolatey)
```powershell
choco install -y make openssl
```

Create `input.txt` file with message if not yet created (will change so it can be any file later [same with decryption too]).
Also, please do not forget to edit `cifera_main.cpp` and declare the keys at the top of the file.

Once that's done, just run `make` once:

```bash
make
```

If you ran make once, you can just directly run the executable next time (unless otherwise):
```bash
./cifera
```

## Random Q/A
Q: Was all the time wasted worth it?

A: Nah
