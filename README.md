# Encryption

This project is a command line tool to encrypt and decrypt files and strings using AES-256-CBC encryption with PBKDF2 key derivation function and SHA-512 as hashing algorithm.

## Features

- String encoding and decoding
- Files and directories encryption and decryption
- Binary or Base64 encoding for files and directories
- Password-based key derivation
- Uses AES-256-CBC encryption
- Uses PBKDF2 key derivation function with SHA-512 hashing algorithm

### enc.sh specific features
- Key plus password encyption method
- Automatic key creation if not found in the config file

### enc.c specific features
- Automatic generation of salt and IV
- Directory encryption is streamed (not in enc.sh)

## Tutorial/Documentation

### C program (enc.c)

1. Compilation:

   To compile the `enc.c` file, use the `make` command.
   This will create an executable file called `enc` in the current directory.

2. Run the program with the appropriate options:

   ```
   ./enc {OPTIONS} [FILE|STRING]
   ```

   Options:

   - `-h, --help`: Show the help message and exit
   - `-s, --string`: Treat any file as its content

   Examples:

   ```
   ./enc "Hello, world!"             # Encode/decode a string
   ./enc -s input.txt                # Encode/decode the content of a file
   ./enc /path/to/file.txt           # Encrypt/decrypt a file
   ```

### Bash Script (enc.sh)

1. Make the script executable:

   ```
   chmod +x enc.sh
   ```

2. Run the script with the appropriate options:

   ```
   ./enc.sh [-s|--string] <file to encode>
   ./enc.sh <text to encode/decode>
   ./enc.sh [-h|--help]
   ```

   Options:

   - `-h, --help`: Show the help message and exit
   - `-s, --string`: Encrypt a file and encode the result in base64

   Examples:

   ```
   ./enc.sh "Hello, world!"           # Encode/decode a string
   ./enc.sh -s input.txt              # Encode/decode the content of a file
   ./enc.sh /path/to/file.txt         # Encrypt/decrypt a file
   ```

#### Configuring the key password (enc.sh)

The `enc.sh` script stores the encrypted key in a configuration file located at `$HOME/.config/encrypted`. If the configuration file does not exist or is empty, the script will prompt you to enter a new key password and generate a random key that will be encrypted and stored in the configuration file.
If you want to change the key password, you can delete the configuration file and run the script again. This will prompt you to enter a new key password and generate a new random key that will be encrypted and stored in the configuration file.

### Limitations

- The current implementation uses a fixed number of iterations for key derivation, which could be improved by making it user-configurable.
- The encryption algorithm used is AES-256-CBC, which could be extended to support other algorithms as well.
- The Bash script can store an encrypted key in a configuration file, which is not available in the C program. This feature could be added to the C program for consistency.
