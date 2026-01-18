# Nuitka Extractor

Nuitka extractor is a tool to extract nuitka compiled Python executables. In particular only onefile (single file) executables are supported. The tool can extract both Windows PE as well as Linux ELF binaries.

Nuitka compiles Python code to native code. A nuitka compiled executable doesn't contain pyc file. Hence this tool can only extract DLLs, shared libraries and other binary assets embedded in the executable.

## Usage

Precompiled binaries can be downloaded from releases.

Simply pass the path to the file as an argument.

```bash
$ ./nuitka-extractor <file name>
```

```cmd
X:\> nuitka-extractor.exe <file name>
```

## ToDo

- Signed PE execuables are not yet supported. Strip the certificate before extraction.

## License

Nuitka extractor is released under the MIT license.