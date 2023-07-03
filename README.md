# Nuitka Extractor

Nuitka extractor is a tool to extract nuitka compiled Python executables. In particular only onefile (single file) executables are supported. The tool can extract both Windows PE as well as Linux ELF binaries.

## Usage

Precompiled binaries can be downloaded from releases.

Simply pass the path to the file as an argument.

```
$ ./nuitka-extractor <file name>
```

```
X:\> nuitka-extractor.exe <file name>
```

## ToDo

- Signed PE execuables are not yet supported. Strip the certificate before extraction.
- Support for executables with a hardcoded extraction directory. For such executables, nuitka includes the crc32 of each embedded file within the payload. Thus the payload format is slightly changed.

## License

Nuitka extractor is released under the MIT license.