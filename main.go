package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/text/encoding/unicode"
)

type FileType int

const (
	ELF FileType = iota
	PE
)

type CompressionFlag int

const (
	NON_COMPRESSED CompressionFlag = iota
	COMPRESSED
)

type NuitkaExecutable struct {
	path         string
	fileType     FileType
	fPtr         *os.File
	decoder      io.Reader
	compressFlag CompressionFlag
}

func (ne *NuitkaExecutable) New(path string) {
	ne.path = path
}

func (ne *NuitkaExecutable) Check() bool {
	var err error
	ne.fPtr, err = os.Open(ne.path)
	if err != nil {
		fmt.Println("[!] Couldn't open %s", ne.path)
		return false
	}
	fmt.Println("[+] Processing", ne.path)

	// Rudimentary file check logic
	var magic = make([]byte, 4)
	_, err = ne.fPtr.Read(magic)
	if magic[0] == 0x4d && magic[1] == 0x5a {
		ne.fileType = PE
		fmt.Println("[+] File type: PE")
	} else if magic[0] == 0x7F && magic[1] == 0x45 && magic[2] == 0x4C && magic[3] == 0x46 {
		fmt.Println("[+] File type: ELF")
		ne.fileType = ELF
	} else {
		fmt.Println("[!] Unsupported file type")
		return false
	}

	streamPosition, _ := ne.fPtr.Seek(-8, os.SEEK_END)

	var payLoadSize int64
	var payloadSizeBuf = make([]byte, 8)
	ne.fPtr.Read(payloadSizeBuf)
	binary.Read(bytes.NewReader(payloadSizeBuf), binary.LittleEndian, &payLoadSize)
	fmt.Println("[+] Payload size:", payLoadSize, "bytes")

	payLoadStartPos := streamPosition - payLoadSize
	ne.fPtr.Seek(payLoadStartPos, os.SEEK_SET)

	var nuitkaMagic = make([]byte, 3)
	ne.fPtr.Read(nuitkaMagic)

	if nuitkaMagic[0] == 'K' && nuitkaMagic[1] == 'A' {
		if nuitkaMagic[2] == 'X' {
			ne.compressFlag = NON_COMPRESSED
			fmt.Println("[+] Payload compression: false")
			return true
		} else if nuitkaMagic[2] == 'Y' {
			ne.compressFlag = COMPRESSED
			fmt.Println("[+] Payload compression: true")
			return true
		}
	}

	fmt.Println("[!] Nuitka magic header mismatch")
	return false
}

func (ne *NuitkaExecutable) readFileName() string {
	var buffer []byte
	if ne.fileType == PE {
		buffer = make([]byte, 2)
	} else {
		buffer = make([]byte, 1)
	}

	var fileName string

	for {
		ne.readChunk(buffer)
		if buffer[0] == 0 {
			break
		}
		fileName += string(buffer)
	}
	if ne.fileType == PE {
		utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		fileName, _ = utf16.String(fileName)
	}
	return fileName
}

func (ne *NuitkaExecutable) dumpFile(fileSize uint64, outpath string) {
	dir, _ := filepath.Split(outpath)
	os.MkdirAll(dir, 0755)

	f, err := os.Create(outpath)
	if err != nil {
		fmt.Println("[!] Couldn't write", outpath)
		return
	}

	remaining := int64(fileSize)

	for {
		nBytes, _ := io.CopyN(f, ne.decoder, remaining)
		remaining -= nBytes
		if remaining == 0 {
			break
		}
	}
	f.Close()
}

func (ne *NuitkaExecutable) readChunk(buf []byte) {
	var read = 0

	for {
		nBytes, _ := ne.decoder.Read(buf[read:])
		read += nBytes
		if read == len(buf) {
			break
		}
	}
}

func (ne *NuitkaExecutable) Extract() {
	var err error
	ne.decoder, err = zstd.NewReader(ne.fPtr)
	if err != nil {
		fmt.Println("[!] Couldn't initialize zstd for decompression")
		return
	}
	fmt.Println("[+] Beginning extraction...")
	var extractionDir = ne.path + "_extracted"
	os.Mkdir(extractionDir, 0755)

	total_files := 0

	for {
		fn := ne.readFileName()
		if fn == "" {
			break
		}
		if ne.fileType == ELF {
			var fileFlags = make([]byte, 1)
			ne.readChunk(fileFlags)
		}

		var fileSize uint64
		var fileSizeBuffer = make([]byte, 8)
		ne.readChunk(fileSizeBuffer)
		fileSize = binary.LittleEndian.Uint64(fileSizeBuffer)

		// TODO: 4 bytes crc32 is at this position
        // if executable uses custom extraction directory
        // 
        // https://github.com/Nuitka/Nuitka/blob/c371b3/nuitka/build/static_src/OnefileBootstrap.c#L959
        // https://github.com/Nuitka/Nuitka/blob/c371b3/nuitka/tools/onefile_compressor/OnefileCompressor.py#L184-L187
        // https://github.com/Nuitka/Nuitka/blob/c371b3/nuitka/Options.py#L1538

		// Basic path sanitization
        extractionDir = strings.ReplaceAll(extractionDir, "..", "__")        
        var outpath = filepath.Join(extractionDir, fn)
		ne.dumpFile(fileSize, outpath)
		total_files += 1
	}
	fmt.Println("[+] Total files:", total_files)
	fmt.Println("[+] Successfully extracted to", extractionDir)
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Usage: nuitka-extractor <filename>")
		return
	}

	ne := NuitkaExecutable{}
	ne.New(os.Args[1])
	if ne.Check() {
		ne.Extract()
	}
}
