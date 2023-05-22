package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: encrypt <input_file> <password>")
		os.Exit(1)
	}

	dir := os.Args[1]
	password := os.Args[2]

	outputFile := fmt.Sprintf("%s.goen", dir)

	fmt.Printf("target: %s.goen\n", dir)

	err := encryptAndCompressDirectory(dir, outputFile, password)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func encryptAndCompressDirectory(dir, outputFile, password string) error {
	// Create AES-256 cipher
	key := []byte(password)
	for len(key) < 32 {
		key = append(key, ' ')
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Create AES CBC encrypter
	encrypter := cipher.NewCBCEncrypter(block, iv)

	// Create a buffer to store compressed data
	var compressedData bytes.Buffer

	// Create gzip writer
	gzipWriter := gzip.NewWriter(&compressedData)

	// Create tar writer
	tarWriter := tar.NewWriter(gzipWriter)

	// Walk through the directory and add files to the tar archive
	err = filepath.Walk(
		dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}

			header.Name = strings.TrimPrefix(path, string(filepath.Separator))

			if err := tarWriter.WriteHeader(header); err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(tarWriter, file)
			return err
		},
	)

	if err != nil {
		return err
	}

	// Close tar writer
	err = tarWriter.Close()
	if err != nil {
		return err
	}

	// Close gzip writer to flush data to compressedData buffer
	err = gzipWriter.Close()
	if err != nil {
		return err
	}

	// Pad compressed data to be a multiple of the block size
	padding := aes.BlockSize - len(compressedData.Bytes())%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	paddedData := append(compressedData.Bytes(), padText...)

	// Encrypt data
	encryptedData := make([]byte, len(paddedData))
	encrypter.CryptBlocks(encryptedData, paddedData)

	// Create output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Write IV to output file
	_, err = outFile.Write(iv)
	if err != nil {
		return err
	}

	// Write encrypted data to output file
	_, err = outFile.Write(encryptedData)
	if err != nil {
		return err
	}

	return nil
}

func outFileSize(f *os.File) int64 {
	fi, err := f.Stat()
	if err != nil {
		return 0
	}
	return fi.Size()
}
