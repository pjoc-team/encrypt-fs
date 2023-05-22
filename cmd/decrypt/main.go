package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: decrypt <input_file> <output_dir> <password>")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputDir := os.Args[2]
	password := os.Args[3]

	err := decryptAndDecompressDirectory(inputFile, outputDir, password)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func decryptAndDecompressDirectory(inputFile, outputDir, password string) error {
	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	// Create AES-256 cipher
	key := []byte(password)
	for len(key) < 32 {
		key = append(key, ' ')
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return err
	}

	// Read IV from input file
	iv := make([]byte, aes.BlockSize)
	if _, err := inFile.Read(iv); err != nil {
		return err
	}

	// Create AES CBC decrypter
	decrypter := cipher.NewCBCDecrypter(block, iv)

	// Read encrypted data from input file
	encryptedData, err := ioutil.ReadAll(inFile)
	if err != nil {
		return err
	}

	// Decrypt data
	decryptedData := make([]byte, len(encryptedData))
	decrypter.CryptBlocks(decryptedData, encryptedData)

	// Remove padding
	padding := int(decryptedData[len(decryptedData)-1])
	decryptedData = decryptedData[:len(decryptedData)-padding]

	// Write decrypted data to a temporary file
	tempFile, err := ioutil.TempFile("", "decrypted-*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write(decryptedData); err != nil {
		return err
	}

	// Create gzip reader
	tempFile.Seek(0, io.SeekStart)
	gzipReader, err := gzip.NewReader(tempFile)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzipReader)

	// Extract files from the tar archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(outputDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			dir := filepath.Dir(target)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return err
			}

			outFile, err := os.Create(target)
			if err != nil {
				return err
			}
			defer outFile.Close()

			if _, err := io.Copy(outFile, tarReader); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown type: %v in %s", header.Typeflag, header.Name)
		}
	}

	return nil
}
