package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/glacier"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	maxRetries = 5
	baseDelay  = 1 * time.Second
	maxDelay   = 30 * time.Second
)

const oneMB int64 = 1024 * 1024

func main() {
	vaultName := flag.String("vault", "", "Vault name")
	filePath := flag.String("file", "", "File to upload")
	flag.Parse()

	if *vaultName == "" || *filePath == "" {
		fmt.Println("Usage: glacier-upload -vault <vaultname> -file <filename>")
		os.Exit(1)
	}

	if cfg, err := config.LoadDefaultConfig(context.TODO()); err != nil {
		panic(err)
	} else {
		fmt.Printf("Using AWS Region: %s\n", cfg.Region)
	}

	err := uploadFileToGlacier(*vaultName, *filePath)
	if err != nil {
		log.Fatalf("Error uploading file: %v", err)
	}

	fmt.Println("Upload successful")
}

func uploadFileToGlacier(vaultName, filePath string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()

	fmt.Println("Computing hashes...")
	treeHash, linearHash, err := computeHashes(filePath)
	if err != nil {
		return err
	}

	if fileSize < 4*1024*1024*1024 {
		// File is less than 4GB, use UploadArchive
		return uploadArchiveSingle(cfg, vaultName, filePath, treeHash, linearHash)
	} else {
		// Use multipart upload
		return uploadArchiveMultipart(cfg, vaultName, filePath, treeHash, fileSize)
	}
}

func computeHashes(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	// Initialize the linear hash and the tree hash
	linearHash := sha256.New()
	var chunkHashes [][]byte
	buf := make([]byte, oneMB)
	for {
		n, err := io.ReadFull(file, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return "", "", err
		}
		if n == 0 {
			break
		}

		linearHash.Write(buf[:n])

		h := sha256.Sum256(buf[:n])
		chunkHashes = append(chunkHashes, h[:])

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	treeHashBytes := computeTreeHashFromHashes(chunkHashes)
	treeHash := hex.EncodeToString(treeHashBytes)

	linearHashBytes := linearHash.Sum(nil)
	linearHashHex := hex.EncodeToString(linearHashBytes)

	return treeHash, linearHashHex, nil
}

func computeTreeHashFromHashes(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		// Return the SHA256 of empty string
		emptyHash := sha256.Sum256([]byte{})
		return emptyHash[:]
	}
	for len(hashes) > 1 {
		var newHashes [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i], hashes[i+1]...)
				h := sha256.Sum256(combined)
				newHashes = append(newHashes, h[:])
			} else {
				// If odd number of hashes, carry over the last one
				newHashes = append(newHashes, hashes[i])
			}
		}
		hashes = newHashes
	}
	return hashes[0]
}

func uploadArchiveSingle(cfg aws.Config, vaultName, filePath, treeHash, linearHash string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	input := &glacier.UploadArchiveInput{
		AccountId:          aws.String("-"),
		VaultName:          aws.String(vaultName),
		Body:               file,
		Checksum:           aws.String(treeHash),
		ArchiveDescription: aws.String(filePath),
	}

	customClient := glacier.NewFromConfig(cfg, func(o *glacier.Options) {
		o.APIOptions = append(o.APIOptions, addContentSHA256HeaderMiddleware(linearHash))
	})

	resp, err := customClient.UploadArchive(context.TODO(), input)
	if err != nil {
		return err
	}

	fmt.Printf("Archive ID: %s\n", aws.ToString(resp.ArchiveId))
	return nil
}

func addContentSHA256HeaderMiddleware(linearHash string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Build.Add(middleware.BuildMiddlewareFunc("AddContentSHA256Header", func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
			req, ok := input.Request.(*smithyhttp.Request)
			if !ok {
				return middleware.BuildOutput{}, middleware.Metadata{}, fmt.Errorf("unknown transport type %T", input.Request)
			}
			req.Header.Set("X-Amz-Content-Sha256", linearHash)
			return next.HandleBuild(ctx, input)
		}), middleware.After)
	}
}

func uploadArchiveMultipart(cfg aws.Config, vaultName, filePath, fileTreeHash string, fileSize int64) error {
	svc := glacier.NewFromConfig(cfg)

	partSize := int64(128 * 1024 * 1024) // 128Mb

	input := &glacier.InitiateMultipartUploadInput{
		AccountId:          aws.String("-"),
		VaultName:          aws.String(vaultName),
		ArchiveDescription: aws.String(filePath),
		PartSize:           aws.String(fmt.Sprintf("%d", partSize)),
	}

	initResp, err := svc.InitiateMultipartUpload(context.TODO(), input)
	if err != nil {
		return err
	}

	uploadID := aws.ToString(initResp.UploadId)
	fmt.Printf("Initiated multipart upload with UploadId: %s\n", uploadID)

	numParts := int((fileSize + partSize - 1) / partSize)

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	buf := make([]byte, partSize)
	for i := 0; i < numParts; i++ {
		start := int64(i) * partSize
		end := start + partSize - 1
		if end >= fileSize {
			end = fileSize - 1
		}

		partSizeActual := end - start + 1

		n, err := io.ReadFull(file, buf[:partSizeActual])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		partData := buf[:n]

		partTreeHash := computeTreeHashFromBytes(partData)
		partTreeHashHex := hex.EncodeToString(partTreeHash)

		partLinearHash := sha256.Sum256(partData)
		partLinearHashHex := hex.EncodeToString(partLinearHash[:])

		rangeHeader := fmt.Sprintf("bytes %d-%d/*", start, end)
		uploadPartInput := &glacier.UploadMultipartPartInput{
			AccountId: aws.String("-"),
			VaultName: aws.String(vaultName),
			Checksum:  aws.String(partTreeHashHex),
			Range:     aws.String(rangeHeader),
			UploadId:  aws.String(uploadID),
		}

		// Upload with retries.
		var uploadErr error
		for retries := 0; retries <= maxRetries; retries++ {
			if retries > 0 {
				delay := calculateBackoff(retries)
				fmt.Printf("Retrying part %d upload (attempt %d/%d) after %v...\n",
					i+1, retries, maxRetries, delay)
				time.Sleep(delay)

			}

			uploadPartInput.Body = bytes.NewReader(partData)

			customClient := glacier.NewFromConfig(cfg, func(o *glacier.Options) {
				o.APIOptions = append(o.APIOptions, addContentSHA256HeaderMiddleware(partLinearHashHex))
			})

			_, uploadErr = customClient.UploadMultipartPart(context.TODO(), uploadPartInput)
			if uploadErr == nil {
				break
			}

			if retries == maxRetries {
				return fmt.Errorf("failed to upload part %d after %d retries: %v",
					i+1, maxRetries, uploadErr)
			}
		}

		fmt.Printf("Uploaded part %d/%d\n", i+1, numParts)
	}

	completeInput := &glacier.CompleteMultipartUploadInput{
		AccountId:   aws.String("-"),
		VaultName:   aws.String(vaultName),
		ArchiveSize: aws.String(fmt.Sprintf("%d", fileSize)),
		Checksum:    aws.String(fileTreeHash),
		UploadId:    aws.String(uploadID),
	}

	var completeResp *glacier.CompleteMultipartUploadOutput
	var completeErr error
	for retries := 0; retries <= maxRetries; retries++ {
		if retries > 0 {
			delay := calculateBackoff(retries)
			fmt.Printf("Retrying completion (attempt %d/%d) after %v...\n",
				retries, maxRetries, delay)
			time.Sleep(delay)
		}

		completeResp, completeErr = svc.CompleteMultipartUpload(context.TODO(), completeInput)
		if completeErr == nil {
			fmt.Printf("Multipart upload completed. Archive ID: %s\n",
				aws.ToString(completeResp.ArchiveId))
			return nil
		}

		if retries == maxRetries {
			return fmt.Errorf("failed to complete multipart upload after %d retries: %v",
				maxRetries, completeErr)
		}
	}

	fmt.Printf("Multipart upload completed. Archive ID: %s\n", aws.ToString(completeResp.ArchiveId))
	return nil
}

func calculateBackoff(retryAttempt int) time.Duration {
	expBackoff := float64(baseDelay) * math.Pow(2, float64(retryAttempt))

	// Add jitter (±20% of the backoff value)
	jitter := (rand.Float64()*0.4 - 0.2) * expBackoff

	delay := time.Duration(expBackoff + jitter)

	if delay > maxDelay {
		delay = maxDelay
	}

	return delay
}

func computeTreeHashFromBytes(data []byte) []byte {
	// Read the data in 1MB chunks
	var hashes [][]byte
	for i := 0; i < len(data); i += int(oneMB) {
		end := i + int(oneMB)
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		h := sha256.Sum256(chunk)
		hashes = append(hashes, h[:])
	}

	return computeTreeHashFromHashes(hashes)
}
