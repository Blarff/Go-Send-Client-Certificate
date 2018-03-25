package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"time"
)

// ReadPEMFile - function used to read private and public pem files
func ReadPEMFile(path, passphrase string) ([]byte, error) {
	pass := []byte(passphrase)
	var blocks []*pem.Block

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(content) > 0 {
		var block *pem.Block

		block, content = pem.Decode(content)
		if block == nil {
			if len(blocks) == 0 {
				return nil, errors.New("no pem file")
			}
			break
		}

		if x509.IsEncryptedPEMBlock(block) {
			var buffer []byte
			var err error
			if len(pass) == 0 {
				err = errors.New("No passphrase available")
			} else {
				// Note, decrypting pem might succeed even with wrong password, but
				// only noise will be stored in buffer in this case.
				buffer, err = x509.DecryptPEMBlock(block, pass)
			}

			if err != nil {
				panic(err)
			}

			// DEK-Info contains encryption info. Remove header to mark block as
			// unencrypted.
			delete(block.Headers, "DEK-Info")
			block.Bytes = buffer
		}
		blocks = append(blocks, block)
	}

	if len(blocks) == 0 {
		return nil, errors.New("no PEM blocks")
	}

	// re-encode available, decrypted blocks
	buffer := bytes.NewBuffer(nil)
	for _, block := range blocks {
		err := pem.Encode(buffer, block)
		if err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func transport() *http.Transport {
	// Load private key
	keyPEM, err := ReadPEMFile("${PATH_TO_ENCRYPTED_KEY_FILE_HERE}", "${KEY_FILE_PASSWORD}")
	if err != nil {
		panic(err)
	}

	// Load public key
	certPEM, err := ReadPEMFile("${PATH_TO_ASSOCIATED_PUBLIC_KEY}", "")
	if err != nil {
		panic(err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	// Load CA certs
	rootCA, err := ioutil.ReadFile("${PATH_TO_CERTIFICATE_AUTHORITY(S)}")
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()

	// need to append every certificate authority
	certPool.AppendCertsFromPEM(rootCA)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}
	tlsConfig.BuildNameToCertificate()
	return &http.Transport{TLSClientConfig: tlsConfig}
}

// HTTPClient - Instantiate HTTP Client
func HTTPClient() *http.Client {
	var hc = http.Client{
		Timeout:   time.Second * 30,
		Transport: transport(),
	}
	return &hc
}
