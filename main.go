package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/emmansun/gmsm/pkcs12"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"io"
	"os"
)

func main() {
	strcipher := `MHkCIQCNiQv0R/D0YRkPk2wOMz35OmJ4aOwlrx57j7+9KeXCbQIgWoM3eo3I+pljL2huA1zghCkuKPn+rND//wI4dA0wqIAEIKTlZcD84mdLrz4Aj7rYiScxKoJIuK5RRRXWqw25YNgCBBANboU+SGQ7FqdmHMaA+owY`
	strp12 := `MIIFlAIBAzCCBWAGCSqGSIb3DQEHAaCCBVEEggVNMIIFSTCCBDcGCSqGSIb3DQEHBqCCBCgwggQkAgEAMIIEHQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIGJD3cLXt2UsCAggAgIID8JMkQaKphq8zCcTmOYH0K4HcKWTRi7u9bOG7zO5Go0r6ZLYgVj+Kmh7osZ3F42wGHJK8zkkhpGUIt2ImZY+6+6wBAvPnwl9sqsKs1KtZGQQHrRPqZQapLDsLjlarM7auf7sjsLlFl5I/XdjoCm9F5BXec/VDkrGgnuR0kNFW2joQPVbTv1drXHNmZohzMbYrbOwhtmy9z5hSx6qApoJ/BKbc0tZ4sPz6LPdDhIX6Ukro9mvYfj1mMS2g2v2ds2xCPor8Fh/LtK1J7oE/EEddoeSyBjTi8/68VNS7tUNi28VsvH3eYtMdHiFgb3mxTHd51hd6XBT+S9a52ru8RVG7L3mmT+3ZuiVHluIQLV7lXv50EWLD4F9j5h35vNsn3bu18IE/QYfCe6YEMVOScNdTGa7gPvMRRKz8BVDfNuNG698uIths9V63e2ZS76R/OA3F+y6tdhMK9gfDOzrt5MBFrTJ1l+BnVXlNfQ3AlnwyZvvpRM9DpzOrasQNyO6WEgqoxbLOKNK/aHNm42ARrIXM5qYfCjQizz2YxqVu73H6EO/cIcYliqkEULub7VRuyeCdeq0Nq2a4OQ/MYbs0yUQ6sA+/rmSr83xamJ1RUnmWT2t1RO4LDr8JCzbACNSekBu5cdatnE44PJc3dYbgbYc7pUu+TlTig6c2ReA0i1hYh+2LQcZ1CVcj5s1vQKbJJKnuth2cHAu6uHZDdZRxy46GXJRIEPJ5aulDmGVaYJgvNbOmWepPfaUpj4bRa5GCdsjO7Vv8rSNBWGhJ6MLqOLWDzonhoDYM7VRyZRIZA3L+VZGXXjyvpsXs55NK6VQP3r+fP6n212s6+hy37Frdmh40fCblGsjpTBfaOndqyGcVHwX6oL+Fr+zCbOsMRlqTFP2EguxS8hQNrQ07yJbwtE+t2PMY0TZxtfjC0qrBnyRsdSZr7pu70+oG9a275GvN68an3HCAo5R/yaZ76UTTzehjpmHjLuUvIVnmSvrFk+y39GZwGn+ta6u1BC9z48fw/2c8n0H7YevE5p8CNHYEE1zwylX5D5lqmsn2RIoHfzApvvpfFcbhK19OvJV6B/x7P5lcdEP2Lc6zx+8jYUiblcn4IU5PnW/gYLsSjH1pZ91ULbmilc133D2580kLIHT4pFiJ64DTw1kvX2QIuaX9GS3EZaEO/99O3YnAPNZe7u4qeweYkS5GqU65r6HDMpNDcXpND5vLAI16tQKtHFmAr9IHyXLFjEAtaqZkE9/aVBzDu42XBkEUgSb3wjlEwxfmK/cNqpLh7XUtZJwtAbAtMzrM4io3Se6srD0/qil+hv3/EGDbbdUcPHIRAW+fyI5LKNP14jCCAQoGCSqGSIb3DQEHAaCB/ASB+TCB9jCB8wYLKoZIhvcNAQwKAQKggbwwgbkwHAYKKoZIhvcNAQwBAzAOBAg/hgTTuXX3kQICCAAEgZi5OkXoE7w4i8bzYMLFnviWE2IuUgI5ClXe97JC+sAjnhj1hUUO6BnbGyXJebALdaeBvA+Uyr87OTEWfviCXqdpLvmD6Mn9iGHYV7TTSwz0dGBh4NHVdbzJlcJrR5zYiml5ANiPLirA9tx1heZ5KTCO9QJ6xB5UBUGXzqj/KNgdmawkk2cIc9rOTEzE5CAIUMtfhy0x+QhgYzElMCMGCSqGSIb3DQEJFTEWBBTedIKyjdd5ue1SAunZHLqVTPle5zArMB8wBwYFKw4DAhoEFI2A/db+/cBpwXNZRynjFtVRaQF5BAgVT+T9HolCkQ==`
	bcipher, err := base64.StdEncoding.DecodeString(strcipher)
	if err != nil {
		return
	}
	bp12, err := base64.StdEncoding.DecodeString(strp12)
	if err != nil {
		return
	}
	pkey, _, err := pkcs12.Decode(bp12, "11111111")
	if err != nil {
		return
	}
	key := &sm2.PrivateKey{
		PrivateKey: *pkey.(*ecdsa.PrivateKey),
	}
	deced, err := key.Decrypt(rand.Reader, bcipher, sm2.ASN1DecrypterOpts)
	if err != nil {
		return
	}
	if err != nil {
		return
	}
	println(deced)
}

func main0() {
	path1 := `d:\\1.crt`
	path2 := `d:\\2.crt`
	path3 := `d:\\3.crt`
	file1, err := os.Open(path1)
	if err != nil {
		return
	}
	bytes1, err := io.ReadAll(file1)
	if err != nil {
		return
	}
	cert1, err := smx509.ParseCertificatePEM(bytes1)
	if err != nil {
		return
	}
	file2, err := os.Open(path2)
	if err != nil {
		return
	}
	bytes2, err := io.ReadAll(file2)
	if err != nil {
		return
	}
	cert2, err := smx509.ParseCertificatePEM(bytes2)
	if err != nil {
		return
	}
	file3, err := os.Open(path3)
	if err != nil {
		return
	}
	bytes3, err := io.ReadAll(file3)
	if err != nil {
		return
	}
	cert3, err := smx509.ParseCertificatePEM(bytes3)
	if err != nil {
		return
	}
	certpool := smx509.NewCertPool()
	certpool.AddCert(cert1)
	certpool.AddCert(cert2)
	opts := smx509.VerifyOptions{
		Intermediates: certpool,
	}
	ret, err := cert3.Verify(opts)
	if err != nil {
		return
	}
	fmt.Printf("验证后的证书链包括%d个证书\n", len(ret[0]))
	for i, vericert := range ret[0] {
		fmt.Printf("其中第%d个证书内容如下：\n", i+1)
		fmt.Printf("Subject：%s\n", vericert.Subject.String())
		fmt.Printf("CertSN：%s\n", vericert.SerialNumber.Text(16))
	}
}
