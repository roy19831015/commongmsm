//go:build !amd64 || generic
// +build !amd64 generic

package zuc

func block256(m *ZUC256Mac, p []byte) {
	block256Generic(m, p)
}
