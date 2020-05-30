package algorithms

type Algorithm interface {
	Name() string
	Sign()
	Verify(message []byte, signature []byte, key interface{}) error
}

func Find(name string) Algorithm {
	switch name {
	case "rsa-sha1":
		return RSASha1
	case "rsa-sha256":
		return RSASha256
	default:
		return nil
	}
}
