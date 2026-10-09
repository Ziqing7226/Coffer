package crypto

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChunkSize is the plaintext chunk size for object files: 64 MiB
// (docs/format-spec.md §5). Each chunk is sealed independently with a fresh
// nonce, so damage is localized and files stream without holding the whole
// ciphertext in memory.
const ChunkSize = 64 << 20

// WriteChunked encrypts plaintext into w as a sequence of chunks, each
// formatted as nonce || ciphertext. specific returns the role-specific AAD
// id for chunk k.
func WriteChunked(w io.Writer, plaintext io.Reader, dek []byte, specific func(chunk int) string) error {
	return writeChunked(w, plaintext, dek, specific, nil)
}

// writeChunked seals every chunk under a fresh random nonce; nonces, when
// non-nil, supplies a deterministic nonce per chunk index — the format
// test vectors pin exact bytes this way.
func writeChunked(w io.Writer, plaintext io.Reader, dek []byte, specific func(chunk int) string, nonces map[int][]byte) error {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return err
	}
	buf := make([]byte, ChunkSize)
	for k := 0; ; k++ {
		n, rerr := io.ReadFull(plaintext, buf)
		if n > 0 {
			nonce := make([]byte, NonceSize)
			if fixed, ok := nonces[k]; ok {
				if len(fixed) != NonceSize {
					return fmt.Errorf("object chunk %d: seal nonce must be %d bytes", k, NonceSize)
				}
				copy(nonce, fixed)
			} else if _, err := rand.Read(nonce); err != nil {
				return err
			}
			if _, err := w.Write(nonce); err != nil {
				return err
			}
			if _, err := w.Write(aead.Seal(nil, nonce, buf[:n], AAD("obj-chunk", specific(k)))); err != nil {
				return err
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// chunkReader decrypts a chunked object file on the fly.
type chunkReader struct {
	r        *bufio.Reader
	aead     cipher.AEAD
	specific func(chunk int) string
	total    int   // total number of chunks
	next     int   // index of the next chunk to decrypt
	size     int64 // total plaintext size
	buf      []byte
	err      error
}

// ReadChunked returns a reader that decrypts a chunked object file of the
// given plaintext size.
func ReadChunked(r io.Reader, plaintextSize int64, dek []byte, specific func(chunk int) string) (io.Reader, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, err
	}
	total := 0
	if plaintextSize > 0 {
		total = int((plaintextSize + ChunkSize - 1) / ChunkSize)
	}
	return &chunkReader{
		r:        bufio.NewReaderSize(r, 1<<16),
		aead:     aead,
		specific: specific,
		total:    total,
		size:     plaintextSize,
	}, nil
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if c.next >= c.total {
			c.err = io.EOF
			return 0, io.EOF
		}
		k := c.next
		plain := c.size - int64(k)*ChunkSize
		if plain > ChunkSize {
			plain = ChunkSize
		}
		nonce := make([]byte, NonceSize)
		if _, err := io.ReadFull(c.r, nonce); err != nil {
			c.err = fmt.Errorf("object chunk %d: reading nonce: %w", k, err)
			return 0, c.err
		}
		ct := make([]byte, plain+TagSize)
		if _, err := io.ReadFull(c.r, ct); err != nil {
			c.err = fmt.Errorf("object chunk %d: reading ciphertext: %w", k, err)
			return 0, c.err
		}
		pt, err := c.aead.Open(nil, nonce, ct, AAD("obj-chunk", c.specific(k)))
		if err != nil {
			c.err = fmt.Errorf("object chunk %d: %w", k, ErrAuth)
			return 0, c.err
		}
		c.buf = pt
		c.next++
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}
