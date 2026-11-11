// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package capsule

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wojciechpolak/dud/client/drop"
)

// normalizeCollection canonicalizes native tar paths and removes local file
// metadata. Private containers retain file bytes and permission bits; native
// attributes and timestamps are not part of the portable collection format.
func normalizeCollection(payload []byte) ([]byte, error) {
	reader := tar.NewReader(bytes.NewReader(payload))
	var output bytes.Buffer
	bounded := &collectionWriter{output: &output}
	writer := tar.NewWriter(bounded)
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		entries++
		if entries > drop.MaximumCollectionEntries {
			return nil, errors.New("collection exceeds its entry bound")
		}
		header.Name = strings.TrimPrefix(header.Name, "./")
		if header.Typeflag == tar.TypeDir {
			header.Name = strings.TrimSuffix(header.Name, "/")
		}
		if err := drop.ValidateArchivePath(header.Name); err != nil {
			return nil, err
		}
		if err := normalizeNativeMetadata(header); err != nil {
			return nil, err
		}
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := io.Copy(writer, reader); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	normalized := output.Bytes()
	if _, err := InspectCollection(normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func normalizeNativeMetadata(header *tar.Header) error {
	for key := range header.PAXRecords {
		if key == "path" {
			header.PAXRecords[key] = header.Name
			continue
		}
		if !nativeMetadataRecord(key) {
			return fmt.Errorf("collection entry %q uses unsupported native extension %q", header.Name, key)
		}
		delete(header.PAXRecords, key)
	}
	*header = tar.Header{
		Name: header.Name, Mode: header.Mode, Size: header.Size,
		Typeflag: header.Typeflag, Linkname: header.Linkname,
		PAXRecords: header.PAXRecords, Format: tar.FormatPAX,
	}
	return nil
}

func nativeMetadataRecord(key string) bool {
	switch key {
	case "atime", "ctime", "mtime", "uid", "gid", "uname", "gname", "LIBARCHIVE.creationtime", "SCHILY.fflags":
		return true
	default:
		return strings.HasPrefix(key, "SCHILY.xattr.") || strings.HasPrefix(key, "LIBARCHIVE.xattr.") || strings.HasPrefix(key, "SCHILY.acl.")
	}
}

type collectionWriter struct{ output *bytes.Buffer }

func (w *collectionWriter) Write(data []byte) (int, error) {
	if w.output.Len()+len(data) > MaxPayloadSize {
		return 0, drop.ErrInputLimit
	}
	return w.output.Write(data)
}
