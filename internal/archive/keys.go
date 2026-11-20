package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// maxSegmentLen bounds the reporter and report ID parts of an object
	// name; the identity hash, not these parts, keeps reports apart.
	maxSegmentLen = 64
	// maxPrefixLen keeps every key under S3's 1024-byte limit: the rest of a
	// key is under 200 bytes.
	maxPrefixLen = 512
	// maxMetadataLen bounds each user metadata value. S3 allows 2 KB of user
	// metadata per object, names included, and each object carries four.
	maxMetadataLen = 256
)

const jsonContentType = "application/json"

// rawExtensions are the attachment suffixes kept on the raw object, longest
// first so ".xml.gz" wins over ".gz".
var rawExtensions = []string{".xml.gz", ".json.gz", ".xml", ".json", ".zip", ".gz"}

// objectKeys returns where r is stored. prefix must be normalized.
func objectKeys(prefix string, r Report) Keys {
	day := r.Begin.UTC()
	partition := fmt.Sprintf("%s/year=%04d/month=%02d/day=%02d/", r.Kind, day.Year(), int(day.Month()), day.Day())
	name := objectName(r)
	return Keys{
		Raw:    prefix + "raw/" + partition + name + ".raw" + rawExtension(r.RawFilename),
		Parsed: prefix + "parsed/" + partition + name + ".json",
	}
}

// objectName is the file name both objects of a report share, without
// extension: the reporter and report ID for people browsing the bucket, then
// the identity hash, which keeps reports apart that sanitize to the same text.
func objectName(r Report) string {
	// The name starts with the reporter, and Athena, Hive and Spark skip
	// files whose names start with '.' or '_'.
	org := segment(r.OrgName)
	switch {
	case org == "":
		org = "-"
	case org[0] == '.' || org[0] == '_':
		org = "-" + org[1:]
	}
	return org + "_" + segment(r.ReportID) + "_" + identityHash(r)
}

// segment keeps the characters of s that are safe in any S3 key and URL,
// replaces each other character with '-', and cuts the result at
// maxSegmentLen.
func segment(s string) string {
	var b strings.Builder
	for _, c := range s {
		if b.Len() == maxSegmentLen {
			break
		}
		if isSegmentChar(c) {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func isSegmentChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == '-'
}

// identityHash is the first 16 hex digits of the SHA-256 of the JSON array
// [kind, org_name, report_id, lowercase(domain)], encoded compactly and
// without HTML escaping, so another tool can recompute it from the report.
func identityHash(r Report) string {
	identity, err := encodeJSON([]string{string(r.Kind), r.OrgName, r.ReportID, strings.ToLower(r.Domain)})
	if err != nil {
		panic(fmt.Sprintf("encode report identity: %v", err)) // a []string always encodes
	}
	sum := sha256.Sum256(bytes.TrimSuffix(identity, []byte("\n")))
	return hex.EncodeToString(sum[:8])
}

// encodeJSON encodes v compactly, ending in a newline so stored objects
// concatenate into JSON Lines. HTML escaping is off: "AT&T" stays readable.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// rawExtension is the attachment's own extension when it is a report format,
// else ".bin".
func rawExtension(filename string) string {
	lower := strings.ToLower(filename)
	for _, ext := range rawExtensions {
		if strings.HasSuffix(lower, ext) {
			return ext
		}
	}
	return ".bin"
}

// rawContentType is the declared media type when it parses, else one sniffed
// from the bytes. Gzip is stored as a type, never as Content-Encoding, which
// would have HTTP clients decompress the original on download.
func rawContentType(declared string, data []byte) string {
	if mediaType, params, err := mime.ParseMediaType(declared); err == nil {
		if formatted := mime.FormatMediaType(mediaType, params); formatted != "" {
			return formatted
		}
	}
	return http.DetectContentType(data)
}

// metadata is the user metadata both objects of r carry.
func metadata(r Report) map[string]string {
	return map[string]string{
		"kind":      metadataValue(string(r.Kind)),
		"org-name":  metadataValue(r.OrgName),
		"report-id": metadataValue(r.ReportID),
		"domain":    metadataValue(r.Domain),
	}
}

// metadataValue percent-encodes every byte of s outside the RFC 3986
// unreserved set, since S3 metadata is ASCII, and cuts the result at
// maxMetadataLen bytes without splitting a character.
func metadataValue(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); {
		_, width := utf8.DecodeRuneInString(s[i:])
		if width == 1 && isUnreserved(s[i]) {
			if b.Len()+1 > maxMetadataLen {
				break
			}
			b.WriteByte(s[i])
			i++
			continue
		}
		if b.Len()+3*width > maxMetadataLen {
			break
		}
		for _, c := range []byte(s[i : i+width]) {
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
		i += width
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// normalizePrefix drops empty path elements, so the prefix has no leading
// slash and, unless empty, exactly one trailing slash.
func normalizePrefix(prefix string) string {
	parts := strings.FieldsFunc(prefix, func(c rune) bool { return c == '/' })
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "/") + "/"
}

// validatePrefix checks a normalized prefix.
func validatePrefix(prefix string) error {
	if len(prefix) > maxPrefixLen {
		return fmt.Errorf("archive prefix is %d bytes, over the %d-byte limit", len(prefix), maxPrefixLen)
	}
	if !utf8.ValidString(prefix) {
		return errors.New("archive prefix is not valid UTF-8")
	}
	if strings.IndexFunc(prefix, unicode.IsControl) >= 0 {
		return fmt.Errorf("archive prefix %q contains a control character", prefix)
	}
	// S3 has no directories, but MinIO and file-backed servers reject
	// "." and ".." elements, and other tools resolve them.
	for _, part := range strings.Split(strings.TrimSuffix(prefix, "/"), "/") {
		if part == "." || part == ".." {
			return fmt.Errorf("archive prefix %q contains a %q element", prefix, part)
		}
	}
	return nil
}
