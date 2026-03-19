package mmtls

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// ParsedField represents a single parsed field in a protocol message.
type ParsedField struct {
	Name     string
	Value    string
	Raw      []byte
	Children []ParsedField
}

// ParsedRecord represents a single parsed MMTLS record.
type ParsedRecord struct {
	Index      int
	RecordType uint8
	Version    uint16
	Length     uint16
	Fields     []ParsedField
	Raw        []byte
}

// ParseRecords parses raw MMTLS binary data into structured records.
func ParseRecords(data []byte) ([]ParsedRecord, error) {
	reader := bytes.NewReader(data)
	var records []ParsedRecord
	idx := 0

	for reader.Len() > 0 {
		rec, err := readRecord(reader)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return records, fmt.Errorf("record #%d: %w", idx, err)
		}

		parsed := ParsedRecord{
			Index:      idx,
			RecordType: rec.recordType,
			Version:    rec.version,
			Length:     rec.length,
			Raw:        rec.data,
		}

		if (rec.recordType == MagicHandshake || rec.recordType == MagicSystem) && len(rec.data) > 5 {
			parsed.Fields = parseHandshakePayload(rec.data)
		} else if rec.recordType == MagicRecord {
			parsed.Fields = parseApplicationData(rec.data)
		} else if rec.recordType == MagicAbort {
			parsed.Fields = parseAbortPayload(rec.data)
		} else if rec.recordType == MagicSystem {
			// System record too short to be a handshake message
			parsed.Fields = encryptedPayload(rec.data)
		} else {
			parsed.Fields = []ParsedField{{
				Name:  "Unknown",
				Value: fmt.Sprintf("(%d bytes)", len(rec.data)),
				Raw:   rec.data,
			}}
		}

		records = append(records, parsed)
		idx++
	}

	return records, nil
}

func parseHandshakePayload(data []byte) []ParsedField {
	if len(data) < 5 {
		return encryptedFallback(data)
	}

	// The payload starts with totalLength(4B BE) + flag(1B)
	// Validate: totalLength should equal len(data)-4 for plaintext messages
	totalLen := binary.BigEndian.Uint32(data[0:4])
	flag := data[4]

	// If totalLength doesn't match actual payload size, this is likely encrypted
	if int(totalLen) != len(data)-4 {
		return encryptedPayload(data)
	}

	switch flag {
	case 0x01:
		return parseClientHelloFields(data)
	case 0x02:
		return parseServerHelloFields(data)
	case 0x08:
		return parsePskExtensionsFields(data)
	case 0x0F:
		return parseSignatureFields(data)
	case 0x04:
		return parseNewSessionTicketFields(data)
	case 0x14:
		return parseServerFinishFields(data)
	default:
		return encryptedPayload(data)
	}
}

func parseClientHelloFields(data []byte) []ParsedField {
	fields := []ParsedField{{Name: "ClientHello"}}
	r := bytes.NewReader(data)

	// totalLength (4B BE)
	var totalLen uint32
	if err := binary.Read(r, binary.BigEndian, &totalLen); err != nil {
		return encryptedFallback(data)
	}
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name: "Total Length", Value: fmt.Sprintf("%d", totalLen),
	})

	// flag (1B)
	flag, _ := r.ReadByte()
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name: "Flag", Value: fmt.Sprintf("0x%02X", flag),
	})

	// protocolVersion (2B LE)
	var protoVer uint16
	if err := binary.Read(r, binary.LittleEndian, &protoVer); err != nil {
		return encryptedFallback(data)
	}
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name: "Protocol Version", Value: fmt.Sprintf("0x%04X (LE)", protoVer),
	})

	// cipherSuitesCount (1B)
	csCount, err := r.ReadByte()
	if err != nil {
		return encryptedFallback(data)
	}

	csField := ParsedField{
		Name:  "Cipher Suites",
		Value: fmt.Sprintf("(%d)", csCount),
	}
	for i := 0; i < int(csCount); i++ {
		var cs uint16
		if err := binary.Read(r, binary.BigEndian, &cs); err != nil {
			break
		}
		csField.Children = append(csField.Children, ParsedField{
			Name:  fmt.Sprintf("[%d]", i),
			Value: fmt.Sprintf("%s (0x%04X)", cipherSuiteName(cs), cs),
		})
	}
	fields[0].Children = append(fields[0].Children, csField)

	// random (32B)
	random := make([]byte, 32)
	if _, err := io.ReadFull(r, random); err != nil {
		return encryptedFallback(data)
	}
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name:  "Client Random",
		Value: fmt.Sprintf("%s (32 bytes)", hex.EncodeToString(random)),
		Raw:   random,
	})

	// timestamp (4B BE)
	var ts uint32
	if err := binary.Read(r, binary.BigEndian, &ts); err != nil {
		return encryptedFallback(data)
	}
	t := time.Unix(int64(ts), 0).UTC()
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name:  "Timestamp",
		Value: fmt.Sprintf("%d (%s)", ts, t.Format("2006-01-02 15:04:05 UTC")),
	})

	// Extensions: extensionsLength(4B BE), extensionCount(1B)
	var extLen uint32
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		return fields
	}
	var extCount byte
	extCount, err = r.ReadByte()
	if err != nil {
		return fields
	}

	extField := ParsedField{
		Name:  "Extensions",
		Value: fmt.Sprintf("(%d), total %d bytes", extCount, extLen),
	}

	for i := 0; i < int(extCount); i++ {
		ext := parseExtension(r)
		if ext != nil {
			extField.Children = append(extField.Children, *ext)
		}
	}

	fields[0].Children = append(fields[0].Children, extField)
	return fields
}

func parseExtension(r *bytes.Reader) *ParsedField {
	// Each extension: length(4B BE), marker(2B BE), ...
	var extItemLen uint32
	if err := binary.Read(r, binary.BigEndian, &extItemLen); err != nil {
		return nil
	}

	var marker uint16
	if err := binary.Read(r, binary.BigEndian, &marker); err != nil {
		return nil
	}

	switch marker {
	case 0x000F:
		return parsePSKExtension(r, extItemLen)
	case 0x0010:
		return parseECDHEExtension(r, extItemLen)
	default:
		// skip remaining bytes
		remaining := int(extItemLen) - 2
		if remaining > 0 {
			buf := make([]byte, remaining)
			r.Read(buf)
			return &ParsedField{
				Name:  fmt.Sprintf("Unknown Extension (0x%04X)", marker),
				Value: fmt.Sprintf("%d bytes", remaining),
				Raw:   buf,
			}
		}
		return &ParsedField{
			Name:  fmt.Sprintf("Unknown Extension (0x%04X)", marker),
			Value: "empty",
		}
	}
}

func parsePSKExtension(r *bytes.Reader, _ uint32) *ParsedField {
	field := &ParsedField{Name: "PSK Extension"}

	ticketCount, err := r.ReadByte()
	if err != nil {
		return field
	}
	field.Value = fmt.Sprintf("(%d ticket(s))", ticketCount)

	for i := 0; i < int(ticketCount); i++ {
		var ticketLen uint32
		if err := binary.Read(r, binary.BigEndian, &ticketLen); err != nil {
			break
		}
		ticketData := make([]byte, ticketLen)
		if _, err := io.ReadFull(r, ticketData); err != nil {
			break
		}

		tf := ParsedField{
			Name:  fmt.Sprintf("[%d] Ticket", i),
			Value: fmt.Sprintf("(%d bytes)", ticketLen),
			Raw:   ticketData,
		}

		// Try to parse inner sessionTicket structure
		if st, err := readSessionTicket(ticketData); err == nil {
			tf.Children = append(tf.Children,
				ParsedField{Name: "Ticket Type", Value: fmt.Sprintf("0x%02X", st.ticketType)},
				ParsedField{Name: "Lifetime", Value: fmt.Sprintf("%d seconds", st.ticketLifeTime)},
				ParsedField{Name: "Ticket Age Add", Value: fmt.Sprintf("(%d bytes)", len(st.ticketAgeAdd)), Raw: st.ticketAgeAdd},
				ParsedField{Name: "Reserved", Value: fmt.Sprintf("0x%08X", st.reversed)},
				ParsedField{Name: "Nonce", Value: fmt.Sprintf("(%d bytes): %s", len(st.nonce), hex.EncodeToString(st.nonce)), Raw: st.nonce},
				ParsedField{Name: "Ticket Data", Value: fmt.Sprintf("(%d bytes): %s", len(st.ticket), truncateHex(st.ticket, 32)), Raw: st.ticket},
			)
		}

		field.Children = append(field.Children, tf)
	}

	return field
}

func parseECDHEExtension(r *bytes.Reader, _ uint32) *ParsedField {
	field := &ParsedField{Name: "ECDHE Extension"}

	keyCount, err := r.ReadByte()
	if err != nil {
		return field
	}
	field.Value = fmt.Sprintf("(%d key(s))", keyCount)

	for i := 0; i < int(keyCount); i++ {
		var keyLen uint32
		if err := binary.Read(r, binary.BigEndian, &keyLen); err != nil {
			break
		}

		var keyFlag uint32
		if err := binary.Read(r, binary.BigEndian, &keyFlag); err != nil {
			break
		}

		var keySize uint16
		if err := binary.Read(r, binary.BigEndian, &keySize); err != nil {
			break
		}

		ecPoint := make([]byte, keySize)
		if _, err := io.ReadFull(r, ecPoint); err != nil {
			break
		}

		pointHex := hex.EncodeToString(ecPoint)
		if len(pointHex) > 16 {
			pointHex = pointHex[:16] + "..."
		}

		field.Children = append(field.Children, ParsedField{
			Name:  fmt.Sprintf("[%d]", i),
			Value: fmt.Sprintf("Flag=%d, EC Point (%d bytes): %s", keyFlag, keySize, pointHex),
			Raw:   ecPoint,
		})
	}

	// Trailing magic bytes (13B): read whatever remains in this extension
	// totalLen includes the marker(2B) we already read, plus keyCount(1B), plus keys, plus magic
	// Just try to read the 13-byte magic trailer
	magic := make([]byte, 13)
	n, _ := io.ReadFull(r, magic)
	if n > 0 {
		field.Children = append(field.Children, ParsedField{
			Name:  "Trailing Magic",
			Value: fmt.Sprintf("%d bytes", n),
			Raw:   magic[:n],
		})
	}

	return field
}

func parseServerHelloFields(data []byte) []ParsedField {
	fields := []ParsedField{{Name: "ServerHello"}}
	r := bytes.NewReader(data)

	// totalLength (4B BE)
	var totalLen uint32
	if err := binary.Read(r, binary.BigEndian, &totalLen); err != nil {
		return encryptedFallback(data)
	}
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name: "Total Length", Value: fmt.Sprintf("%d", totalLen),
	})

	// flag (1B) - should be 0x02
	flag, _ := r.ReadByte()
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name: "Flag", Value: fmt.Sprintf("0x%02X", flag),
	})

	// protocolVersion (2B BE)
	var protoVer uint16
	if err := binary.Read(r, binary.BigEndian, &protoVer); err != nil {
		return encryptedFallback(data)
	}
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name: "Protocol Version", Value: fmt.Sprintf("0x%04X", protoVer),
	})

	// negotiated cipher suite (2B BE)
	var cipherSuite uint16
	if err := binary.Read(r, binary.BigEndian, &cipherSuite); err != nil {
		return encryptedFallback(data)
	}
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name: "Negotiated Cipher Suite", Value: fmt.Sprintf("%s (0x%04X)", cipherSuiteName(cipherSuite), cipherSuite),
	})

	// server random (32B)
	serverRandom := make([]byte, 32)
	if _, err := io.ReadFull(r, serverRandom); err != nil {
		return encryptedFallback(data)
	}
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name:  "Server Random",
		Value: fmt.Sprintf("%s (32 bytes)", hex.EncodeToString(serverRandom)),
		Raw:   serverRandom,
	})

	// extensions package length (4B BE)
	var extPkgLen uint32
	if err := binary.Read(r, binary.BigEndian, &extPkgLen); err != nil {
		return fields
	}

	// extensions count (1B)
	extCount, err := r.ReadByte()
	if err != nil {
		return fields
	}

	extField := ParsedField{
		Name:  "Extensions",
		Value: fmt.Sprintf("(%d), total %d bytes", extCount, extPkgLen),
	}

	for i := 0; i < int(extCount); i++ {
		ext := parseServerHelloExtension(r)
		if ext != nil {
			extField.Children = append(extField.Children, *ext)
		}
	}

	fields[0].Children = append(fields[0].Children, extField)
	return fields
}

func parseServerHelloExtension(r *bytes.Reader) *ParsedField {
	// extension package length (4B BE)
	var extItemLen uint32
	if err := binary.Read(r, binary.BigEndian, &extItemLen); err != nil {
		return nil
	}

	// extension type (2B BE)
	var extType uint16
	if err := binary.Read(r, binary.BigEndian, &extType); err != nil {
		return nil
	}

	field := &ParsedField{
		Name: fmt.Sprintf("Extension (0x%04X)", extType),
	}

	// Try to parse as ECDHE key share (extType=0x0010 typically)
	// Format: arrayIndex(4B) + keyLen(2B) + ecPoint
	var arrayIdx uint32
	if err := binary.Read(r, binary.BigEndian, &arrayIdx); err != nil {
		return field
	}

	var keyLen uint16
	if err := binary.Read(r, binary.BigEndian, &keyLen); err != nil {
		return field
	}

	ecPoint := make([]byte, keyLen)
	if _, err := io.ReadFull(r, ecPoint); err != nil {
		return field
	}

	field.Value = fmt.Sprintf("Key Share (%d bytes)", keyLen)
	field.Children = append(field.Children, ParsedField{
		Name: "Array Index", Value: fmt.Sprintf("%d", arrayIdx),
	})
	field.Children = append(field.Children, ParsedField{
		Name:  "Server EC Public Key",
		Value: fmt.Sprintf("(%d bytes): %s", keyLen, hex.EncodeToString(ecPoint)),
		Raw:   ecPoint,
	})

	// Read remaining bytes in this extension if any
	consumed := 2 + 4 + 2 + int(keyLen) // extType + arrayIdx + keyLen + ecPoint
	remaining := int(extItemLen) - consumed
	if remaining > 0 {
		extra := make([]byte, remaining)
		r.Read(extra)
		field.Children = append(field.Children, ParsedField{
			Name:  "Extra Data",
			Value: fmt.Sprintf("(%d bytes): %s", remaining, hex.EncodeToString(extra)),
			Raw:   extra,
		})
	}

	return field
}

func parseSignatureFields(data []byte) []ParsedField {
	sig, err := readSignature(data)
	if err != nil {
		return encryptedFallback(data)
	}

	return []ParsedField{{
		Name: "Signature",
		Children: []ParsedField{
			{Name: "Type", Value: fmt.Sprintf("0x%02X", sig.Type)},
			{Name: "ECDSA Signature", Value: fmt.Sprintf("(%d bytes): %s", len(sig.EcdsaSignature), truncateHex(sig.EcdsaSignature, 64)), Raw: sig.EcdsaSignature},
		},
	}}
}

func parseNewSessionTicketFields(data []byte) []ParsedField {
	nst, err := readNewSessionTicket(data)
	if err != nil {
		return encryptedFallback(data)
	}

	field := ParsedField{
		Name: "NewSessionTicket",
		Children: []ParsedField{
			{Name: "Reversed", Value: fmt.Sprintf("0x%02X", nst.reversed)},
			{Name: "Ticket Count", Value: fmt.Sprintf("%d", nst.count)},
		},
	}

	for i, t := range nst.tickets {
		nonceHex := hex.EncodeToString(t.nonce)

		tf := ParsedField{
			Name: fmt.Sprintf("[%d] Ticket", i),
			Children: []ParsedField{
				{Name: "Type", Value: fmt.Sprintf("0x%02X", t.ticketType)},
				{Name: "Lifetime", Value: fmt.Sprintf("%d seconds", t.ticketLifeTime)},
				{Name: "Ticket Age Add", Value: fmt.Sprintf("(%d bytes)", len(t.ticketAgeAdd)), Raw: t.ticketAgeAdd},
				{Name: "Reserved", Value: fmt.Sprintf("0x%08X", t.reversed)},
				{Name: "Nonce", Value: fmt.Sprintf("(%d bytes): %s", len(t.nonce), nonceHex), Raw: t.nonce},
				{Name: "Ticket Data", Value: fmt.Sprintf("(%d bytes): %s", len(t.ticket), truncateHex(t.ticket, 64)), Raw: t.ticket},
			},
		}
		field.Children = append(field.Children, tf)
	}

	return []ParsedField{field}
}

func parseServerFinishFields(data []byte) []ParsedField {
	sf, err := ReadServerFinish(data)
	if err != nil {
		return encryptedFallback(data)
	}

	return []ParsedField{{
		Name: "ServerFinish",
		Children: []ParsedField{
			{Name: "Flag", Value: fmt.Sprintf("0x%02X", sf.reversed)},
			{Name: "Verify Data", Value: fmt.Sprintf("(%d bytes): %s", len(sf.data), truncateHex(sf.data, 64)), Raw: sf.data},
		},
	}}
}

// parsePskExtensionsFields parses the 0-RTT PSK extensions record (flag=0x08).
// Format from mmtls_short.go packHttp:
//
//	totalLen(4B) + flag(1B=0x08) + extLen(4B) + extFlag(1B) + timestampLen(4B) +
//	timestampMarker(2B=0x0012) + timestamp(4B)
func parsePskExtensionsFields(data []byte) []ParsedField {
	fields := []ParsedField{{Name: "PSK Extensions (0-RTT)"}}
	r := bytes.NewReader(data)

	var totalLen uint32
	binary.Read(r, binary.BigEndian, &totalLen)
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name: "Total Length", Value: fmt.Sprintf("%d", totalLen),
	})

	flag, _ := r.ReadByte()
	fields[0].Children = append(fields[0].Children, ParsedField{
		Name: "Flag", Value: fmt.Sprintf("0x%02X", flag),
	})

	// Parse remaining bytes as structured fields
	remaining := data[5:]
	if len(remaining) >= 15 {
		// extLen(4B) + extFlag(1B) + innerLen(4B) + marker(2B) + timestamp(4B)
		var extLen uint32
		var extFlag byte
		var innerLen uint32
		var marker uint16
		var timestamp uint32

		rr := bytes.NewReader(remaining)
		binary.Read(rr, binary.BigEndian, &extLen)
		extFlag, _ = rr.ReadByte()
		binary.Read(rr, binary.BigEndian, &innerLen)
		binary.Read(rr, binary.BigEndian, &marker)
		binary.Read(rr, binary.BigEndian, &timestamp)

		fields[0].Children = append(fields[0].Children,
			ParsedField{Name: "Extension Length", Value: fmt.Sprintf("%d", extLen)},
			ParsedField{Name: "Extension Flag", Value: fmt.Sprintf("0x%02X", extFlag)},
			ParsedField{Name: "Inner Length", Value: fmt.Sprintf("%d", innerLen)},
			ParsedField{Name: "Marker", Value: fmt.Sprintf("0x%04X", marker)},
		)

		if timestamp > 0 {
			t := time.Unix(int64(timestamp), 0).UTC()
			fields[0].Children = append(fields[0].Children, ParsedField{
				Name:  "Timestamp",
				Value: fmt.Sprintf("%d (%s)", timestamp, t.Format("2006-01-02 15:04:05 UTC")),
			})
		} else {
			fields[0].Children = append(fields[0].Children, ParsedField{
				Name: "Timestamp", Value: "0 (not set)",
			})
		}
	} else {
		fields[0].Children = append(fields[0].Children, ParsedField{
			Name:  "Raw Data",
			Value: truncateHex(remaining, 64),
			Raw:   remaining,
		})
	}

	return fields
}

// parseAbortPayload parses Abort (0x15) records.
// In 0-RTT PSK, the abort carries ClientFinished (encrypted).
// Plaintext abort format: totalLen(4B) + flag(2B) + data(1B).
func parseAbortPayload(data []byte) []ParsedField {
	if len(data) >= 5 {
		totalLen := binary.BigEndian.Uint32(data[0:4])
		if int(totalLen) == len(data)-4 {
			// Plaintext abort
			field := ParsedField{Name: "Abort (plaintext)"}
			field.Children = append(field.Children,
				ParsedField{Name: "Total Length", Value: fmt.Sprintf("%d", totalLen)},
				ParsedField{Name: "Data", Value: truncateHex(data[4:], 32), Raw: data[4:]},
			)
			return []ParsedField{field}
		}
	}

	// Encrypted abort (e.g. 0-RTT ClientFinished)
	return []ParsedField{{
		Name:  "Abort (encrypted)",
		Value: fmt.Sprintf("(%d bytes)", len(data)),
		Raw:   data,
		Children: []ParsedField{
			{Name: "Data", Value: truncateHex(data, 80)},
		},
	}}
}

func parseApplicationData(data []byte) []ParsedField {
	field := ParsedField{
		Name:  "Application Data",
		Value: fmt.Sprintf("(%d bytes)", len(data)),
		Raw:   data,
	}

	// Try to parse inner dataRecord header: length(4B) + flag1(2B) + flag2(2B) + dataType(4B) + cmdId(4B) + payload
	if len(data) >= 16 {
		r := bytes.NewReader(data)
		var innerLen uint32
		var flag1, flag2 uint16
		var dataType, cmdId uint32
		if err := binary.Read(r, binary.BigEndian, &innerLen); err == nil {
			binary.Read(r, binary.BigEndian, &flag1)
			binary.Read(r, binary.BigEndian, &flag2)
			binary.Read(r, binary.BigEndian, &dataType)
			binary.Read(r, binary.BigEndian, &cmdId)

			if innerLen == uint32(len(data)) {
				field.Children = append(field.Children,
					ParsedField{Name: "Inner Length", Value: fmt.Sprintf("%d", innerLen)},
					ParsedField{Name: "Flag1", Value: fmt.Sprintf("0x%04X", flag1)},
					ParsedField{Name: "Flag2", Value: fmt.Sprintf("0x%04X", flag2)},
					ParsedField{Name: "Data Type", Value: fmt.Sprintf("0x%08X", dataType)},
					ParsedField{Name: "Cmd ID", Value: fmt.Sprintf("0x%08X (%d)", cmdId, cmdId)},
				)
				if len(data) > 16 {
					payload := data[16:]
					field.Children = append(field.Children, ParsedField{
						Name:  "Payload",
						Value: fmt.Sprintf("(%d bytes): %s", len(payload), truncateHex(payload, 64)),
						Raw:   payload,
					})
				}
			}
		}
	}

	return []ParsedField{field}
}

func truncateHex(data []byte, maxHexChars int) string {
	s := hex.EncodeToString(data)
	if len(s) > maxHexChars {
		return s[:maxHexChars] + "..."
	}
	return s
}

func encryptedPayload(data []byte) []ParsedField {
	return []ParsedField{{
		Name:  "Encrypted Payload",
		Value: fmt.Sprintf("(%d bytes)", len(data)),
		Raw:   data,
		Children: []ParsedField{
			{Name: "Data", Value: truncateHex(data, 80)},
		},
	}}
}

func encryptedFallback(data []byte) []ParsedField {
	return []ParsedField{{
		Name:  "Encrypted Payload",
		Value: fmt.Sprintf("(%d bytes): %s", len(data), truncateHex(data, 64)),
		Raw:   data,
	}}
}

func cipherSuiteName(cs uint16) string {
	switch cs {
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return "TLS_PSK_WITH_AES_128_GCM_SHA256"
	default:
		return "Unknown"
	}
}

// RecordTypeName returns a human-readable name for a record type.
func RecordTypeName(rt uint8) string {
	switch rt {
	case MagicAbort:
		return "Abort"
	case MagicHandshake:
		return "Handshake"
	case MagicRecord:
		return "Data"
	case MagicSystem:
		return "System"
	default:
		return "Unknown"
	}
}

// FormatRecords formats parsed records as a Wireshark-style tree string.
func FormatRecords(records []ParsedRecord) string {
	var sb strings.Builder
	for i, rec := range records {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("Record #%d [%s] (%d bytes)\n",
			rec.Index, RecordTypeName(rec.RecordType), rec.Length+5))
		sb.WriteString(fmt.Sprintf("  Type: %s (0x%02X)\n", RecordTypeName(rec.RecordType), rec.RecordType))
		sb.WriteString(fmt.Sprintf("  Version: 0x%04X\n", rec.Version))
		sb.WriteString(fmt.Sprintf("  Length: %d\n", rec.Length))

		for _, f := range rec.Fields {
			formatField(&sb, f, 2)
		}
	}
	return sb.String()
}

func formatField(sb *strings.Builder, f ParsedField, indent int) {
	prefix := strings.Repeat(" ", indent)
	if f.Value != "" {
		sb.WriteString(fmt.Sprintf("%s%s: %s\n", prefix, f.Name, f.Value))
	} else {
		sb.WriteString(fmt.Sprintf("%s%s\n", prefix, f.Name))
	}
	for _, child := range f.Children {
		formatField(sb, child, indent+2)
	}
}

// CleanHexString normalizes a hex string by removing common formatting characters.
func CleanHexString(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, "0X", "")
	return s
}
