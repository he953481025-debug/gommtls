package mmtls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestParseClientHelloECDHE(t *testing.T) {
	pubKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ch := newECDHEHello(&pubKey.PublicKey, &verKey.PublicKey)
	payload := ch.serialize()

	// Wrap in a handshake record
	rec := createHandshakeRecord(payload)
	data := rec.serialize()

	records, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("ParseRecords failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	r := records[0]
	if r.RecordType != MagicHandshake {
		t.Errorf("expected record type 0x%02X, got 0x%02X", MagicHandshake, r.RecordType)
	}
	if r.Version != ProtocolVersion {
		t.Errorf("expected version 0x%04X, got 0x%04X", ProtocolVersion, r.Version)
	}

	// Should have a ClientHello field
	if len(r.Fields) == 0 {
		t.Fatal("no fields parsed")
	}
	if r.Fields[0].Name != "ClientHello" {
		t.Errorf("expected ClientHello field, got %s", r.Fields[0].Name)
	}

	// Check children
	children := r.Fields[0].Children
	found := map[string]bool{}
	for _, c := range children {
		found[c.Name] = true
		t.Logf("  %s: %s", c.Name, c.Value)
		for _, gc := range c.Children {
			t.Logf("    %s: %s", gc.Name, gc.Value)
		}
	}

	for _, name := range []string{"Flag", "Protocol Version", "Cipher Suites", "Client Random", "Timestamp", "Extensions"} {
		if !found[name] {
			t.Errorf("missing field: %s", name)
		}
	}

	// Print formatted output
	t.Log("\n" + FormatRecords(records))
}

func TestParseClientHelloPSKZero(t *testing.T) {
	// Create a dummy session ticket for 0-RTT PSK
	ticket := &sessionTicket{
		ticketType:     0x01,
		ticketLifeTime: 86400,
		ticketAgeAdd:   []byte{},
		reversed:       0x48,
		nonce:          make([]byte, 12),
		ticket:         []byte("test-ticket-data-for-psk"),
	}

	ch := newPskZeroHello(ticket)
	payload := ch.serialize()

	rec := createHandshakeRecord(payload)
	data := rec.serialize()

	records, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("ParseRecords failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	r := records[0]
	if r.Fields[0].Name != "ClientHello" {
		t.Errorf("expected ClientHello, got %s", r.Fields[0].Name)
	}

	// Should have PSK cipher suite
	children := r.Fields[0].Children
	for _, c := range children {
		if c.Name == "Cipher Suites" {
			if len(c.Children) != 1 {
				t.Errorf("expected 1 cipher suite for PSK-only, got %d", len(c.Children))
			}
		}
	}

	t.Log("\n" + FormatRecords(records))
}

func TestParseMultipleRecords(t *testing.T) {
	// Create an ECDHE ClientHello
	pubKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	verKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	ch := newECDHEHello(&pubKey.PublicKey, &verKey.PublicKey)

	rec1 := createHandshakeRecord(ch.serialize())
	rec2 := createAbortRecord([]byte{0x00})
	rec3 := createDataRecord(0x01, 0x01, []byte("hello"))

	// Concatenate all records
	data := append(rec1.serialize(), rec2.serialize()...)
	data = append(data, rec3.serialize()...)

	records, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("ParseRecords failed: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}

	if records[0].RecordType != MagicHandshake {
		t.Errorf("record 0: expected Handshake, got 0x%02X", records[0].RecordType)
	}
	if records[1].RecordType != MagicAbort {
		t.Errorf("record 1: expected Abort, got 0x%02X", records[1].RecordType)
	}
	if records[2].RecordType != MagicRecord {
		t.Errorf("record 2: expected Data, got 0x%02X", records[2].RecordType)
	}

	t.Log("\n" + FormatRecords(records))
}

func TestHexCleaning(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"16 f1 04 00 05", "16f1040005"},
		{"16:f1:04:00:05", "16f1040005"},
		{"0x160xf10x04", "16f104"},
		{"16F104\n0005", "16F1040005"},
		{"  16 f1 04  ", "16f104"},
		{"0X160XF1", "16F1"},
	}

	for _, tt := range tests {
		result := CleanHexString(tt.input)
		if result != tt.expected {
			t.Errorf("CleanHexString(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseNewSessionTicket(t *testing.T) {
	// Build a NewSessionTicket and parse it
	nst := &newSessionTicket{
		reversed: 0x04,
		count:    1,
		tickets: []sessionTicket{
			{
				ticketType:     0x01,
				ticketLifeTime: 3600,
				ticketAgeAdd:   []byte{0x01, 0x02},
				reversed:       0x48,
				nonce:          make([]byte, 12),
				ticket:         []byte("ticket-data"),
			},
		},
	}

	payload, err := nst.serialize()
	if err != nil {
		t.Fatal(err)
	}

	rec := createHandshakeRecord(payload)
	data := rec.serialize()

	records, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("ParseRecords failed: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	if records[0].Fields[0].Name != "NewSessionTicket" {
		t.Errorf("expected NewSessionTicket, got %s", records[0].Fields[0].Name)
	}

	t.Log("\n" + FormatRecords(records))
}

func TestParseSignature(t *testing.T) {
	// Build a signature record manually:
	// totalLength(4B) + flag(1B=0x0F) + sigLength(2B) + sigData
	sigData := []byte{0x30, 0x44, 0x02, 0x20} // partial DER prefix
	sigData = append(sigData, make([]byte, 60)...)

	buf := make([]byte, 0, 128)
	// totalLength = 1 + 2 + len(sigData)
	totalLen := uint32(1 + 2 + len(sigData))
	buf = append(buf, byte(totalLen>>24), byte(totalLen>>16), byte(totalLen>>8), byte(totalLen))
	buf = append(buf, 0x0F) // flag
	sigLen := uint16(len(sigData))
	buf = append(buf, byte(sigLen>>8), byte(sigLen))
	buf = append(buf, sigData...)

	rec := createHandshakeRecord(buf)
	data := rec.serialize()

	records, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("ParseRecords failed: %v", err)
	}

	if records[0].Fields[0].Name != "Signature" {
		t.Errorf("expected Signature, got %s", records[0].Fields[0].Name)
	}

	t.Log("\n" + FormatRecords(records))
}

func TestParseRawHex(t *testing.T) {
	// Test a complete round-trip: serialize → hex → clean → decode → parse
	pubKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	verKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	ch := newECDHEHello(&pubKey.PublicKey, &verKey.PublicKey)
	rec := createHandshakeRecord(ch.serialize())
	raw := rec.serialize()

	// Convert to spaced hex
	hexStr := hex.EncodeToString(raw)
	spaced := ""
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			spaced += " "
		}
		spaced += hexStr[i : i+2]
	}

	// Clean and decode
	cleaned := CleanHexString(spaced)
	data, err := hex.DecodeString(cleaned)
	if err != nil {
		t.Fatal(err)
	}

	records, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("ParseRecords failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatal("expected 1 record")
	}
	if records[0].Fields[0].Name != "ClientHello" {
		t.Errorf("expected ClientHello, got %s", records[0].Fields[0].Name)
	}
}

func TestParsePskZeroFlow(t *testing.T) {
	// Simulate a 0-RTT PSK short-link client request:
	//   Record #0: System (0x19) — ClientHello with PSK ticket (plaintext)
	//   Record #1: System (0x19) — Encrypted Extensions
	//   Record #2: Data   (0x17) — Encrypted Early Data
	//   Record #3: Abort  (0x15) — Encrypted ClientFinished

	var allData []byte

	// --- Record #0: System with PSK ClientHello (plaintext) ---
	ticket := &sessionTicket{
		ticketType:     0x01,
		ticketLifeTime: 86400,
		ticketAgeAdd:   []byte{},
		reversed:       0x48,
		nonce:          []byte{0x71, 0xae, 0xce, 0xff, 0xd8, 0x3f, 0x29, 0x48, 0x01, 0x02, 0x03, 0x04},
		ticket:         []byte("psk-access-ticket-data-here"),
	}
	ch := newPskZeroHello(ticket)
	helloPart := ch.serialize()
	rec0 := createSystemRecord(helloPart)
	allData = append(allData, rec0.serialize()...)

	// --- Record #1: System with encrypted Extensions ---
	encExt := make([]byte, 52)
	copy(encExt, []byte{0x47, 0x4c, 0x34, 0x03, 0x71, 0x9e, 0xaa, 0xbb})
	rec1 := createSystemRecord(encExt)
	allData = append(allData, rec1.serialize()...)

	// --- Record #2: Data with encrypted early data ---
	encData := make([]byte, 96)
	copy(encData, []byte{0x98, 0xcd, 0x6e, 0xa0, 0x7c, 0x6b, 0x11, 0x22})
	rec2 := createRawDataRecord(encData)
	allData = append(allData, rec2.serialize()...)

	// --- Record #3: Abort with encrypted ClientFinished ---
	encAbort := make([]byte, 40)
	copy(encAbort, []byte{0x8a, 0xd1, 0xc3, 0x42, 0x9a, 0x30, 0x55, 0x66})
	rec3 := createAbortRecord(encAbort)
	allData = append(allData, rec3.serialize()...)

	// Parse
	records, err := ParseRecords(allData)
	if err != nil {
		t.Fatalf("ParseRecords failed: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	// Record 0: System with ClientHello
	if records[0].RecordType != MagicSystem {
		t.Errorf("record 0: expected System (0x19), got 0x%02X", records[0].RecordType)
	}
	if records[0].Fields[0].Name != "ClientHello" {
		t.Errorf("record 0: expected ClientHello, got %s", records[0].Fields[0].Name)
	}

	// Record 1: System encrypted
	if records[1].RecordType != MagicSystem {
		t.Errorf("record 1: expected System (0x19), got 0x%02X", records[1].RecordType)
	}
	if records[1].Fields[0].Name != "Encrypted Payload" {
		t.Errorf("record 1: expected Encrypted Payload, got %s", records[1].Fields[0].Name)
	}

	// Record 2: Data encrypted
	if records[2].RecordType != MagicRecord {
		t.Errorf("record 2: expected Data (0x17), got 0x%02X", records[2].RecordType)
	}

	// Record 3: Abort encrypted
	if records[3].RecordType != MagicAbort {
		t.Errorf("record 3: expected Abort (0x15), got 0x%02X", records[3].RecordType)
	}
	if records[3].Fields[0].Name != "Abort (encrypted)" {
		t.Errorf("record 3: expected Abort (encrypted), got %s", records[3].Fields[0].Name)
	}

	t.Log("\n" + FormatRecords(records))
}

func TestParseServerResponse(t *testing.T) {
	// Simulate a server response: ServerHello (plaintext) + 3 encrypted handshake records
	// This matches the real flow:
	//   Record #0: ServerHello (plaintext)
	//   Record #1: Encrypted Signature (server certificate)
	//   Record #2: Encrypted NewSessionTicket
	//   Record #3: Encrypted ServerFinish

	var allData []byte

	// --- Record #0: ServerHello (plaintext) ---
	shPayload := make([]byte, 0, 128)
	// totalLength placeholder (4B)
	shPayload = append(shPayload, 0, 0, 0, 0)
	// flag=0x02 (ServerHello)
	shPayload = append(shPayload, 0x02)
	// protocolVersion (2B BE) = 0xF104
	shPayload = append(shPayload, 0xF1, 0x04)
	// negotiated cipher suite (2B BE) = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	shPayload = append(shPayload, 0xC0, 0x2B)
	// server random (32B)
	serverRandom := []byte{
		0x2b, 0xa6, 0x88, 0x7e, 0x61, 0x5e, 0x27, 0xeb,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	}
	shPayload = append(shPayload, serverRandom...)
	// extensions: pkgLen(4B) + count(1B) + extPkgLen(4B) + extType(2B) + arrayIdx(4B) + keyLen(2B) + ecPoint(65B)
	ecPoint := make([]byte, 65)
	ecPoint[0] = 0x04                                                   // uncompressed
	copy(ecPoint[1:], []byte{0xfa, 0xe3, 0xdc, 0x03, 0x4a, 0x21, 0xd9}) // sample bytes
	extInnerLen := uint32(2 + 4 + 2 + 65)                               // extType + arrayIdx + keyLen + ecPoint
	extPkgLen := uint32(4 + extInnerLen)                                // extPkgLen field + inner
	// extensions package length
	shPayload = append(shPayload,
		byte(extPkgLen>>24), byte(extPkgLen>>16), byte(extPkgLen>>8), byte(extPkgLen))
	// extensions count = 1
	shPayload = append(shPayload, 0x01)
	// extension package length
	shPayload = append(shPayload,
		byte(extInnerLen>>24), byte(extInnerLen>>16), byte(extInnerLen>>8), byte(extInnerLen))
	// extension type = 0x0010 (ECDHE)
	shPayload = append(shPayload, 0x00, 0x10)
	// array index
	shPayload = append(shPayload, 0x00, 0x00, 0x00, 0x00)
	// key length
	shPayload = append(shPayload, 0x00, 0x41) // 65
	// ec point
	shPayload = append(shPayload, ecPoint...)
	// fix totalLength
	binary.BigEndian.PutUint32(shPayload[0:4], uint32(len(shPayload)-4))

	rec0 := createHandshakeRecord(shPayload)
	allData = append(allData, rec0.serialize()...)

	// --- Record #1: Encrypted Signature (random ciphertext) ---
	encSig := make([]byte, 80)
	copy(encSig, []byte{0xb8, 0x79, 0xa1, 0x60, 0xbe, 0x6c, 0x3f, 0x22})
	rec1 := createHandshakeRecord(encSig)
	allData = append(allData, rec1.serialize()...)

	// --- Record #2: Encrypted NewSessionTicket ---
	encTicket := make([]byte, 120)
	copy(encTicket, []byte{0x1a, 0x6d, 0xc9, 0xdd, 0x6e, 0xf1, 0x88, 0x44})
	rec2 := createHandshakeRecord(encTicket)
	allData = append(allData, rec2.serialize()...)

	// --- Record #3: Encrypted ServerFinish ---
	encFinish := make([]byte, 48)
	copy(encFinish, []byte{0xb8, 0x79, 0xa1, 0x60, 0xbe, 0x6c, 0x55, 0x99})
	rec3 := createHandshakeRecord(encFinish)
	allData = append(allData, rec3.serialize()...)

	// Parse all
	records, err := ParseRecords(allData)
	if err != nil {
		t.Fatalf("ParseRecords failed: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	// Record 0: should be ServerHello
	if records[0].Fields[0].Name != "ServerHello" {
		t.Errorf("record 0: expected ServerHello, got %s", records[0].Fields[0].Name)
	}

	// Records 1-3: should all be Encrypted Payload
	for i := 1; i <= 3; i++ {
		if records[i].Fields[0].Name != "Encrypted Payload" {
			t.Errorf("record %d: expected Encrypted Payload, got %s", i, records[i].Fields[0].Name)
		}
	}

	t.Log("\n" + FormatRecords(records))
}
