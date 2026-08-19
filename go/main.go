package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
)

type DNSHeader struct {
	ID             uint16
	Flags          uint16
	NumQuestions   uint16
	NumAnswers     uint16
	NumAuthorities uint16
	NumAdditionals uint16
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func headerToBytes(header DNSHeader) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], header.ID)
	binary.BigEndian.PutUint16(buf[2:4], header.Flags)
	binary.BigEndian.PutUint16(buf[4:6], header.NumQuestions)
	binary.BigEndian.PutUint16(buf[6:8], header.NumAnswers)
	binary.BigEndian.PutUint16(buf[8:10], header.NumAuthorities)
	binary.BigEndian.PutUint16(buf[10:12], header.NumAdditionals)
	return buf
}

func parseHeader(r io.Reader) (DNSHeader, error) {
	var header DNSHeader

	err := binary.Read(r, binary.BigEndian, &header)
	if err != nil {
		return header, err
	}
	return header, nil
}

func questionToBytes(question DNSQuestion) []byte {
	var buf []byte
	// Encode the domain name
	buf = append(buf, encodeDNSName(question.Name)...)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp[0:2], question.Type)
	binary.BigEndian.PutUint16(tmp[2:4], question.Class)
	buf = append(buf, tmp...)
	return buf
}

func parseQuestion(r io.Reader) (DNSQuestion, error) {
	var question DNSQuestion
	name, err := decodeNameSimple(r)
	if err != nil {
		return question, err
	}
	question.Name = name
	err = binary.Read(r, binary.BigEndian, &question.Type)
	if err != nil {
		return question, err
	}
	err = binary.Read(r, binary.BigEndian, &question.Class)
	if err != nil {
		return question, err
	}
	return question, nil
}

func encodeDNSName(domainName string) []byte {
	labels := []byte{}
	for _, label := range strings.Split(domainName, ".") {
		labels = append(labels, byte(len(label)))
		labels = append(labels, []byte(label)...)
	}
	labels = append(labels, 0)
	return labels
}

func decodeNameSimple(r io.Reader) (string, error) {
	var parts []string
	for {
		var lengthByte [1]byte
		_, err := r.Read(lengthByte[:])
		if err != nil {
			return "", err
		}
		length := int(lengthByte[0])
		if length == 0 {
			break
		}
		label := make([]byte, length)
		_, err = r.Read(label)
		if err != nil {
			return "", err
		}
		parts = append(parts, string(label))
	}
	return strings.Join(parts, "."), nil
}

func decodeName(r io.ReadSeeker) (string, error) {
	return decodeNameWrapper(r, 10) // Limit to 10 pointers to avoid infinite loops
}

func decodeNameWrapper(r io.ReadSeeker, count int) (string, error) {
	if count <= 0 {
		return "", fmt.Errorf("Too many pointers or invalid pointer in DNS name decoding")
	}
	parts := []string{}
	for {
		var lengthByte [1]byte
		_, err := r.Read(lengthByte[:])
		if err != nil {
			return "", err
		}
		length := int(lengthByte[0])
		if length == 0 {
			break
		}
		if length&0b11000000 == 0b11000000 {
			// This is a pointer
			name, err := decodeCompressedName(length, r, count)
			if err != nil {
				return "", err
			}
			parts = append(parts, name)
			break
		} else {
			label := make([]byte, length)
			_, err = r.Read(label)
			if err != nil {
				return "", err
			}
			parts = append(parts, string(label))
		}
	}
	return strings.Join(parts, "."), nil
}

func decodeCompressedName(length int, r io.ReadSeeker, count int) (string, error) {
	pointerBytes := make([]byte, 2)
	pointerBytes[0] = byte(length & 0b00111111) // Mask the first two bits
	_, err := r.Read(pointerBytes[1:])
	if err != nil {
		return "", err
	}
	pointer := int(binary.BigEndian.Uint16(pointerBytes))
	currentPos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", err
	}
	_, err = r.Seek(int64(pointer), io.SeekStart)
	if err != nil {
		return "", err
	}
	res, err := decodeNameWrapper(r, count-1)
	if err != nil {
		return "", err
	}
	_, err = r.Seek(currentPos, io.SeekStart)
	if err != nil {
		return "", err
	}
	return res, nil
}

type DNSRecordType int

const (
	TYPE_A     DNSRecordType = 1
	TYPE_NS    DNSRecordType = 2
	TYPE_CNAME DNSRecordType = 5

	CLASS_IN = 1
)

func buildQuery(domainName string, recordType DNSRecordType) ([]byte, error) {
	id := rand.Intn(65536)
	header := DNSHeader{
		ID:             uint16(id),
		Flags:          0,
		NumQuestions:   1,
		NumAnswers:     0,
		NumAuthorities: 0,
		NumAdditionals: 0,
	}
	question := DNSQuestion{
		Name:  domainName,
		Type:  uint16(recordType),
		Class: CLASS_IN,
	}
	var buf []byte
	headerBytes := headerToBytes(header)
	questionBytes := questionToBytes(question)
	buf = append(buf, headerBytes...)
	buf = append(buf, questionBytes...)
	return buf, nil
}

type DNSRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

func parseRecord(r io.ReadSeeker) (DNSRecord, error) {
	var record DNSRecord
	name, err := decodeName(r)
	if err != nil {
		return record, err
	}
	record.Name = name
	err = binary.Read(r, binary.BigEndian, &record.Type)
	if err != nil {
		return record, err
	}
	err = binary.Read(r, binary.BigEndian, &record.Class)
	if err != nil {
		return record, err
	}
	err = binary.Read(r, binary.BigEndian, &record.TTL)
	if err != nil {
		return record, err
	}
	var dataLength uint16
	err = binary.Read(r, binary.BigEndian, &dataLength)
	if err != nil {
		return record, err
	}
	var data []byte
	switch record.Type {
	case uint16(TYPE_A):
		tmp := make([]byte, dataLength)
		_, err = r.Read(tmp)
		if err != nil {
			return record, err
		}
		ip := ipToString(tmp)
		data = []byte(ip)
	case uint16(TYPE_CNAME), uint16(TYPE_NS):
		name, err := decodeName(r)
		if err != nil {
			return record, err
		}
		data = []byte(name)
	default:
		data = make([]byte, dataLength)
		_, err = r.Read(data)
		if err != nil {
			return record, err
		}
	}
	record.Data = data
	return record, nil
}

type DNSPacket struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSRecord
	Authorities []DNSRecord
	Additionals []DNSRecord
}

func parseDNSPacket(data []byte) (DNSPacket, error) {
	var packet DNSPacket
	reader := bytes.NewReader(data)
	header, err := parseHeader(reader)
	if err != nil {
		return packet, err
	}
	packet.Header = header

	questions := make([]DNSQuestion, header.NumQuestions)
	for i := 0; i < int(header.NumQuestions); i++ {
		question, err := parseQuestion(reader)
		if err != nil {
			return packet, err
		}
		questions[i] = question
	}
	packet.Questions = questions

	answers := make([]DNSRecord, header.NumAnswers)
	for i := 0; i < int(header.NumAnswers); i++ {
		answer, err := parseRecord(reader)
		if err != nil {
			return packet, err
		}
		answers[i] = answer
	}
	packet.Answers = answers

	authorities := make([]DNSRecord, header.NumAuthorities)
	for i := 0; i < int(header.NumAuthorities); i++ {
		authority, err := parseRecord(reader)
		if err != nil {
			return packet, err
		}
		authorities[i] = authority
	}
	packet.Authorities = authorities

	additionals := make([]DNSRecord, header.NumAdditionals)
	for i := 0; i < int(header.NumAdditionals); i++ {
		additional, err := parseRecord(reader)
		if err != nil {
			return packet, err
		}
		additionals[i] = additional
	}
	packet.Additionals = additionals

	return packet, nil
}

func sendQuery(ipAddress string, domainName string, recordType DNSRecordType) (DNSPacket, error) {
	query, err := buildQuery(domainName, recordType)
	if err != nil {
		return DNSPacket{}, err
	}
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:53", ipAddress))
	if err != nil {
		return DNSPacket{}, err
	}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return DNSPacket{}, err
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		return DNSPacket{}, err
	}

	response := make([]byte, 1024)
	_, err = conn.Read(response)
	if err != nil {
		return DNSPacket{}, err
	}
	packet, err := parseDNSPacket(response)
	if err != nil {
		return DNSPacket{}, err
	}
	return packet, nil
}

func ipToString(ip []byte) string {
	if len(ip) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func getAnswer(packet *DNSPacket) string {
	for _, answer := range packet.Answers {
		if answer.Type == uint16(TYPE_A) {
			return string(answer.Data)
		}
	}
	return ""
}

func getCNAME(packet *DNSPacket) string {
	for _, answer := range packet.Answers {
		if answer.Type == uint16(TYPE_CNAME) {
			return string(answer.Data)
		}
	}
	return ""
}

func getNameserverIP(packet *DNSPacket) string {
	for _, additional := range packet.Additionals {
		if additional.Type == uint16(TYPE_A) {
			return string(additional.Data)
		}
	}
	return ""
}

func getNameserver(packet *DNSPacket) string {
	for _, authority := range packet.Authorities {
		if authority.Type == uint16(TYPE_NS) {
			return string(authority.Data)
		}
	}
	return ""
}

func resolve(domainName string, recordType DNSRecordType) (string, error) {
	nameserver := "198.41.0.4"
	for {
		fmt.Printf("Querying %s for %s\n", nameserver, domainName)
		response, err := sendQuery(nameserver, domainName, recordType)
		if err != nil {
			return "", err
		}
		if ip := getAnswer(&response); ip != "" {
			return ip, nil
		} else if cname := getCNAME(&response); cname != "" {
			return resolve(cname, recordType)
		} else if nsIP := getNameserverIP(&response); nsIP != "" {
			nameserver = nsIP
		} else if ns := getNameserver(&response); ns != "" {
			nsIP, err := resolve(ns, TYPE_A)
			if err != nil {
				return "", err
			}
			nameserver = nsIP
		} else {
			return "", fmt.Errorf("Something went wrong while resolving %s", domainName)
		}
	}
}

func main() {
	fmt.Println("Resolving domain names...")
	res, err := resolve("twitter.com", TYPE_A)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Result:", res)
	}
	fmt.Println("")

	// CNAME example
	fmt.Println("Resolving domain names with CNAME...")
	res, err = resolve("docs.helpscout.com", TYPE_A)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Result:", res)
	}
	fmt.Println("")
}
