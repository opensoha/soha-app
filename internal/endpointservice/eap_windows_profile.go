package endpointservice

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf16"
)

type eapWindowsXMLNode struct {
	Name     xml.Name
	Text     string
	Children []eapWindowsXMLNode
}

func parseEAPWindowsXML(raw []byte) (eapWindowsXMLNode, error) {
	if len(raw) == 0 || len(raw) > 128<<10 {
		return eapWindowsXMLNode{}, errors.New("Windows EAP XML exceeds the safe size")
	}
	wasUTF16 := bytes.HasPrefix(raw, []byte{0xff, 0xfe}) || bytes.HasPrefix(raw, []byte{0xfe, 0xff})
	if wasUTF16 {
		if len(raw)%2 != 0 {
			return eapWindowsXMLNode{}, errors.New("Windows EAP XML has a truncated UTF-16 character")
		}
		var order binary.ByteOrder = binary.LittleEndian
		if raw[0] == 0xfe {
			order = binary.BigEndian
		}
		units := make([]uint16, len(raw)/2-1)
		for index := range units {
			units[index] = order.Uint16(raw[index*2+2:])
		}
		raw = []byte(string(utf16.Decode(units)))
	}
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		if wasUTF16 && strings.EqualFold(label, "UTF-16") {
			return input, nil
		}
		return nil, errors.New("Windows EAP XML has an unsupported encoding")
	}
	var stack []eapWindowsXMLNode
	var root *eapWindowsXMLNode
	count := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF && root != nil && len(stack) == 0 {
			return *root, nil
		}
		if err != nil {
			return eapWindowsXMLNode{}, errors.New("Windows EAP XML is incomplete or invalid")
		}
		switch value := token.(type) {
		case xml.StartElement:
			count++
			if root != nil || len(stack) >= 32 || count > 4096 || value.Name.Space == "" {
				return eapWindowsXMLNode{}, errors.New("Windows EAP XML has an ambiguous or oversized structure")
			}
			for _, attribute := range value.Attr {
				if attribute.Name.Space != "xmlns" && (attribute.Name.Space != "" || attribute.Name.Local != "xmlns") {
					return eapWindowsXMLNode{}, errors.New("Windows EAP XML has unexpected attributes")
				}
			}
			stack = append(stack, eapWindowsXMLNode{Name: value.Name})
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(value)) != "" {
					return eapWindowsXMLNode{}, errors.New("Windows EAP XML has text outside the profile")
				}
			} else {
				stack[len(stack)-1].Text += string(value)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return eapWindowsXMLNode{}, errors.New("Windows EAP XML has an unexpected end element")
			}
			node := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			node.Text = strings.TrimSpace(node.Text)
			if len(node.Children) != 0 && node.Text != "" {
				return eapWindowsXMLNode{}, errors.New("Windows EAP XML mixes profile fields and text")
			}
			if len(stack) == 0 {
				root = &node
			} else {
				parent := &stack[len(stack)-1]
				if node.Name.Local != "TrustedRootCA" && slices.ContainsFunc(parent.Children, func(child eapWindowsXMLNode) bool { return child.Name == node.Name }) {
					return eapWindowsXMLNode{}, errors.New("Windows EAP XML repeats a profile field")
				}
				parent.Children = append(parent.Children, node)
			}
		case xml.Directive:
			return eapWindowsXMLNode{}, errors.New("Windows EAP XML directives are forbidden")
		}
	}
}

func canonicalEAPWindowsXML(node eapWindowsXMLNode) string {
	raw, _ := json.Marshal(normalizeEAPWindowsXML(node))
	return string(raw)
}

func normalizeEAPWindowsXML(node eapWindowsXMLNode) eapWindowsXMLNode {
	if node.Name.Local == "hex" || node.Name.Local == "TrustedRootCA" || node.Name.Local == "UserCert" {
		node.Text = strings.ToLower(strings.Map(func(character rune) rune {
			if unicode.IsSpace(character) {
				return -1
			}
			return character
		}, node.Text))
	}
	node.Children = slices.Clone(node.Children)
	for index, child := range node.Children {
		node.Children[index] = normalizeEAPWindowsXML(child)
	}
	slices.SortFunc(node.Children, func(left, right eapWindowsXMLNode) int {
		a, _ := json.Marshal(left)
		b, _ := json.Marshal(right)
		return bytes.Compare(a, b)
	})
	return node
}

func matchEAPWindowsXML(actual, expected []byte) error {
	left, err := parseEAPWindowsXML(actual)
	if err != nil {
		return err
	}
	right, err := parseEAPWindowsXML(expected)
	if err != nil {
		return err
	}
	if canonicalEAPWindowsXML(left) != canonicalEAPWindowsXML(right) {
		return errors.New("Windows EAP profile differs from the managed configuration")
	}
	return nil
}

func eapWindowsLANBaselineAllowed(raw []byte) bool {
	node, err := parseEAPWindowsXML(raw)
	if err != nil || node.Name != (xml.Name{Space: "http://www.microsoft.com/networking/LAN/profile/v1", Local: "LANProfile"}) {
		return false
	}
	for _, field := range []string{"MSM", "security", "OneXEnabled"} {
		index := slices.IndexFunc(node.Children, func(child eapWindowsXMLNode) bool {
			return child.Name.Space == node.Name.Space && child.Name.Local == field
		})
		if index < 0 {
			return false
		}
		node = node.Children[index]
	}
	return node.Text == "false" || node.Text == "0"
}
