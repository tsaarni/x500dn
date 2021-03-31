package x500dn

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	enchex "encoding/hex"
	"errors"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

var oids = map[string]asn1.ObjectIdentifier{
	"businesscategory":           {2, 5, 4, 15},
	"c":                          {2, 5, 4, 6},
	"cn":                         {2, 5, 4, 3},
	"dc":                         {0, 9, 2342, 19200300, 100, 1, 25},
	"description":                {2, 5, 4, 13},
	"destinationindicator":       {2, 5, 4, 27},
	"distinguishedName":          {2, 5, 4, 49},
	"dnqualifier":                {2, 5, 4, 46},
	"enhancedsearchguide":        {2, 5, 4, 47},
	"facsimiletelephonenumber":   {2, 5, 4, 23},
	"generationqualifier":        {2, 5, 4, 44},
	"givenname":                  {2, 5, 4, 42},
	"houseidentifier":            {2, 5, 4, 51},
	"initials":                   {2, 5, 4, 43},
	"internationalisdnnumber":    {2, 5, 4, 25},
	"l":                          {2, 5, 4, 7},
	"member":                     {2, 5, 4, 31},
	"name":                       {2, 5, 4, 41},
	"o":                          {2, 5, 4, 10},
	"ou":                         {2, 5, 4, 11},
	"owner":                      {2, 5, 4, 32},
	"physicaldeliveryofficename": {2, 5, 4, 19},
	"postaladdress":              {2, 5, 4, 16},
	"postalcode":                 {2, 5, 4, 17},
	"postOfficebox":              {2, 5, 4, 18},
	"preferreddeliverymethod":    {2, 5, 4, 28},
	"registeredaddress":          {2, 5, 4, 26},
	"roleoccupant":               {2, 5, 4, 33},
	"searchguide":                {2, 5, 4, 14},
	"seealso":                    {2, 5, 4, 34},
	"serialnumber":               {2, 5, 4, 5},
	"sn":                         {2, 5, 4, 4},
	"st":                         {2, 5, 4, 8},
	"street":                     {2, 5, 4, 9},
	"telephonenumber":            {2, 5, 4, 20},
	"teletexterminalidentifier":  {2, 5, 4, 22},
	"telexnumber":                {2, 5, 4, 21},
	"title":                      {2, 5, 4, 12},
	"uid":                        {0, 9, 2342, 19200300, 100, 1, 1},
	"uniquemember":               {2, 5, 4, 50},
	"userpassword":               {2, 5, 4, 35},
	"x121address":                {2, 5, 4, 24},
}

// ParseDN returns a distinguishedName or an error.
// The function respects https://tools.ietf.org/html/rfc4514
func ParseDN(str string) (*pkix.Name, error) {
	dn := make(pkix.RelativeDistinguishedNameSET, 0)
	buffer := bytes.Buffer{}
	rdn := new(pkix.AttributeTypeAndValue)
	escaping := false

	unescapedTrailingSpaces := 0
	stringFromBuffer := func() string {
		s := buffer.String()
		s = s[0 : len(s)-unescapedTrailingSpaces]
		buffer.Reset()
		unescapedTrailingSpaces = 0
		return s
	}

	for i := 0; i < len(str); i++ {
		char := str[i]
		switch {
		case escaping:
			unescapedTrailingSpaces = 0
			escaping = false
			switch char {
			case ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\':
				buffer.WriteByte(char)
				continue
			}
			// Not a special character, assume hex encoded octet
			if len(str) == i+1 {
				return nil, errors.New("got corrupted escaped character")
			}

			dst := []byte{0}
			n, err := enchex.Decode([]byte(dst), []byte(str[i:i+2]))
			if err != nil {
				return nil, fmt.Errorf("failed to decode escaped character: %s", err)
			} else if n != 1 {
				return nil, fmt.Errorf("expected 1 byte when un-escaping, got %d", n)
			}
			buffer.WriteByte(dst[0])
			i++
		case char == '\\':
			unescapedTrailingSpaces = 0
			escaping = true
		case char == '=':
			rdn.Type = oids[strings.ToLower(stringFromBuffer())]
			// Special case: If the first character in the value is # the
			// following data is BER encoded so we can just fast forward
			// and decode.
			if len(str) > i+1 && str[i+1] == '#' {
				i += 2
				index := strings.IndexAny(str[i:], ",+")
				data := str
				if index > 0 {
					data = str[i : i+index]
				} else {
					data = str[i:]
				}
				rawBER, err := enchex.DecodeString(data)
				if err != nil {
					return nil, fmt.Errorf("failed to decode BER encoding: %s", err)
				}
				packet, err := ber.DecodePacketErr(rawBER)
				if err != nil {
					return nil, fmt.Errorf("failed to decode BER packet: %s", err)
				}
				buffer.WriteString(packet.Data.String())
				i += len(data) - 1
			}
		case char == ',' || char == '+':
			// We're done with this RDN or value, push it
			if len(rdn.Type) == 0 {
				return nil, errors.New("incomplete type, value pair")
			}
			rdn.Value = stringFromBuffer()
			dn = append(dn, *rdn)
			rdn = new(pkix.AttributeTypeAndValue)
			if char == ',' {
				dn = append(dn, *rdn)
				rdn = new(pkix.AttributeTypeAndValue)
			}
		case char == ' ' && buffer.Len() == 0:
			// ignore unescaped leading spaces
			continue
		default:
			if char == ' ' {
				// Track unescaped spaces in case they are trailing and we need to remove them
				unescapedTrailingSpaces++
			} else {
				// Reset if we see a non-space char
				unescapedTrailingSpaces = 0
			}
			buffer.WriteByte(char)
		}
	}
	if buffer.Len() > 0 {
		if len(rdn.Type) == 0 {
			return nil, errors.New("DN ended with incomplete type, value pair")
		}
		rdn.Value = stringFromBuffer()
		dn = append(dn, *rdn)
	}

	var sequence = pkix.RDNSequence{dn}
	var name pkix.Name
	name.FillFromRDNSequence(&sequence)
	err := fillExtraNames(&sequence, &name)
	if err != nil {
		return nil, err
	}
	return &name, nil
}

// Fill in ExtranNames with RDNs with OID prefix other than 2.5.4
func fillExtraNames(rdns *pkix.RDNSequence, name *pkix.Name) error {
	for _, rdn := range *rdns {
		if len(rdn) == 0 {
			continue
		}

		for _, atv := range rdn {
			if atv.Type.Equal(oids["dc"]) {
				// IA5String
				atv.Value = asn1.RawValue{Tag: 22, Class: 0, Bytes: []byte(atv.Value.(string))}
				name.ExtraNames = append(name.ExtraNames, atv)
			}
		}
	}
	return nil
}
