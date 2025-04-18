package x500dn

import (
	"encoding/asn1"
	"reflect"
	"testing"
)

func TestDnParse(t *testing.T) {
	dn, err := ParseDN("CN=John Doe,OU=People,O=MyCompany")
	if err != nil {
		t.Errorf("Failed %s\n", err)
	}

	if dn.CommonName != "John Doe" || dn.OrganizationalUnit[0] != "People" || dn.Organization[0] != "MyCompany" {
		t.Errorf("Failed: dn not as expected %v\n", dn)
	}
}

func TestEscape(t *testing.T) {
	dn, err := ParseDN("CN=John \"Bob\" Doe")
	if err != nil {
		t.Errorf("Failed %s\n", err)
	}
	if dn.CommonName != "John \"Bob\" Doe" {
		t.Errorf("Failed: dn not as expected %v\n", dn)
	}

	dn, err = ParseDN("CN=Before\\0DAfter")
	if err != nil {
		t.Errorf("Failed %s\n", err)
	}
	if dn.CommonName != "Before\rAfter" {
		t.Errorf("Failed: dn not as expected %v\n", dn)
	}
}

func TestParseDomainComponent(t *testing.T) {
	dn, err := ParseDN("CN=John Doe,DC=domain-component")
	if err != nil {
		t.Errorf("Failed %s\n", err)
	}

	expected := asn1.RawValue{Tag: 22, Class: 0, Bytes: []byte("domain-component")}
	if dn.CommonName != "John Doe" || !reflect.DeepEqual(dn.ExtraNames[0].Value.(asn1.RawValue), expected) {
		t.Errorf("Failed: dn not as expected %v\n", dn)
	}
}

func TestParseEmailAddress(t *testing.T) {
	dn, err := ParseDN("CN=John Doe, emailAddress=john@example.com")
	if err != nil {
		t.Errorf("Failed %s\n", err)
	}

	expected := asn1.RawValue{Tag: 22, Class: 0, Bytes: []byte("john@example.com")}
	if dn.CommonName != "John Doe" || !reflect.DeepEqual(dn.ExtraNames[0].Value.(asn1.RawValue), expected) {
		t.Errorf("Failed: dn not as expected %v\n", dn)
	}
}
