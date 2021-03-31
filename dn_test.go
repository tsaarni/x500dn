package x500dn

import (
	"testing"
)

func TestDnParse(t *testing.T) {
	dn, err := ParseDN("CN=John Doe,OU=People,O=MyCompany")
	if err != nil {
		t.Errorf("Failed %s\n", err)
	}

	if !(dn.CommonName == "John Doe" && dn.OrganizationalUnit[0] == "People" && dn.Organization[0] == "MyCompany") {
		t.Errorf("Failed: dn not as expected %v\n", dn)
	}
}

func TestParseDomainComponent(t *testing.T) {
	dn, err := ParseDN("CN=John Doe,DC=domain-component")
	if err != nil {
		t.Errorf("Failed %s\n", err)
	}

	if !(dn.CommonName == "John Doe" && dn.ExtraNames[0].Value == "domain-component") {
		t.Errorf("Failed: dn not as expected %v\n", dn)
	}

}
