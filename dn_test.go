package x500dn

import (
	"fmt"
	"testing"
)

func TestDnParse(t *testing.T) {
	dn, err := ParseDN("CN=John Doe,OU=People,O=MyCompany")
	fmt.Printf("%+v\n", dn)
	if err != nil {
		t.Errorf("Failed %s\n", err)
	}

}
