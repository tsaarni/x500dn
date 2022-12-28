# x500dn

Go library that parses string with X.500 distinguished name into [pkix.Name](https://golang.org/pkg/crypto/x509/pkix/#Name). See [doc](https://pkg.go.dev/github.com/tsaarni/x500dn).

Acknowledgements:

* Code adapted from [go-ldap](https://github.com/go-ldap/ldap/blob/a4f79d8a7cda1dcfbe9efafbd1e1621608881e93/dn.go)
* List of commonly used ASN.1 OIDs copied from [BouncyCastle](https://github.com/bcgit/bc-java/blob/738dfc0132323d66ad27e7ec366666ed3e0638ab/core/src/main/java/org/bouncycastle/asn1/x500/style/RFC4519Style.java)
