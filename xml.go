package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"time"
)

// Define the Go structs based on the XSD schema
type DeltaCertificateData struct {
	XMLName                             xml.Name              `xml:"DeltaCertificateData"`
	Version                             string                `xml:"ver,attr"`
	Header                              Header                `xml:"Header"`
	CredentialTypeLabel                 string                `xml:"CredentialTypeLabel"`
	EKPub                               string                `xml:"EKPub,omitempty"`
	BasePlatformCertificateSerialNumber string                `xml:"BasePlatformCertificateSerialNumber"`
	PlatformManufacturer                string                `xml:"PlatformManufacturer"`
	PlatformModel                       string                `xml:"PlatformModel"`
	PlatformVersion                     string                `xml:"PlatformVersion"`
	BasePlatformCertificateIssuer       string                `xml:"BasePlatformCertificateIssuer"`
	ValidTo                             time.Time             `xml:"ValidTo"`
	PlatformClass                       int                   `xml:"PlatformClass"`
	MajorVersion                        int                   `xml:"MajorVersion"`
	MinorVersion                        int                   `xml:"MinorVersion"`
	Revision                            int                   `xml:"Revision"`
	SignatureValue                      string                `xml:"SignatureValue,omitempty"`
	PlatformAssertions                  string                `xml:"PlatformAssertions,omitempty"`
	PlatformSerialNumber                string                `xml:"PlatformSerialNumber,omitempty"`
	TPMVendor                           string                `xml:"TPMVendor,omitempty"`
	PlatformConfiguration               PlatformConfiguration `xml:"PlatformConfiguration,omitempty"`
	PlatformConfigurationUri            string                `xml:"PlatformConfigurationUri,omitempty"`
}

type Header struct {
	SystemSN      string    `xml:"SystemSN"`
	GUID          string    `xml:"GUID,omitempty"`
	Manufacturer  string    `xml:"Manufacturer"`
	Model         string    `xml:"Model"`
	DateTime      time.Time `xml:"DateTime"`
	OEM           string    `xml:"OEM"`
	ODM           string    `xml:"ODM,omitempty"`
	MfgPubKeyHash string    `xml:"MfgPubKeyHash,omitempty"`
}

type PlatformConfiguration struct {
	ComponentIdentifiers  ComponentIdentifiers `xml:"ComponentIdentifiers,omitempty"`
	PlatformProperties    PlatformProperties   `xml:"PlatformProperties,omitempty"`
	PlatformPropertiesUri string               `xml:"PlatformPropertiesUri,omitempty"`
}

type ComponentIdentifiers struct {
	ComponentIdentifier []ComponentIdentifier `xml:"ComponentIdentifier,omitempty"`
}

type ComponentIdentifier struct {
	ComponentClass           string                `xml:"ComponentClass"`
	Manufacturer             string                `xml:"Manufacturer"`
	Model                    string                `xml:"Model"`
	Serial                   string                `xml:"Serial,omitempty"`
	Revision                 string                `xml:"Revision,omitempty"`
	ManufacturerId           int                   `xml:"ManufacturerId,omitempty"`
	FieldReplaceable         bool                  `xml:"FieldReplaceable,omitempty"`
	Status                   string                `xml:"Status,omitempty"`
	ComponentAddresses       ComponentAddresses    `xml:"ComponentAddresses,omitempty"`
	ComponentPlatformCert    ComponentPlatformCert `xml:"ComponentPlatformCert,omitempty"`
	ComponentPlatformCertUri string                `xml:"ComponentPlatformCertUri,omitempty"`
}

type ComponentAddresses struct {
	ComponentAddress []ComponentAddress `xml:"ComponentAddress,omitempty"`
}

type ComponentAddress struct {
	AddressType  string `xml:"AddressType"`
	AddressValue string `xml:"AddressValue"`
}

type ComponentPlatformCert struct {
	AttributeCertIdentifier AttributeCertIdentifier `xml:"AttributeCertIdentifier,omitempty"`
	GenericCertIdentifier   GenericCertIdentifier   `xml:"GenericCertIdentifier,omitempty"`
}

type AttributeCertIdentifier struct {
	HashAlgorithm     string `xml:"HashAlgorithm"`
	HashOverSignature string `xml:"HashOverSignature"`
}

type GenericCertIdentifier struct {
	CertificateIssuer       string `xml:"CertificateIssuer"`
	CertificateSerialNumber string `xml:"CertificateSerialNumber"`
}

type PlatformProperties struct {
	Property []Property `xml:"Property,omitempty"`
}

type Property struct {
	Name   string `xml:"Name"`
	Value  string `xml:"Value"`
	Status string `xml:"Status,omitempty"`
}

func main() {
	// Create an instance of the struct with sample data
	data := DeltaCertificateData{
		Version: "1",
		Header: Header{
			SystemSN:      "SN12345678",
			GUID:          "GUID1234",
			Manufacturer:  "Manufacturer1",
			Model:         "Model1",
			DateTime:      time.Now(),
			OEM:           "OEM1",
			ODM:           "ODM1",
			MfgPubKeyHash: "Hash1234",
		},
		CredentialTypeLabel:                 "Label1",
		EKPub:                               "EKPub1",
		BasePlatformCertificateSerialNumber: "Serial1",
		PlatformManufacturer:                "Manufacturer1",
		PlatformModel:                       "Model1",
		PlatformVersion:                     "Version1",
		BasePlatformCertificateIssuer:       "Issuer1",
		ValidTo:                             time.Now().AddDate(1, 0, 0),
		PlatformClass:                       1,
		MajorVersion:                        1,
		MinorVersion:                        0,
		Revision:                            1,
		SignatureValue:                      "Signature1",
		PlatformAssertions:                  "Assertions1",
		PlatformSerialNumber:                "Serial1",
		TPMVendor:                           "Vendor1",
		PlatformConfiguration: PlatformConfiguration{
			ComponentIdentifiers: ComponentIdentifiers{
				ComponentIdentifier: []ComponentIdentifier{
					{
						ComponentClass:   "Class1",
						Manufacturer:     "Manufacturer1",
						Model:            "Model1",
						Serial:           "Serial1",
						Revision:         "Revision1",
						ManufacturerId:   1,
						FieldReplaceable: true,
						Status:           "Status1",
						ComponentAddresses: ComponentAddresses{
							ComponentAddress: []ComponentAddress{
								{
									AddressType:  "Type1",
									AddressValue: "Value1",
								},
							},
						},
						ComponentPlatformCert: ComponentPlatformCert{
							AttributeCertIdentifier: AttributeCertIdentifier{
								HashAlgorithm:     "SHA-256",
								HashOverSignature: "SignatureHash1",
							},
							GenericCertIdentifier: GenericCertIdentifier{
								CertificateIssuer:       "Issuer1",
								CertificateSerialNumber: "Serial1",
							},
						},
						ComponentPlatformCertUri: "URI1",
					},
				},
			},
			PlatformProperties: PlatformProperties{
				Property: []Property{
					{
						Name:   "PropertyName1",
						Value:  "PropertyValue1",
						Status: "Status1",
					},
				},
			},
			PlatformPropertiesUri: "URI1",
		},
		PlatformConfigurationUri: "URI1",
	}

	// Marshal the struct into XML format
	output, err := xml.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling to XML: %v\n", err)
		return
	}

	// Add XML header
	xmlOutput := xml.Header + string(output)

	// Write to file
	err = os.WriteFile("DeltaCertificateData.xml", []byte(xmlOutput), 0644)
	if err != nil {
		fmt.Printf("Error writing XML to file: %v\n", err)
		return
	}

	fmt.Println("Successfully created DeltaCertificateData.xml")
}
