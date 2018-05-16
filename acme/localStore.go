package acme

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/provider/acme"
)

// LocalStore is a store using a file as storage
type LocalStore struct {
	file string
}

// NewLocalStore create a LocalStore
func NewLocalStore(file string) *LocalStore {
	return &LocalStore{
		file: file,
	}
}

// Get loads file into store and returns the Account
func (s *LocalStore) Get() (*Account, error) {
	account := &Account{}

	hasData, err := acme.CheckFile(s.file)
	if err != nil {
		return nil, err
	}

	if hasData {
		f, err := os.Open(s.file)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		file, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(file, &account); err != nil {
			return nil, err
		}
	}

	return account, nil
}

// RemoveAccountV1Values removes ACME account V1 values
func RemoveAccountV1Values(account *Account) error {
	// Check if ACME Account is in ACME V1 format
	if account != nil && account.Registration != nil {
		isOldRegistration, err := regexp.MatchString(acme.RegistrationURLPathV1Regexp, account.Registration.URI)
		if err != nil {
			return err
		}

		if isOldRegistration {
			account.Email = ""
			account.Registration = nil
			account.PrivateKey = nil
			account.KeyType = "RSA4096"
		}
	}
	return nil
}

// ConvertToNewFormat converts old acme.json format to the new one and store the result into the file (used for the backward compatibility)
func ConvertToNewFormat(fileName string) {
	localStore := acme.NewLocalStore(fileName)

	storeAccount, err := localStore.GetAccount()
	if err != nil {
		log.Errorf("Failed to read new account, ACME data conversion is not available : %v", err)
		return
	}

	storeCertificates, err := localStore.GetCertificates()
	if err != nil {
		log.Errorf("Failed to read new certificates, ACME data conversion is not available : %v", err)
		return
	}

	if storeAccount == nil {
		localStore := NewLocalStore(fileName)

		account, err := localStore.Get()
		if err != nil {
			log.Errorf("Failed to read old account, ACME data conversion is not available : %v", err)
			return
		}

		// Convert ACME data from old to new format
		newAccount := &acme.Account{}
		if account != nil && len(account.Email) > 0 {
			err = backupACMEFile(fileName, account)
			if err != nil {
				log.Errorf("Unable to create a backup for the V1 formatted ACME file: %s", err.Error())
				return
			}

			err = RemoveAccountV1Values(account)
			if err != nil {
				log.Errorf("Unable to remove ACME Account V1 values: %s", err.Error())
				return
			}

			newAccount = &acme.Account{
				PrivateKey:   account.PrivateKey,
				Registration: account.Registration,
				Email:        account.Email,
				KeyType:      account.KeyType,
			}

			var newCertificates []*acme.Certificate
			for _, cert := range account.DomainsCertificate.Certs {
				newCertificates = append(newCertificates, &acme.Certificate{
					Certificate: cert.Certificate.Certificate,
					Key:         cert.Certificate.PrivateKey,
					Domain:      cert.Domains,
				})
			}

			// If account is in the old format, storeCertificates is nil or empty and has to be initialized
			storeCertificates = newCertificates
		}

		// Store the data in new format into the file even if account is nil
		// to delete Account in ACME v1 format and keeping the certificates
		newLocalStore := acme.NewLocalStore(fileName)
		newLocalStore.SaveDataChan <- &acme.StoredData{Account: newAccount, Certificates: storeCertificates}
	}
}

func backupACMEFile(originalFileName string, account interface{}) error {
	// write account to file
	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(originalFileName+".bak", data, 0600)
}

// FromNewToOldFormat converts new acme account to the old one (used for the backward compatibility)
func FromNewToOldFormat(fileName string) (*Account, error) {
	localStore := acme.NewLocalStore(fileName)

	storeAccount, err := localStore.GetAccount()
	if err != nil {
		return nil, err
	}

	storeCertificates, err := localStore.GetCertificates()
	if err != nil {
		return nil, err
	}

	// Convert ACME Account from new to old format
	// (Needed by the KV stores)
	var account *Account
	if storeAccount != nil {
		account = &Account{
			Email:              storeAccount.Email,
			PrivateKey:         storeAccount.PrivateKey,
			Registration:       storeAccount.Registration,
			DomainsCertificate: DomainsCertificates{},
			KeyType:            storeAccount.KeyType,
		}
	}

	// Convert ACME Certificates from new to old format
	// (Needed by the KV stores)
	if len(storeCertificates) > 0 {
		// Account can be nil if data are migrated from new format
		// with a ACME V1 Account
		if account == nil {
			account = &Account{}
		}
		for _, cert := range storeCertificates {
			_, err := account.DomainsCertificate.addCertificateForDomains(&Certificate{
				Domain:      cert.Domain.Main,
				Certificate: cert.Certificate,
				PrivateKey:  cert.Key,
			}, cert.Domain)
			if err != nil {
				return nil, err
			}
		}
	}

	return account, nil
}
