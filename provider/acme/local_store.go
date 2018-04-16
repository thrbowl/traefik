package acme

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/safe"
)

var _ Store = (*LocalStore)(nil)

// LocalStore Store implementation for local file
type LocalStore struct {
	filename     string
	storedData   *StoredData
	SaveDataChan chan *StoredData `json:"-"`
}

// NewLocalStore initializes a new LocalStore with a file name
func NewLocalStore(filename string) LocalStore {
	store := LocalStore{filename: filename, SaveDataChan: make(chan *StoredData)}
	store.listenSaveAction()
	return store
}

func (s *LocalStore) get() (*StoredData, error) {
	if s.storedData == nil {
		s.storedData = &StoredData{HTTPChallenges: make(map[string]map[string][]byte)}

		hasData, err := CheckFile(s.filename)
		if err != nil {
			return nil, err
		}

		if hasData {
			f, err := os.Open(s.filename)
			if err != nil {
				return nil, err
			}
			defer f.Close()

			file, err := ioutil.ReadAll(f)
			if err != nil {
				return nil, err
			}

			if len(file) > 0 {
				if err := json.Unmarshal(file, s.storedData); err != nil {
					return nil, err
				}
			}

			// Check if ACME Account is in ACME V1 format
			if s.storedData.Account != nil && s.storedData.Account.Registration != nil {
				isOldRegistration, err := regexp.MatchString(RegistrationURLPathV1Regexp, s.storedData.Account.Registration.URI)
				if err != nil {
					return nil, err
				}
				if isOldRegistration {
					s.storedData.Account = nil
					s.SaveDataChan <- s.storedData
				}
			}

			// Delete all certificates with no value
			var certificates []*Certificate
			for _, certificate := range s.storedData.Certificates {
				if len(certificate.Certificate) == 0 || len(certificate.Key) == 0 {
					log.Debugf("Delete certificate %v for domains %v which have no value.", certificate, certificate.Domain.ToStrArray())
					continue
				}
				certificates = append(certificates, certificate)
			}

			if len(certificates) < len(s.storedData.Certificates) {
				s.storedData.Certificates = certificates
				s.SaveDataChan <- s.storedData
			}
		}
	}

	return s.storedData, nil
}

// listenSaveAction listens to a chan to store ACME data in json format into LocalStore.filename
func (s *LocalStore) listenSaveAction() {
	safe.Go(func() {
		for object := range s.SaveDataChan {
			data, err := json.MarshalIndent(object, "", "  ")
			if err != nil {
				log.Error(err)
			}

			err = ioutil.WriteFile(s.filename, data, 0600)
			if err != nil {
				log.Error(err)
			}
		}
	})
}

// GetAccount returns ACME Account
func (s *LocalStore) GetAccount() (*Account, error) {
	storedData, err := s.get()
	if err != nil {
		return nil, err
	}

	return storedData.Account, nil
}

// SaveAccount stores ACME Account
func (s *LocalStore) SaveAccount(account *Account) error {
	storedData, err := s.get()
	if err != nil {
		return err
	}

	storedData.Account = account
	s.SaveDataChan <- storedData

	return nil
}

// GetCertificates returns ACME Certificates list
func (s *LocalStore) GetCertificates() ([]*Certificate, error) {
	storedData, err := s.get()
	if err != nil {
		return nil, err
	}

	return storedData.Certificates, nil
}

// SaveCertificates stores ACME Certificates list
func (s *LocalStore) SaveCertificates(certificates []*Certificate) error {
	storedData, err := s.get()
	if err != nil {
		return err
	}

	storedData.Certificates = certificates
	s.SaveDataChan <- storedData

	return nil
}

// GetHTTPChallenges returns ACME HTTP Challenges list
func (s *LocalStore) GetHTTPChallenges() (map[string]map[string][]byte, error) {
	return s.storedData.HTTPChallenges, nil
}

// SaveHTTPChallenges stores ACME HTTP Challenges list
func (s *LocalStore) SaveHTTPChallenges(httpChallenges map[string]map[string][]byte) error {
	s.storedData.HTTPChallenges = httpChallenges
	return nil
}
