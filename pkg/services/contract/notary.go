package contract

import (
	"errors"
	"fmt"
	"time"

	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services/validator"
)

type contractNotaryService struct {
	Registry         registry.RegistryClient
	Crypto           nutscrypto.Client
	ContractValidity time.Duration
}

func NewContractNotary(reg registry.RegistryClient, crypto nutscrypto.Client, contractValidity time.Duration) *contractNotaryService {
	return &contractNotaryService{Registry: reg, ContractValidity: contractValidity, Crypto: crypto}
}

// organizationNameByID returns the name of an organisation from the registry
func (s contractNotaryService) organizationNameByID(legalEntity core.PartyID) (string, error) {
	org, err := s.Registry.OrganizationById(legalEntity)
	if err != nil {
		return "", err
	}
	return org.Name, nil
}

// KeyExistsFor check if the private key exists on this node by calling the same function on the CryptoClient
func (s *contractNotaryService) KeyExistsFor(legalEntity core.PartyID) bool {
	return s.Crypto.PrivateKeyExists(cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: legalEntity.String()}))
}

// DrawUpContract accepts a template and fills in the Party, validFrom time and its duration.
// If validFrom is zero, the current time is used.
// If the duration is 0 than the default duration is used.
func (s contractNotaryService) DrawUpContract(template contract.Template, orgID core.PartyID, validFrom time.Time, validDuration time.Duration) (*contract.Contract, error) {
	// Test if the org in managed by this node:
	if !s.KeyExistsFor(orgID) {
		return nil, fmt.Errorf("could not draw up contract: organization is not managed by this node: %w", validator.ErrMissingOrganizationKey)
	}

	// DrawUpContract draws up a contract for a specific organisation from a template
	orgName, err := s.organizationNameByID(orgID)
	if err != nil {
		return nil, fmt.Errorf("could not draw up contract: %w", err)
	}
	contractAttrs := map[string]string{
		contract.LegalEntityAttr: orgName,
	}

	if validDuration == 0 {
		validDuration = s.ContractValidity
	}
	if validFrom.IsZero() {
		validFrom = time.Now()
	}

	drawnUpContract, err := template.Render(contractAttrs, validFrom, validDuration)
	if err != nil {
		return nil, fmt.Errorf("could not draw up contract: %w", err)
	}
	return drawnUpContract, nil
}

// ValidateContract checks if a given contract is valid for a given orgID and is valid at a given checkTime.
func (s contractNotaryService) ValidateContract(contractToValidate contract.Contract, orgID core.PartyID, checkTime time.Time) (bool, error) {
	// check if the contract is sound and it is valid at the given checkTime
	err := contractToValidate.VerifyForGivenTime(checkTime)
	if err != nil {
		return false, err
	}

	// check that the legal entity in the contract is the name of the party identified with the given orgID
	legalEntityName, ok := contractToValidate.Params[contract.LegalEntityAttr]
	if !ok {
		return false, errors.New("legalEntity not part of the contract")
	}
	le, err := s.Registry.ReverseLookup(legalEntityName)
	if le.Identifier != orgID {
		return false, fmt.Errorf("legalEntityName '%s' does not match as the name for legalEntity with id: '%s':'%s'", legalEntityName, orgID.String(), le.Name)
	}

	return true, nil
}
