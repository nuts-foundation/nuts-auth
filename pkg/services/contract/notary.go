package contract

import (
	"errors"
	"fmt"
	"time"

	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

type contractNotaryService struct {
	Registry         registry.RegistryClient
	ContractValidity time.Duration
}

func NewContractNotary(reg registry.RegistryClient, contractValidity time.Duration) *contractNotaryService {
	return &contractNotaryService{reg, contractValidity}
}

// organizationNameByID returns the name of an organisation from the registry
func (s contractNotaryService) organizationNameByID(legalEntity core.PartyID) (string, error) {
	org, err := s.Registry.OrganizationById(legalEntity)
	if err != nil {
		return "", err
	}
	return org.Name, nil
}

// DrawUpContract draws up a contract for a specific organisation from a template
func (s contractNotaryService) DrawUpContract(template contract.Template, orgID core.PartyID) (*contract.Contract, error) {
	orgName, err := s.organizationNameByID(orgID)
	if err != nil {
		return nil, fmt.Errorf("could not draw up contract: %w", err)
	}
	contractAttrs := map[string]string{
		contract.LegalEntityAttr: orgName,
	}
	drawnUpContract, err := template.Render(contractAttrs, 0, s.ContractValidity)
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
