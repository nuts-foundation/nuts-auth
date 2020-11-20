package contract

import (
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
