package testdata

import (
	"encoding/base64"
	"fmt"
)

func ConstructValidationContract(contract, actingParty string) string {
	return fmt.Sprintf(`{
	"contract_format": "irma",
    "contract_string": "%s",
	"acting_party_cn": "%s"
}`, base64.StdEncoding.EncodeToString([]byte(contract)), actingParty)
}

const InvalidContract = `
    { "this datas": "smellz bad"}
	`

const ValidIrmaContract = `{
    "signature": [
      {
        "c": "TH/z6HoTX5rvu70H8t7Q3B7mKG09a3LRU6UqlkEfJ3M=",
        "A": "dcij67w/Dlk7FJftjFEvaQ8FKOf5PaLjrhfza9pl2OvqUFDeor0jMY5WiYpY6nimM4HT72BfNh6qS+RbMgk7TIVvPj3wV12BX7TRmLOwpHRM34JVtyen4msIJCoBm8or+T1HHE3bGhAN1kld9bG6HiprJGzMDz6eV2VMM1ppSIcbg+J6Mt4XlaCOqTi7ox+hvgVxOTJu5OlIMw4/OvmSRkG63h7iSuHF8pmavB3bUh3UUww2tVeesgDp1zQoSZKWJ8a+J1BHTDYAOy8fiS0tpDnckX09v/LiQOzYocPB2NUGn9AzCEcrlCZU3MNYSHlKH80dINoHE6+NkdzjMhrVHQ==",
        "e_response": "1AjGh0WGbR5lZ6bqORFDKhhu2ORmY3B6H3SCXOtSbmi1x40CXAAw/ADCFXuy+wQd5OHwka85FmQD7vinSCkv",
        "v_response": "CRNwuI0B5L9r/anmGdSqqpFtW8EHfkZeBo65aUPspRTpgvA6OjefaxNz06bJeIwuIgInKXMo8HbmISYYUAbVe9wvDwW9Jd5qw8N6sQiUnUouvhvWfBB5g04d6GbEfgszlNgXNQBpxowXlLe3Kphq8HOzlGPyGtC5jzsFv9iQQx2VVDWOxZ/lJSUwylM8luGsiMl4Pj2iVQ+2Lx9gAdVRdrjRwnmrkd6mcpH4fk/8NZ3wl8BMgG/U519DmZ7QachzOC2a5OdhkBF+v98bwUFmNXl+2ck1PpYrstJC37EAQQNHyLP9C1XCyDoLL9Sr1NIay6nb/q5nP2hjJQVLunOfTDEOAtz08mmn7oLIwS8uaO+Gi9vM8yqEd7ArAmGJvDkjE6y4tXDxyhNcs6q7+2q3kkwTR75wf5Z+rbrp8nhgqDwLQaZsiK4QGXkATuuGnYSSEPVKUWkQaXuX9b5PRoAwj1Ik61Noyfolxqsy89dvW8ffFyM6TaESk01aihjXFiL7oeGFPgTaKOxLQdYsujrym6M=",
        "a_responses": {
          "0": "s9L2fM80S9pNxwqC/nbhByCVL12XX+V3kLavkcWwLRPgIMEBCOPSBpcxFhsqWK5HosCRdBr5YpWTzIm8+JcZaB8HGTkS5srqJMs=",
          "3": "DcAgFh30gmjhe5GsUNWZw2WZgDBuoCIDjBkCsHA0CyTJBVEfoDIYHYc3pJ0eFJngQ3T+X2tFrIL0M/rABvgRfLvfShmnihSXOGNI9orRf+g="
        },
        "a_disclosed": {
          "1": "AwAKCwAaAABH2jklUts5iBWSlKLhMjvi",
          "2": "YGBgYGBgYGM="
        }
      }
    ],
    "indices": [
      [
        {
          "cred": 0,
          "attr": 2
        }
      ]
    ],
    "nonce": "YPffjG+4BTMBtW1j5z1HOA==",
    "context": "AQ==",
    "message": "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Helder om uit zijn/haar naam het Nuts netwerk te bevragen. Deze toestemming is geldig van vrijdag, 26 april 2019 11:45:30 tot vrijdag, 26 april 2019 12:45:30.",
    "timestamp": {
      "Time": 1556271999,
      "ServerUrl": "https://metrics.privacybydesign.foundation/atum",
      "Sig": {
        "Alg": "ed25519",
        "Data": "B1vRNosk4094k29T3JIsz1Te/YZEkSKFertuwvvTWUiWx5isZ3AYnc0ufBiL8eYqxtrkKGlhkBvz/NPz8ojIDQ==",
        "PublicKey": "e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8="
      }
    }
  }
`
