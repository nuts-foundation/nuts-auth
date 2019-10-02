package testdata

const InvalidContract = `
    { "thisdatas": "smellz bad"}
	`

const ValidIrmaContract = `
{
  "@context": "https://irma.app/ld/signature/v2",
  "signature": [
    {
      "c": "m40VOyPMjHe5KxKR/TQSWXNHM00muh0pbZFjMd14JWA=",
      "A": "W69bC6pbSJyCFPh4y9kaFpByWkR64a/FNK37pBU5IWpMPWtj3J+/eft0UR2JhF+vdZhKS+78rcYI1gALqxFoWg/FXlLzeP2S/gBHd9aTP71xhtoAzmeRA9tlrETK9rIUUDDhGTdtgJFcNzFFiSxgSveBWv8llRMxw6l/x924hlJt9o1q6snVdyBklumw3vWtG9TFWzJRZK5voCwF9t+abClxOGKX+Dn+1PLXvZCD4kPYNMzorKDcTtE5UNXbBTihOXV7VnArX2B2GTqHGU73QB3XMtDZIqg8IXoxSTL96nzwWXhn4E2RS2nQU6jO3TifoWzqymaSYQehn8JPR3Qr1A==",
      "e_response": "2PzNudT7ROCu6qPYlPtWPff1BT8NbnIBSynV1zdCH8qBkgBnPBK20iEjwsjPmIZ5NoOJyL+MEUe18sJiuppn",
      "v_response": "FZOEu8NIilVRn/gCuh4HaTmrGEjVhdHpKZg/UHuRF+ohM0QjKWVPsyVLQpJMBXBWaqLUi92iFy0ai91DJR+dkbTY8JXPb6Y878uVZ+5yvK8PULLFZ+MvkRLdD7NTICS51+usHxK1NP7r46ao7fvhWijmFoCKF7+4jFjqKn8mG7eLUeskj9v0bN6cZ4xnyC+CZ+0Dfeo/rUi8UgU2eD1F+hdjhxiYxsa8DunHEwjOdxbvtQrimsCkB8pG7ETD6Rxa7zvN67klUdCs075SxHrNDeDiU8MJJ07GEKUpaMobHpiAuHnobikSZXWS1Mj+A3IOpgSKfSZlmfV9g5k16P9rMSIdohUJiMUyhtwsBScQyyQJcRIq2qBtsTEx/9R2TGK7eqxbLgBhVknf/P6tH9CHYXGNsa2+CVihgq9B8mUALnXtrHn8mryQYYlMMFDAfjl5BdV8NDa9NjCvW/DiqH9K5VQN79KtnUAt/z/EGAFHBSEUYjL3/C2mQiXMVlwsqPkeT7JZtWLLytPi3TJ85tW8fQ==",
      "a_responses": {
        "0": "S9tt+rB2Z2tN9qd05GHkkblOMta7v9C34Qxf4lcQmrXbt+tYTr3jSrV8n3yTPM5ylFWjH+41HyVRag8i5LOsnNl+zGKbAbSVwW4=",
        "3": "6/PbsO3gfEtCCpvohvpyuKBeMIUFOQ30kveHdkd+cp1M83A2vec3QwsFvn+6Bo5uxuFafN77IPBHUATY06IYayxgi/1JXffbijhsb+5s8yw="
      },
      "a_disclosed": {
        "1": "AwAKIAAaAAFH2jklUts5iBWSlKLhMjvi",
        "2": "YGBgYGBgYG8="
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
  "nonce": "7Y8eMnUwjkdW3eIlrcSD0Q==",
  "context": "AQ==",
  "message": "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens verpleeghuis De nootjes en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
  "timestamp": {
    "Time": 1569929468,
    "ServerUrl": "https://keyshare.privacybydesign.foundation/atumd/",
    "Sig": {
      "Alg": "ed25519",
      "Data": "ofaPD6qyPJi6Rfs1qUP9MZ5DT32peMa1603sTf83WVZ8IORNs16O95RuRklKnAqo2J+Tk42C8Qxd+07P8pW1Aw==",
      "PublicKey": "MKdXxJxEWPRIwNP7SuvP0J/M/NV51VZvqCyO+7eDwJ8="
    }
  }
}
`

const ForgedIrmaContract = `
{
  "@context": "https://irma.app/ld/signature/v2",
  "signature": [
    {
      "c": "m40VOyPMjHe5KxKR/TQSWXNHM00muh0pbZFjMd14JWa=",
      "A": "W69bC6pbSJyCFPh4y9kaFpByWkR64a/FNK37pBU5IWpMPWtj3J+/eft0UR2JhF+vdZhKS+78rcYI1gALqxFoWg/FXlLzeP2S/gBHd9aTP71xhtoAzmeRA9tlrETK9rIUUDDhGTdtgJFcNzFFiSxgSveBWv8llRMxw6l/x924hlJt9o1q6snVdyBklumw3vWtG9TFWzJRZK5voCwF9t+abClxOGKX+Dn+1PLXvZCD4kPYNMzorKDcTtE5UNXbBTihOXV7VnArX2B2GTqHGU73QB3XMtDZIqg8IXoxSTL96nzwWXhn4E2RS2nQU6jO3TifoWzqymaSYQehn8JPR3Qr1A==",
      "e_response": "2PzNudT7ROCu6qPYlPtWPff1BT8NbnIBSynV1zdCH8qBkgBnPBK20iEjwsjPmIZ5NoOJyL+MEUe18sJiuppn",
      "v_response": "FZOEu8NIilVRn/gCuh4HaTmrGEjVhdHpKZg/UHuRF+ohM0QjKWVPsyVLQpJMBXBWaqLUi92iFy0ai91DJR+dkbTY8JXPb6Y878uVZ+5yvK8PULLFZ+MvkRLdD7NTICS51+usHxK1NP7r46ao7fvhWijmFoCKF7+4jFjqKn8mG7eLUeskj9v0bN6cZ4xnyC+CZ+0Dfeo/rUi8UgU2eD1F+hdjhxiYxsa8DunHEwjOdxbvtQrimsCkB8pG7ETD6Rxa7zvN67klUdCs075SxHrNDeDiU8MJJ07GEKUpaMobHpiAuHnobikSZXWS1Mj+A3IOpgSKfSZlmfV9g5k16P9rMSIdohUJiMUyhtwsBScQyyQJcRIq2qBtsTEx/9R2TGK7eqxbLgBhVknf/P6tH9CHYXGNsa2+CVihgq9B8mUALnXtrHn8mryQYYlMMFDAfjl5BdV8NDa9NjCvW/DiqH9K5VQN79KtnUAt/z/EGAFHBSEUYjL3/C2mQiXMVlwsqPkeT7JZtWLLytPi3TJ85tW8fQ==",
      "a_responses": {
        "0": "S9tt+rB2Z2tN9qd05GHkkblOMta7v9C34Qxf4lcQmrXbt+tYTr3jSrV8n3yTPM5ylFWjH+41HyVRag8i5LOsnNl+zGKbAbSVwW4=",
        "3": "6/PbsO3gfEtCCpvohvpyuKBeMIUFOQ30kveHdkd+cp1M83A2vec3QwsFvn+6Bo5uxuFafN77IPBHUATY06IYayxgi/1JXffbijhsb+5s8yw="
      },
      "a_disclosed": {
        "1": "AwAKIAAaAAFH2jklUts5iBWSlKLhMjvi",
        "2": "YGBgYGBgYG8="
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
  "nonce": "7Y8eMnUwjkdW3eIlrcSD0Q==",
  "context": "AQ==",
  "message": "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens verpleeghuis De nootjes en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
  "timestamp": {
    "Time": 1569929468,
    "ServerUrl": "https://keyshare.privacybydesign.foundation/atumd/",
    "Sig": {
      "Alg": "ed25519",
      "Data": "ofaPD6qyPJi6Rfs1qUP9MZ5DT32peMa1603sTf83WVZ8IORNs16O95RuRklKnAqo2J+Tk42C8Qxd+07P8pW1Aw==",
      "PublicKey": "MKdXxJxEWPRIwNP7SuvP0J/M/NV51VZvqCyO+7eDwJ8="
    }
  }
}
`

const ValidUnknownIrmaContract = `{
  "signature": [
    {
      "c": "1/7H1N1DrhKEkuD28DMPhIcX1eoq7Hhr2Spg4WggRFQ=",
      "A": "z5ywI1Form5PzkNoqPcLcVlQKhD19gZzTJtvx3nPPEVruWStQ72nTwo3hALdJdzUI301ic6M9F9B6YoLc5n1fJAvGFFGdgFir5Az6s5+3jNQMAIdSIqI1mNPrsNUcrY4hxjmBK+LpfXL3IsoPSyGw9S2gYRqjg1luI31yRWcRdFLSYIjfSY5tQAG1EE4UwqhDZGRD/iDxDD5uWk/Z0CbJM5r20Cth+VPJRMQZFy8B8irE8FiZHJMe6dDAYdzAdAPjNWbAFJ4y+7zp3k78OO4zfWCWiiJkQrXksvW3agHGHhuGZs42IrWckAnUc3FpFDpJvB8APEgMWiD/sZ0uBqi/w==",
      "e_response": "HMYVvSItEbtgnd4fIwnsiHBjpoQUdiPKcNKk4zGK0Kv5rShC4idSY4gI3l5EV+r0fBKIT6uArfyeG2Yxqp8B",
      "v_response": "Bk2GXojcbibyanT77BADGJq7OqxqVwvOIokIFCKLeGuNZ1wBzkEyRHe5Dw6IAjJag+9sEWNTQ3Kf9xDtsQ7fvnj1vOdCLmysVqY9n/nihn1qbaCXfb7gkqkwth55e52Gvd9mCDLTGPDPW/Y2fkBuSf+pidhrENOo0dWCwYnINt7HrtKd3BVVK81BzSimqSxpONb6mJeK3TNneqn0cAkLK3//3wI3AmB0NPf8UgzhNaulJKj5mEuz7Kvp/I0fYyWMNAh5rrHqi/kWoGeo7GywHIIrCAUyiZz4ozOYMh67scvsQOmCAs2Jq/vKOazIeqFASD2q6jCvnQ0zCY+VGtmV8SNwwpNeBhR6+nXTehlPZt+4x0mbme3157azfSv/ndLK14iMgfWC1gX8aOiQx/Ctx/6c5RqVFc2XqyEXVyQmUkT7AgTLrTvBq8hmqpfHY2d2kAT7ukAdp+zGDD+bpI0yMYEj8mktPDOmiRqQGeiL43ZJUbrE6YFzRqo9l3Qz8AnbzH3JlqEJnZZHXzs6/Uj30zQ=",
      "a_responses": {
        "0": "GKIQkMWEIDA3NwPkLuj1+9MEFp6licjoDiHRfbyYxrf4C3dCvEZX74ByjmirtYXZuOfpcIicHi8hPEK3ZxrLKzcJbjT+BBiTOUw=",
        "3": "HebCraFeGgQgT5TCwcq23twJSKRSWGrCTHRozyUUmaLCKDwh6rajdvwaqJ/gZLkCJFcvTPQJKb20SjQPDosgg/K/YP19R3H5MRgeUrdQgIU="
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
  "nonce": "dz016mfjw7kITQDWHI9eFg==",
  "context": "AQ==",
  "message": "NL:PgoLogin:v1 Burger geeft aan PGO Helder toestemming om uit zijn/haar naam het Nuts netwerk te bevragen. Deze toestemming is geldig van woensdag, 1 mei 2019 16:47:52 tot woensdag, 1 mei 2019 17:47:52.",
  "timestamp": {
    "Time": 1556722159,
    "ServerUrl": "https://metrics.privacybydesign.foundation/atum",
    "Sig": {
      "Alg": "ed25519",
      "Data": "D5UUvzEkdItSiQYphP+XLv/EorpzCLrF5MYzkY4DuURYTDwldJ5/YHmT4vgbiprcgxAI+m+qQjbydCVjM/qQAw==",
      "PublicKey": "e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8="
    }
  }
} 
`
