import { useState } from 'react'
import './App.css'

const request = {
  "type": "vp_token",
  "dcql_query": {
    "credentials": [
      {
        "id": "email",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": ["pbdf.sidn-pbdf.email"]
        },
        "claims": [
          {
            "path": ["email"]
          },
          {
            "path": ["domain"]
          }
        ]
      },
      {
        "id": "mobilenumber",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": ["pbdf.sidn-pbdf.mobilenumber"]
        },
        "claims": [
          {
            "path": ["mobilenumber"]
          }
        ]
      },
      // {
      //     "id": "32f54163-7166-48f1-93d8-ff217bdb0655",
      //     "format": "dc+sd-jwt",
      //     "meta": {
      //         "vct_values": ["pbdf.pbdf.linkedin"]
      //     },
      //     "claims": [
      //         {
      //             "path": ["fullname"]
      //         }
      //     ]
      // }
    ],
    "credential_sets": [
      {
        "options": [["email"], ["mobilenumber"]],
      }
    ]
  },
  "nonce": "nonce",
  "jar_mode": "by_reference",
  "request_uri_method": "post",
  "issuer_chain": "-----BEGIN CERTIFICATE-----\nMIICITCCAcigAwIBAgIUJmW4EIKWApJzMrgBjkLi8AnO3f8wCgYIKoZIzj0EAwIw\nQTELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxIzAhBgNVBAMMGm9wZW5pZDR2\nYy5zdGFnaW5nLnlpdmkuYXBwMB4XDTI1MDYwMzA4MzQxNloXDTM1MDYwMTA4MzQx\nNlowQTELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxIzAhBgNVBAMMGm9wZW5p\nZDR2Yy5zdGFnaW5nLnlpdmkuYXBwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\nSr7bMrDTDe+R/HI1wywYtEYr+DJa5HdTnI8dsjZer6grPyZ4vxTeOmdjU9wp0Wkz\nfONmyk8xsPePon4AhwCK+aOBnTCBmjAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIF\noDATBgNVHSUEDDAKBggrgQICAAABBzBJBgNVHREEQjBAhiJodHRwczovL29wZW5p\nZDR2Yy5zdGFnaW5nLnlpdmkuYXBwghpvcGVuaWQ0dmMuc3RhZ2luZy55aXZpLmFw\ncDAdBgNVHQ4EFgQUNFp/ITlrNmraTYMsN3jijYUmLXswCgYIKoZIzj0EAwIDRwAw\nRAIgYDuyJIVAY/2XEoxU1802ztuawBc618Ygyz39PinWrk0CIH2kc3A3LsnYDWun\n6PY2x495dIntuwQAXq9ThYjvtOCE\n-----END CERTIFICATE-----",
}

function openApp(data: any) {
  const params = new URLSearchParams(data)
  const customUrl = `eudi-openid4vp://?${params}`
  window.location.href = customUrl
}

enum FrontendState {
  Pending,
  Polling,
  Done,
}

interface DisclosureContent {
  key: string;
  value: string;
}

function parseSdJwtVc(sdjwt: string): DisclosureContent[] {
  const components = sdjwt.split("~")
  const disclosures = (components.slice(1, components.length - 1).map((value) => {
    return atob(value)
  }) as string[])


  return disclosures.map((value) => {
    const res = JSON.parse(value) as string[]
    return { key: res[1], value: res[2] }
  })
}

interface WalletResponse {
  vp_token: Map<string, string>,
}

function App() {
  const [frontendState, setFrontendState] = useState(FrontendState.Pending)
  const [pollingCallbackId, setPollingCallbackId] = useState(0)
  const [walletResponse, setWalletResponse] = useState<DisclosureContent[][]>([])

  const startSession = async () => {
    const response = await fetch(
      "http://localhost:8080/ui/presentations",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      }
    )
    const json = await response.json()
    console.log(`response: ${json}`)
    openApp(json)
    setFrontendState(FrontendState.Polling)

    const transactionId = json["transaction_id"]
    const id = setInterval(() => {
      (async () => {
        const result = await fetch(`http://localhost:8080/ui/presentations/${transactionId}`)

        if (result.status == 200) {
          setFrontendState(FrontendState.Done)
          clearInterval(id)
          const response = await result.json()
          const entries = new Map<string, string>(Object.entries(response["vp_token"]))
          const parsed = Array.from(entries, ([_, value]) => {
            return parseSdJwtVc(value)
          })
          setWalletResponse(parsed)
        }
      })()

    }, 500)

    setPollingCallbackId(id)
  }

  const cancel = () => {
    setFrontendState(FrontendState.Pending)
    clearInterval(pollingCallbackId)
  }

  const reset = () => setFrontendState(FrontendState.Pending)

  return (
    <>
      <h2 className="text-3xl">Yivi OpenID4VP Verifier</h2>
      {frontendState == FrontendState.Pending && <button className="m-5" onClick={startSession}>Start Session</button>}
      {frontendState == FrontendState.Polling && <button className="m-5" onClick={cancel}>Cancel</button>}
      {frontendState == FrontendState.Done &&
        <div>
          <WalletResponseView disclosures={walletResponse} />
          <button className="m-5" onClick={reset}>Reset</button>
        </div>}
    </>
  )
}

interface WalletResponseViewProps {
  disclosures: DisclosureContent[][]
}

const WalletResponseView = (disclosures: WalletResponseViewProps) => {
  const discs = disclosures.disclosures.flat()
  return (
    <div className="max-w-md mx-auto mt-6 border border-gray-200 rounded-md shadow-sm">
      <dl className="divide-y divide-gray-200">
        {discs.map(({ key, value }) => (
          <div key={key} className="flex justify-between px-4 py-3 bg-white">
            <dt className="text-gray-600 font-medium">{key}</dt>
            <dd className="text-gray-900">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export default App
