const request = {
    "type": "vp_token",
    "dcql_query": {
        "credentials": [
            {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["pbdf.pbdf.email"]
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
                "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["pbdf.pbdf.mobilenumber"]
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
                "options": [
                    [
                        "32f54163-7166-48f1-93d8-ff217bdb0653"
                    ]
                ],
                "purpose": "We need to verify your identity"
            }
        ]
    },
    "nonce": "nonce",
    "jar_mode": "by_reference",
    "request_uri_method": "post"
}

function openApp(data) {
    const params = new URLSearchParams(data)
    const customUrl = `eudi-openid4vp://?${params}`
    window.location.href = customUrl
}

let transactionId = ""

document.getElementById("get-wallet-response").addEventListener("click", async function() {
    console.log("getting wallet response")

    try {
        const result = await fetch(`http://localhost:8080/ui/presentations/${transactionId}`)
        console.log(`wallet response: ${result}`)
        document.getElementById("wallet-response").textContent = `wallet response: ${JSON.stringify(await result.json())}`
    } catch (error) {
        console.error(error)
        document.getElementById("wallet-response").textContent = `error: ${error}`
    }
})

document.getElementById("start-session").addEventListener("click", function() {
    fetch(
        "http://localhost:8080/ui/presentations",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(request),
        }
    ).then((response) => {
        if (!response.ok) {
            console.error("error: network response not ok: ", response)
            throw new Error("Network response was not ok")
        }
        return response.json()
    }).then((data) => {
        console.log("data: ", data)
        openApp(data)
        transactionId = data["transaction_id"]
        document.getElementById("wallet-response").textContent = `url: http://localhost:8080/ui/presentations/${transactionId}`

    })
        .catch((error) => {
            console.error("error: ", error)
        })

});

