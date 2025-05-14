const request = {
    "type": "vp_token",
    "dcql_query": {
        "credentials": [
            {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "format": "dc+sd-jwt",
                "meta": {
                    "doctype_value": "eu.europa.ec.eudi.pid.1"
                },
                "claims": [
                    {
                        "path": ["pbdf.pbdf.email.email"]
                    }
                ]
            }
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

document.getElementById("getButton").addEventListener("click", function() {
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
    })
        .catch((error) => {
            console.error("error: ", error)
        })

});

