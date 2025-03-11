import { check, fail } from 'k6';
import { instance, vu } from 'k6/execution';
import http from 'k6/http';

const url = __ENV.URL;
const issuerID = __ENV.ISSUER_ID;

export const options = {
  minIterationDuration: '1s',
  setupTimeout: '5m', // To make sure there is enough time to make accounts for all VUs.
  thresholds: {
    http_req_failed: ['rate<0.01'], // http errors should be less than 1%
    http_req_duration: ['p(95)<200'], // 95% of requests should be below 200ms
  },
};

function checkResponse(response, expectedOutput = '') {
  const checkOutput = check(response, {
    'verify response': (r) => r.error === '',
    'verify status code': (r) => r.status === 200,
    'verify body': (r) => r.body != null && r.body.includes(expectedOutput),
  });
  if (!checkOutput) fail(`unexpected response: url ${response.request.url}, status ${response.status}, error "${response.error}", body "${response.body}"`);
}

export function setup() {
  if (!url || !issuerID) {
    fail('Must specify URL and ISSUER_ID options via environment variables');
  }

  const registerPayload = {
    language: 'en',
    pin: '0kO3xbCrWMK1336eKzI3KOKWWogGb/oW4xErUd5rwFI=\n',
  };

  const registerPayloadStr = JSON.stringify(registerPayload);

  // An IRMA account cannot be used in parallel, so every VU needs its own account.
  const testAccounts = Array.from({ length: instance.vusInitialized }, () => {
    const registerResp = http.post(`${url}/client/register`, registerPayloadStr, {
      headers: {
        'Content-Type': 'application/json',
      },
    });
    checkResponse(registerResp);

    const sessionResp = http.get(registerResp.json().u, {
      headers: {
        'Authorization': '12345',
        'X-IRMA-MinProtocolVersion': '2.8',
        'X-IRMA-MaxProtocolVersion': '2.8',
      },
    });
    checkResponse(sessionResp);

    checkResponse(http.del(registerResp.json().u));

    return {
      id: Object.values(sessionResp.json().request.credentials[0].attributes)[0],
      pin: registerPayload.pin,
    };
  });

  return {
    testAccounts,
  };
}

export default function ({ testAccounts }) {
  const testAccount = testAccounts[vu.idInTest - 1];

  const pinResp = http.post(`${url}/users/verify/pin`, JSON.stringify(testAccount));
  checkResponse(pinResp);

  const proveParams = {
    headers: {
      'X-IRMA-Keyshare-Username': testAccount.id,
      'Authorization': pinResp.json().message,
    },
  };

  checkResponse(http.post(`${url}/prove/getCommitments`, `["${issuerID}-0"]`, proveParams));

  checkResponse(http.post(`${url}/prove/getResponse`, '"5adEmlEg9U2zjNlPxyPvRym2AzWkBo4kIZJ7ytNg0q0="', proveParams));
}
