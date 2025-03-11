import { check, fail, sleep } from 'k6';
import http from 'k6/http';

const url = __ENV.URL;
const token = __ENV.TOKEN;

export const options = {
  minIterationDuration: '30s',
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

export default function () {
  const newSessionResp = http.post(`${url}/session`, JSON.stringify({
    "@context": "https://irma.app/ld/request/disclosure/v2",
    "disclose": [
      [
        ["irma-demo.sidn-pbdf.email.email"]
      ]
    ]
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': token,
    },
  });
  checkResponse(newSessionResp);

  const sessionPackage = newSessionResp.json();
  const sessionPtrUrl = sessionPackage.sessionPtr.u;

  for (let i = 0; i < 10; i++) {
    let statusResp = http.get(`${sessionPtrUrl}/status`);
    checkResponse(statusResp, 'INITIALIZED');
    sleep(1);
  }

  const sessionResp = http.get(sessionPtrUrl, {
    headers: {
      'Authorization': token,
      'X-IRMA-MinProtocolVersion': '2.8',
      'X-IRMA-MaxProtocolVersion': '2.8',
    },
  });
  checkResponse(sessionResp, '"protocolVersion":"2.8"');

  for (let i = 0; i < 20; i++) {
    let statusResp = http.get(`${sessionPtrUrl}/status`);
    checkResponse(statusResp, 'CONNECTED');
    sleep(1);
  }

  const sessionDeletedResp = http.del(sessionPtrUrl);
  checkResponse(sessionDeletedResp);

  let statusResp = http.get(`${sessionPtrUrl}/status`);
  checkResponse(statusResp, 'CANCELLED');

  let sessionResultResp = http.get(`${url}/session/${sessionPackage.token}/result`);
  checkResponse(sessionResultResp, 'CANCELLED');
}
