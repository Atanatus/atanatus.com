export const ATAN_FEE_V2_SPONSOR_TRANSPORT_CLIENT_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_PRODUCTION_SPONSOR_ORIGIN =
  'https://sponsor.atanatus.com';

function fail(code){
  throw new Error(code);
}

function assertObject(value,label){
  if(
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ){
    fail(`SPONSOR_TRANSPORT_${label}_OBJECT_REQUIRED`);
  }

  return value;
}

function normalizeBaseUrl(
  value,
  allowInsecureLoopback
){
  const url =
    new URL(String(value));

  const production =
    url.origin ===
    ATAN_FEE_V2_PRODUCTION_SPONSOR_ORIGIN;

  const stagedLoopback =
    allowInsecureLoopback === true &&
    url.protocol === 'http:' &&
    (
      url.hostname === '127.0.0.1' ||
      url.hostname === 'localhost'
    );

  if(!production && !stagedLoopback){
    fail('SPONSOR_TRANSPORT_ORIGIN_NOT_ALLOWED');
  }

  if(
    production &&
    url.protocol !== 'https:'
  ){
    fail('SPONSOR_TRANSPORT_PRODUCTION_HTTPS_REQUIRED');
  }

  return url.origin;
}

function joinUrl(
  baseUrl,
  path
){
  if(
    typeof path !== 'string' ||
    !path.startsWith('/')
  ){
    fail('SPONSOR_TRANSPORT_PATH_INVALID');
  }

  return baseUrl + path;
}

async function parseJsonResponse(
  response
){
  const text =
    await response.text();

  let payload =
    null;

  if(text.length > 0){
    try{
      payload =
        JSON.parse(text);
    }
    catch{
      fail('SPONSOR_TRANSPORT_NON_JSON_RESPONSE');
    }
  }

  return {
    response,
    payload
  };
}

export function createSponsorHttpsClient({
  baseUrl =
    ATAN_FEE_V2_PRODUCTION_SPONSOR_ORIGIN,

  allowInsecureLoopback =
    false,

  fetchImpl =
    globalThis.fetch
} = {}){
  if(typeof fetchImpl !== 'function'){
    fail('SPONSOR_TRANSPORT_FETCH_REQUIRED');
  }

  const normalizedBaseUrl =
    normalizeBaseUrl(
      baseUrl,
      allowInsecureLoopback
    );

  async function request(
    method,
    path,
    body = undefined,
    idempotencyKey = undefined
  ){
    const headers = {
      'Accept':
        'application/json'
    };

    let payloadBody =
      undefined;

    if(body !== undefined){
      headers['Content-Type'] =
        'application/json';

      payloadBody =
        JSON.stringify(
          assertObject(
            body,
            'BODY'
          )
        );
    }

    if(idempotencyKey !== undefined){
      const key =
        String(idempotencyKey);

      if(
        key.length < 16 ||
        key.length > 128
      ){
        fail(
          'SPONSOR_TRANSPORT_IDEMPOTENCY_KEY_INVALID'
        );
      }

      headers['Idempotency-Key'] =
        key;
    }

    const response =
      await fetchImpl(
        joinUrl(
          normalizedBaseUrl,
          path
        ),
        {
          method,
          headers,
          body:
            payloadBody,
          credentials:
            'omit',
          cache:
            'no-store',
          redirect:
            'error'
        }
      );

    const parsed =
      await parseJsonResponse(
        response
      );

    return {
      ok:
        response.ok,

      status:
        response.status,

      payload:
        parsed.payload,

      baseUrl:
        normalizedBaseUrl
    };
  }

  return Object.freeze({
    version:
      ATAN_FEE_V2_SPONSOR_TRANSPORT_CLIENT_VERSION,

    baseUrl:
      normalizedBaseUrl,

    productionOrigin:
      ATAN_FEE_V2_PRODUCTION_SPONSOR_ORIGIN,

    async health(){
      const result =
        await request(
          'GET',
          '/v2/health'
        );

      if(
        !result.ok ||
        result.status !== 200
      ){
        fail(
          'SPONSOR_TRANSPORT_HEALTH_FAILED'
        );
      }

      return result;
    },

    async quote(
      feeRequest
    ){
      return request(
        'POST',
        '/v2/quote',
        feeRequest
      );
    },

    async reserve(
      reservationRequest,
      idempotencyKey
    ){
      return request(
        'POST',
        '/v2/reserve',
        reservationRequest,
        idempotencyKey
      );
    },

    async accept(
      acceptanceRequest,
      idempotencyKey
    ){
      return request(
        'POST',
        '/v2/accept',
        acceptanceRequest,
        idempotencyKey
      );
    },

    async sponsorSign(){
      fail(
        'W62D_TRANSACTION_SIGNING_DISABLED'
      );
    },

    async broadcast(){
      fail(
        'W62D_TRANSACTION_BROADCAST_DISABLED'
      );
    }
  });
}