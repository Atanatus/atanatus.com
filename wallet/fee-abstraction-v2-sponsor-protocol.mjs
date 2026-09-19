export const ATAN_FEE_V2_PROTOCOL_VERSION =
  '2.0.0';

export const ATAN_FEE_V2_AUTH_SCHEME =
  'BCH_SIGNMESSAGE_P2PKH_V1';

export const ATAN_FEE_V2_QUOTE_MESSAGE_PREFIX =
  'ATAN_FEE_ABSTRACTION_V2_QUOTE:';

const HEX64 =
  /^[0-9a-f]{64}$/;

const OUTPOINT =
  /^[0-9a-f]{64}:[0-9]+$/;

function fail(
  code
){
  throw new Error(
    code
  );
}

function clone(
  value
){
  return structuredClone(
    value
  );
}

function requireObject(
  value,
  field
){
  if(
    !value ||
    typeof value !==
      'object' ||
    Array.isArray(
      value
    )
  ){
    fail(
      `INVALID_OBJECT:${field}`
    );
  }
}

function requireString(
  value,
  field
){
  if(
    typeof value !==
      'string' ||
    value.length ===
      0
  ){
    fail(
      `INVALID_STRING:${field}`
    );
  }
}

function requireHex64(
  value,
  field
){
  if(
    typeof value !==
      'string' ||
    !HEX64.test(
      value
    )
  ){
    fail(
      `INVALID_HEX64:${field}`
    );
  }
}

function requireOutpoint(
  value,
  field
){
  if(
    typeof value !==
      'string' ||
    !OUTPOINT.test(
      value
    )
  ){
    fail(
      `INVALID_OUTPOINT:${field}`
    );
  }
}

function requireSafeInteger(
  value,
  field,
  minimum = 0
){
  if(
    !Number.isSafeInteger(
      value
    ) ||
    value < minimum
  ){
    fail(
      `INVALID_SAFE_INTEGER:${field}`
    );
  }
}

function requireUintString(
  value,
  field,
  allowZero = false
){
  if(
    typeof value !==
      'string' ||
    !/^[0-9]+$/.test(
      value
    )
  ){
    fail(
      `INVALID_UINT_STRING:${field}`
    );
  }

  const parsed =
    BigInt(
      value
    );

  if(
    allowZero
      ? parsed < 0n
      : parsed <= 0n
  ){
    fail(
      `INVALID_UINT_RANGE:${field}`
    );
  }
}

function canonicalValue(
  value
){
  if(value === null){
    fail(
      'NULL_FORBIDDEN'
    );
  }

  if(
    Array.isArray(
      value
    )
  ){
    return (
      '[' +
      value
        .map(
          canonicalValue
        )
        .join(
          ','
        ) +
      ']'
    );
  }

  if(
    typeof value ===
      'object'
  ){
    const keys =
      Object
        .keys(
          value
        )
        .sort();

    return (
      '{' +
      keys
        .map(
          key =>
            JSON.stringify(
              key
            ) +
            ':' +
            canonicalValue(
              value[
                key
              ]
            )
        )
        .join(
          ','
        ) +
      '}'
    );
  }

  if(
    typeof value ===
      'number'
  ){
    if(
      !Number.isSafeInteger(
        value
      )
    ){
      fail(
        'FLOAT_OR_UNSAFE_NUMBER_FORBIDDEN'
      );
    }

    return String(
      value
    );
  }

  if(
    typeof value ===
      'string' ||
    typeof value ===
      'boolean'
  ){
    return JSON.stringify(
      value
    );
  }

  fail(
    `UNSUPPORTED_CANONICAL_TYPE:${typeof value}`
  );
}

export function canonicalizeV2(
  value
){
  return canonicalValue(
    value
  );
}

function bytesToHex(
  bytes
){
  return Array
    .from(
      bytes
    )
    .map(
      byte =>
        byte
          .toString(
            16
          )
          .padStart(
            2,
            '0'
          )
    )
    .join(
      ''
    );
}

export async function sha256HexV2(
  text
){
  const subtle =
    globalThis
      .crypto
      ?.subtle;

  if(!subtle){
    fail(
      'WEBCRYPTO_SUBTLE_REQUIRED'
    );
  }

  const bytes =
    new TextEncoder()
      .encode(
        String(
          text
        )
      );

  const digest =
    await subtle.digest(
      'SHA-256',
      bytes
    );

  return bytesToHex(
    new Uint8Array(
      digest
    )
  );
}

async function hashObject(
  value
){
  return sha256HexV2(
    canonicalizeV2(
      value
    )
  );
}

function requestPayload(
  value
){
  const result =
    clone(
      value
    );

  delete result.request_id;

  return result;
}

function quotePayload(
  value
){
  const result =
    clone(
      value
    );

  delete result.quote_id;
  delete result.authentication;

  return result;
}

function reservationPayload(
  value
){
  const result =
    clone(
      value
    );

  delete result.reservation_id;

  return result;
}

function acceptancePayload(
  value
){
  const result =
    clone(
      value
    );

  delete result.acceptance_id;

  return result;
}

export async function createFeeRequestV2({
  network,
  token_category,
  recipient,
  payment_sats,
  network_fee_sats,
  valid_until_height,
  request_nonce
}){
  requireString(
    network,
    'network'
  );

  requireHex64(
    token_category,
    'token_category'
  );

  requireString(
    recipient,
    'recipient'
  );

  requireUintString(
    payment_sats,
    'payment_sats'
  );

  requireUintString(
    network_fee_sats,
    'network_fee_sats'
  );

  requireSafeInteger(
    valid_until_height,
    'valid_until_height',
    1
  );

  requireString(
    request_nonce,
    'request_nonce'
  );

  const request = {
    protocol_version:
      ATAN_FEE_V2_PROTOCOL_VERSION,

    network,

    token_category,

    recipient,

    payment_sats,

    fee_policy: {
      mode:
        'EXACT_COMMITTED_FEE',

      network_fee_sats
    },

    valid_until_height,

    request_nonce
  };

  return {
    ...request,

    request_id:
      await hashObject(
        requestPayload(
          request
        )
      )
  };
}

export async function validateFeeRequestV2(
  request
){
  requireObject(
    request,
    'request'
  );

  if(
    request.protocol_version !==
    ATAN_FEE_V2_PROTOCOL_VERSION
  ){
    fail(
      'UNSUPPORTED_PROTOCOL_VERSION'
    );
  }

  requireString(
    request.network,
    'network'
  );

  requireHex64(
    request.token_category,
    'token_category'
  );

  requireString(
    request.recipient,
    'recipient'
  );

  requireUintString(
    request.payment_sats,
    'payment_sats'
  );

  requireObject(
    request.fee_policy,
    'fee_policy'
  );

  if(
    request
      .fee_policy
      .mode !==
    'EXACT_COMMITTED_FEE'
  ){
    fail(
      'UNSUPPORTED_FEE_POLICY'
    );
  }

  requireUintString(
    request
      .fee_policy
      .network_fee_sats,
    'network_fee_sats'
  );

  requireSafeInteger(
    request.valid_until_height,
    'valid_until_height',
    1
  );

  requireString(
    request.request_nonce,
    'request_nonce'
  );

  requireHex64(
    request.request_id,
    'request_id'
  );

  const expected =
    await hashObject(
      requestPayload(
        request
      )
    );

  if(
    expected !==
    request.request_id
  ){
    fail(
      'REQUEST_ID_MISMATCH'
    );
  }

  return true;
}

export async function createSponsorQuoteV2({
  request,
  sponsor_id,
  sponsor_funding_outpoint,
  sponsor_signer_address,
  sponsor_token_address,
  sponsor_bch_change_address,
  token_cost_base,
  valid_until_height,
  quote_nonce,
  authentication
}){
  await validateFeeRequestV2(
    request
  );

  requireString(
    sponsor_id,
    'sponsor_id'
  );

  requireOutpoint(
    sponsor_funding_outpoint,
    'sponsor_funding_outpoint'
  );

  requireString(
    sponsor_signer_address,
    'sponsor_signer_address'
  );

  requireString(
    sponsor_token_address,
    'sponsor_token_address'
  );

  requireString(
    sponsor_bch_change_address,
    'sponsor_bch_change_address'
  );

  requireUintString(
    token_cost_base,
    'token_cost_base',
    true
  );

  requireSafeInteger(
    valid_until_height,
    'valid_until_height',
    1
  );

  requireString(
    quote_nonce,
    'quote_nonce'
  );

  requireObject(
    authentication,
    'authentication'
  );

  const quote = {
    protocol_version:
      ATAN_FEE_V2_PROTOCOL_VERSION,

    request_id:
      request.request_id,

    network:
      request.network,

    sponsor_id,

    sponsor_funding_outpoint,

    sponsor_signer_address,

    sponsor_token_address,

    sponsor_bch_change_address,

    network_fee_sats:
      request
        .fee_policy
        .network_fee_sats,

    token_cost_base,

    valid_until_height,

    quote_nonce
  };

  return {
    ...quote,

    quote_id:
      await hashObject(
        quotePayload(
          quote
        )
      ),

    authentication:
      clone(
        authentication
      )
  };
}

export async function validateSponsorQuoteV2(
  request,
  quote
){
  await validateFeeRequestV2(
    request
  );

  requireObject(
    quote,
    'quote'
  );

  if(
    quote.protocol_version !==
    ATAN_FEE_V2_PROTOCOL_VERSION
  ){
    fail(
      'QUOTE_PROTOCOL_VERSION_INVALID'
    );
  }

  if(
    quote.request_id !==
    request.request_id
  ){
    fail(
      'QUOTE_REQUEST_BINDING_FAILED'
    );
  }

  if(
    quote.network !==
    request.network
  ){
    fail(
      'QUOTE_NETWORK_BINDING_FAILED'
    );
  }

  requireString(
    quote.sponsor_id,
    'sponsor_id'
  );

  requireOutpoint(
    quote.sponsor_funding_outpoint,
    'sponsor_funding_outpoint'
  );

  requireString(
    quote.sponsor_signer_address,
    'sponsor_signer_address'
  );

  requireString(
    quote.sponsor_token_address,
    'sponsor_token_address'
  );

  requireString(
    quote.sponsor_bch_change_address,
    'sponsor_bch_change_address'
  );

  requireUintString(
    quote.network_fee_sats,
    'network_fee_sats'
  );

  if(
    quote.network_fee_sats !==
    request
      .fee_policy
      .network_fee_sats
  ){
    fail(
      'QUOTE_FEE_BINDING_FAILED'
    );
  }

  requireUintString(
    quote.token_cost_base,
    'token_cost_base',
    true
  );

  requireSafeInteger(
    quote.valid_until_height,
    'valid_until_height',
    1
  );

  requireString(
    quote.quote_nonce,
    'quote_nonce'
  );

  requireHex64(
    quote.quote_id,
    'quote_id'
  );

  requireObject(
    quote.authentication,
    'authentication'
  );

  if(
    quote
      .authentication
      .scheme !==
    ATAN_FEE_V2_AUTH_SCHEME
  ){
    fail(
      'QUOTE_AUTH_SCHEME_INVALID'
    );
  }

  if(
    quote
      .authentication
      .signer_address !==
    quote.sponsor_signer_address
  ){
    fail(
      'QUOTE_AUTH_SIGNER_MISMATCH'
    );
  }

  requireString(
    quote
      .authentication
      .signature_base64,
    'signature_base64'
  );

  const expected =
    await hashObject(
      quotePayload(
        quote
      )
    );

  if(
    expected !==
    quote.quote_id
  ){
    fail(
      'QUOTE_ID_MISMATCH'
    );
  }

  return true;
}

export function sponsorQuoteMessageV2(
  quoteId
){
  requireHex64(
    quoteId,
    'quote_id'
  );

  return (
    ATAN_FEE_V2_QUOTE_MESSAGE_PREFIX +
    quoteId
  );
}

export function verifySponsorQuoteSignatureV2({
  quote,
  mainnet
}){
  requireObject(
    quote,
    'quote'
  );

  requireObject(
    mainnet,
    'mainnet'
  );

  if(
    !mainnet.SignedMessage ||
    typeof mainnet
      .SignedMessage
      .verify !==
      'function'
  ){
    fail(
      'MAINNET_SIGNEDMESSAGE_VERIFY_REQUIRED'
    );
  }

  const message =
    sponsorQuoteMessageV2(
      quote.quote_id
    );

  const result =
    mainnet
      .SignedMessage
      .verify(
        message,
        quote
          .authentication
          .signature_base64,
        quote
          .authentication
          .signer_address
      );

  if(
    !result ||
    result.valid !==
      true
  ){
    return false;
  }

  return true;
}

function requireQuoteFacts(
  quote,
  facts
){
  requireObject(
    facts,
    'quote_facts'
  );

  const fields = [
    'authentication_valid',
    'funding_outpoint_unspent',
    'signer_controls_funding_outpoint',
    'token_receive_address_token_aware'
  ];

  for(
    const field
    of fields
  ){
    if(
      typeof facts[
        field
      ] !==
      'boolean'
    ){
      fail(
        `MISSING_BOOLEAN_FACT:${field}`
      );
    }
  }

  if(
    facts.authentication_valid !==
      true
  ){
    fail(
      `QUOTE_AUTH_INVALID:${quote.quote_id}`
    );
  }

  if(
    facts.funding_outpoint_unspent !==
      true
  ){
    fail(
      `QUOTE_FUNDING_SPENT:${quote.quote_id}`
    );
  }

  if(
    facts.signer_controls_funding_outpoint !==
      true
  ){
    fail(
      `QUOTE_SIGNER_CONTROL_INVALID:${quote.quote_id}`
    );
  }

  if(
    facts.token_receive_address_token_aware !==
      true
  ){
    fail(
      `QUOTE_TOKEN_ADDRESS_NOT_TOKEN_AWARE:${quote.quote_id}`
    );
  }

  return true;
}

export async function quoteValidityV2(
  request,
  quote,
  facts,
  currentHeight
){
  try{
    await validateSponsorQuoteV2(
      request,
      quote
    );

    requireSafeInteger(
      currentHeight,
      'currentHeight',
      0
    );

    if(
      currentHeight >
      request.valid_until_height
    ){
      fail(
        'REQUEST_EXPIRED'
      );
    }

    if(
      currentHeight >
      quote.valid_until_height
    ){
      fail(
        'QUOTE_EXPIRED'
      );
    }

    requireQuoteFacts(
      quote,
      facts
    );

    return {
      valid:
        true,

      reason:
        'VALID'
    };
  }
  catch(error){
    return {
      valid:
        false,

      reason:
        error
          ?.message ||
        String(
          error
        )
    };
  }
}

export async function selectSponsorQuoteV2({
  request,
  quotes,
  factsByQuoteId,
  currentHeight
}){
  await validateFeeRequestV2(
    request
  );

  requireSafeInteger(
    currentHeight,
    'currentHeight',
    0
  );

  requireObject(
    factsByQuoteId,
    'factsByQuoteId'
  );

  if(
    !Array.isArray(
      quotes
    ) ||
    quotes.length ===
      0
  ){
    fail(
      'NO_QUOTES'
    );
  }

  const evaluation = [];

  for(
    const quote
    of quotes
  ){
    const validity =
      await quoteValidityV2(
        request,
        quote,
        factsByQuoteId[
          quote?.quote_id
        ],
        currentHeight
      );

    evaluation.push({
      quote_id:
        quote?.quote_id ??
        null,

      sponsor_id:
        quote?.sponsor_id ??
        null,

      token_cost_base:
        quote?.token_cost_base ??
        null,

      eligible:
        validity.valid,

      reason:
        validity.reason
    });
  }

  const eligible =
    quotes
      .filter(
        quote =>
          evaluation
            .find(
              item =>
                item.quote_id ===
                quote.quote_id
            )
            ?.eligible ===
          true
      )
      .slice()
      .sort(
        (
          left,
          right
        ) => {
          const leftCost =
            BigInt(
              left.token_cost_base
            );

          const rightCost =
            BigInt(
              right.token_cost_base
            );

          if(
            leftCost <
            rightCost
          ){
            return -1;
          }

          if(
            leftCost >
            rightCost
          ){
            return 1;
          }

          return left
            .quote_id
            .localeCompare(
              right.quote_id
            );
        }
      );

  if(
    eligible.length ===
      0
  ){
    fail(
      'NO_VALID_QUOTES'
    );
  }

  return {
    selected_quote:
      clone(
        eligible[
          0
        ]
      ),

    evaluation
  };
}

export async function createReservationV2({
  request,
  quote,
  current_height,
  valid_until_height,
  reservation_nonce,
  facts
}){
  await validateFeeRequestV2(
    request
  );

  await validateSponsorQuoteV2(
    request,
    quote
  );

  requireSafeInteger(
    current_height,
    'current_height',
    0
  );

  requireSafeInteger(
    valid_until_height,
    'valid_until_height',
    1
  );

  requireString(
    reservation_nonce,
    'reservation_nonce'
  );

  if(
    valid_until_height <
    current_height
  ){
    fail(
      'RESERVATION_ALREADY_EXPIRED'
    );
  }

  if(
    valid_until_height >
    quote.valid_until_height
  ){
    fail(
      'RESERVATION_EXCEEDS_QUOTE_EXPIRY'
    );
  }

  if(
    valid_until_height >
    request.valid_until_height
  ){
    fail(
      'RESERVATION_EXCEEDS_REQUEST_EXPIRY'
    );
  }

  const validity =
    await quoteValidityV2(
      request,
      quote,
      facts,
      current_height
    );

  if(!validity.valid){
    fail(
      `RESERVATION_QUOTE_INVALID:${validity.reason}`
    );
  }

  const reservation = {
    protocol_version:
      ATAN_FEE_V2_PROTOCOL_VERSION,

    request_id:
      request.request_id,

    quote_id:
      quote.quote_id,

    sponsor_id:
      quote.sponsor_id,

    sponsor_funding_outpoint:
      quote.sponsor_funding_outpoint,

    created_height:
      current_height,

    valid_until_height,

    reservation_nonce
  };

  return {
    ...reservation,

    reservation_id:
      await hashObject(
        reservationPayload(
          reservation
        )
      )
  };
}

export async function validateReservationV2({
  request,
  quote,
  reservation,
  currentHeight,
  facts
}){
  requireObject(
    reservation,
    'reservation'
  );

  requireHex64(
    reservation.reservation_id,
    'reservation_id'
  );

  const expected =
    await hashObject(
      reservationPayload(
        reservation
      )
    );

  if(
    expected !==
    reservation.reservation_id
  ){
    fail(
      'RESERVATION_ID_MISMATCH'
    );
  }

  if(
    reservation.request_id !==
    request.request_id
  ){
    fail(
      'RESERVATION_REQUEST_MISMATCH'
    );
  }

  if(
    reservation.quote_id !==
    quote.quote_id
  ){
    fail(
      'RESERVATION_QUOTE_MISMATCH'
    );
  }

  if(
    reservation
      .sponsor_funding_outpoint !==
    quote
      .sponsor_funding_outpoint
  ){
    fail(
      'RESERVATION_OUTPOINT_MISMATCH'
    );
  }

  if(
    currentHeight >
    reservation.valid_until_height
  ){
    fail(
      'RESERVATION_EXPIRED'
    );
  }

  const validity =
    await quoteValidityV2(
      request,
      quote,
      facts,
      currentHeight
    );

  if(!validity.valid){
    fail(
      `RESERVED_QUOTE_INVALID:${validity.reason}`
    );
  }

  return true;
}

export async function createAcceptanceV2({
  request,
  quote,
  reservation,
  current_height,
  acceptance_nonce,
  facts
}){
  requireSafeInteger(
    current_height,
    'current_height',
    0
  );

  requireString(
    acceptance_nonce,
    'acceptance_nonce'
  );

  await validateReservationV2({
    request,
    quote,
    reservation,
    currentHeight:
      current_height,
    facts
  });

  const acceptance = {
    protocol_version:
      ATAN_FEE_V2_PROTOCOL_VERSION,

    request_id:
      request.request_id,

    quote_id:
      quote.quote_id,

    reservation_id:
      reservation.reservation_id,

    network_fee_sats:
      quote.network_fee_sats,

    token_cost_base:
      quote.token_cost_base,

    accepted_at_height:
      current_height,

    acceptance_nonce
  };

  return {
    ...acceptance,

    acceptance_id:
      await hashObject(
        acceptancePayload(
          acceptance
        )
      )
  };
}
