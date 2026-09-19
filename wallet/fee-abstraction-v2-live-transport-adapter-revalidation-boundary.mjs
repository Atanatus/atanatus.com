import crypto from 'node:crypto';

import {
  verifyDisconnectedTransportHandoffReceiptV2
} from './fee-abstraction-v2-atomic-broadcast-claim-transport-handoff-shadow.mjs';

export const ATAN_FEE_V2_W30_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_W30_LIVE_AUTH_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_LIVE_TRANSPORT_AUTHORIZATION';

export const ATAN_FEE_V2_W30_ADMISSION_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_LIVE_TRANSPORT_ADMISSION_BOUNDARY';

export const ATAN_FEE_V2_W30_LIVE_AUTH_SCOPE =
  'LIVE_TRANSPORT_SINGLE_BROADCAST';

export const ATAN_FEE_V2_W30_SIGNATURE_SCHEME =
  'BCH_SIGNMESSAGE_P2PKH_V1';

export const ATAN_FEE_V2_W30_TRANSPORT_PROFILE =
  'ATAN_FEE_ABSTRACTION_V2_BROADCAST_TRANSPORT_V1';

export const ATAN_FEE_V2_W30_PREFLIGHT_OBSERVER =
  'BCHN_MAINNET_READONLY_OBSERVER';

function fail(code){
  throw new Error(code);
}

function requireObject(value, name){
  if(
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ){
    fail(
      `${name.toUpperCase()}_OBJECT_REQUIRED`
    );
  }
}

function requireString(value, name){
  if(
    typeof value !== 'string' ||
    value.length === 0
  ){
    fail(
      `${name.toUpperCase()}_STRING_REQUIRED`
    );
  }

  return value;
}

function requireHash(value, name){
  const text =
    requireString(
      value,
      name
    ).toLowerCase();

  if(!/^[0-9a-f]{64}$/.test(text)){
    fail(
      `${name.toUpperCase()}_HASH_INVALID`
    );
  }

  return text;
}

function requireHeight(value, name){
  const number =
    Number(value);

  if(
    !Number.isSafeInteger(number) ||
    number < 0
  ){
    fail(
      `${name.toUpperCase()}_HEIGHT_INVALID`
    );
  }

  return number;
}

function requireNonce(value, name){
  const text =
    requireString(
      value,
      name
    );

  if(text.length < 16){
    fail(
      `${name.toUpperCase()}_TOO_SHORT`
    );
  }

  return text;
}

function requireMainnetAddress(value){
  const text =
    requireString(
      value,
      'owner_signer_address'
    );

  if(!text.startsWith('bitcoincash:')){
    fail(
      'W30_OWNER_SIGNER_ADDRESS_MAINNET_REQUIRED'
    );
  }

  return text;
}

function canonicalValue(value){
  if(value === null){
    return null;
  }

  if(
    typeof value === 'string' ||
    typeof value === 'boolean'
  ){
    return value;
  }

  if(typeof value === 'number'){
    if(!Number.isFinite(value)){
      fail(
        'W30_NONFINITE_NUMBER_FORBIDDEN'
      );
    }

    return value;
  }

  if(Array.isArray(value)){
    return value.map(
      item =>
        canonicalValue(
          item
        )
    );
  }

  if(
    value &&
    typeof value === 'object'
  ){
    const result = {};

    for(
      const key of
      Object.keys(value)
        .sort()
    ){
      if(value[key] === undefined){
        fail(
          'W30_UNDEFINED_FORBIDDEN'
        );
      }

      result[key] =
        canonicalValue(
          value[key]
        );
    }

    return result;
  }

  fail(
    'W30_CANONICAL_TYPE_FORBIDDEN'
  );
}

function canonicalize(value){
  return JSON.stringify(
    canonicalValue(
      value
    )
  );
}

function sha256Hex(value){
  return crypto
    .createHash('sha256')
    .update(
      Buffer.from(
        String(value),
        'utf8'
      )
    )
    .digest('hex');
}

function validateFreshPreflight({
  handoff_receipt,
  fresh_preflight_receipt,
  current_height
}){
  requireObject(
    fresh_preflight_receipt,
    'fresh_preflight_receipt'
  );

  const currentHeight =
    requireHeight(
      current_height,
      'current_height'
    );

  if(
    fresh_preflight_receipt.status !==
      'ACCEPTED_READONLY' ||
    fresh_preflight_receipt.allowed !==
      true ||
    fresh_preflight_receipt.read_only !==
      true ||
    fresh_preflight_receipt.rpc_method !==
      'testmempoolaccept' ||
    fresh_preflight_receipt.observation_source !==
      ATAN_FEE_V2_W30_PREFLIGHT_OBSERVER ||
    fresh_preflight_receipt.broadcast_attempted !==
      false ||
    fresh_preflight_receipt.broadcast_allowed !==
      false ||
    fresh_preflight_receipt.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W30_ACCEPTED_READONLY_PREFLIGHT_REQUIRED'
    );
  }

  const preflightHeight =
    requireHeight(
      fresh_preflight_receipt.observed_height,
      'fresh_preflight_observed_height'
    );

  if(preflightHeight !== currentHeight){
    fail(
      'W30_PREFLIGHT_NOT_FRESH_AT_CURRENT_HEIGHT'
    );
  }

  const requestId =
    requireHash(
      fresh_preflight_receipt.request_id,
      'fresh_preflight_request_id'
    );

  if(
    fresh_preflight_receipt.handoff_id !==
      handoff_receipt.handoff_id ||
    fresh_preflight_receipt.execution_gate_id !==
      handoff_receipt.execution_gate_id ||
    fresh_preflight_receipt.claim_id !==
      handoff_receipt.claim_id ||
    fresh_preflight_receipt.guard_id !==
      handoff_receipt.guard_id ||
    fresh_preflight_receipt.signed_transaction_sha256 !==
      handoff_receipt.signed_transaction_sha256 ||
    Number(
      fresh_preflight_receipt.signed_transaction_bytes
    ) !==
      Number(
        handoff_receipt.signed_transaction_bytes
      ) ||
    String(
      fresh_preflight_receipt.network_fee_sats
    ) !==
      String(
        handoff_receipt.network_fee_sats
      )
  ){
    fail(
      'W30_PREFLIGHT_HANDOFF_BINDING_MISMATCH'
    );
  }

  return Object.freeze({
    request_id:
      requestId,

    observed_height:
      preflightHeight
  });
}

function liveAuthorizationPayload({
  handoff_receipt,
  fresh_preflight_receipt,
  owner_signer_address,
  created_height,
  valid_until_height,
  live_authorization_nonce
}){
  return {
    schema:
      ATAN_FEE_V2_W30_LIVE_AUTH_SCHEMA,

    version:
      ATAN_FEE_V2_W30_VERSION,

    scope:
      ATAN_FEE_V2_W30_LIVE_AUTH_SCOPE,

    signature_scheme:
      ATAN_FEE_V2_W30_SIGNATURE_SCHEME,

    transport_profile_id:
      ATAN_FEE_V2_W30_TRANSPORT_PROFILE,

    handoff_id:
      handoff_receipt.handoff_id,

    execution_gate_id:
      handoff_receipt.execution_gate_id,

    authorization_id:
      handoff_receipt.authorization_id,

    claim_id:
      handoff_receipt.claim_id,

    guard_id:
      handoff_receipt.guard_id,

    signed_transaction_sha256:
      handoff_receipt.signed_transaction_sha256,

    signed_transaction_bytes:
      handoff_receipt.signed_transaction_bytes,

    network_fee_sats:
      String(
        handoff_receipt.network_fee_sats
      ),

    fresh_preflight_request_id:
      fresh_preflight_receipt.request_id,

    fresh_preflight_observed_height:
      fresh_preflight_receipt.observed_height,

    owner_signer_address,

    created_height,

    valid_until_height,

    live_authorization_nonce
  };
}

export function verifyFreshReadOnlyPreflightForLiveTransportV2({
  handoff_receipt,
  fresh_preflight_receipt,
  current_height
}){
  verifyDisconnectedTransportHandoffReceiptV2(
    handoff_receipt
  );

  validateFreshPreflight({
    handoff_receipt,
    fresh_preflight_receipt,
    current_height
  });

  return true;
}

export function buildLiveTransportAuthorizationSigningMessageV2({
  handoff_receipt,
  fresh_preflight_receipt,
  owner_signer_address,
  created_height,
  valid_until_height,
  live_authorization_nonce,
  current_height
}){
  verifyDisconnectedTransportHandoffReceiptV2(
    handoff_receipt
  );

  validateFreshPreflight({
    handoff_receipt,
    fresh_preflight_receipt,
    current_height
  });

  const ownerAddress =
    requireMainnetAddress(
      owner_signer_address
    );

  const createdHeight =
    requireHeight(
      created_height,
      'created_height'
    );

  const validUntilHeight =
    requireHeight(
      valid_until_height,
      'valid_until_height'
    );

  const currentHeight =
    requireHeight(
      current_height,
      'current_height'
    );

  if(
    createdHeight !==
      currentHeight
  ){
    fail(
      'W30_LIVE_AUTH_MUST_BE_CREATED_AT_CURRENT_HEIGHT'
    );
  }

  if(validUntilHeight < createdHeight){
    fail(
      'W30_LIVE_AUTH_VALID_UNTIL_BEFORE_CREATED'
    );
  }

  const nonce =
    requireNonce(
      live_authorization_nonce,
      'live_authorization_nonce'
    );

  const payload =
    liveAuthorizationPayload({
      handoff_receipt,
      fresh_preflight_receipt,
      owner_signer_address:
        ownerAddress,
      created_height:
        createdHeight,
      valid_until_height:
        validUntilHeight,
      live_authorization_nonce:
        nonce
    });

  const message =
    canonicalize(
      payload
    );

  return Object.freeze({
    payload:
      Object.freeze(
        structuredClone(
          payload
        )
      ),

    message,

    live_authorization_id:
      sha256Hex(
        message
      )
  });
}

export async function createVerifiedLiveTransportAuthorizationV2({
  handoff_receipt,
  fresh_preflight_receipt,
  owner_signer_address,
  created_height,
  valid_until_height,
  live_authorization_nonce,
  owner_signature,
  current_height,
  verify_owner_signature
}){
  if(typeof verify_owner_signature !== 'function'){
    fail(
      'W30_OWNER_SIGNATURE_VERIFIER_REQUIRED'
    );
  }

  const signing =
    buildLiveTransportAuthorizationSigningMessageV2({
      handoff_receipt,
      fresh_preflight_receipt,
      owner_signer_address,
      created_height,
      valid_until_height,
      live_authorization_nonce,
      current_height
    });

  const signature =
    requireString(
      owner_signature,
      'owner_signature'
    );

  const verified =
    await verify_owner_signature({
      scheme:
        ATAN_FEE_V2_W30_SIGNATURE_SCHEME,

      owner_signer_address:
        signing.payload.owner_signer_address,

      message:
        signing.message,

      signature
    });

  if(verified !== true){
    fail(
      'W30_OWNER_LIVE_AUTH_SIGNATURE_INVALID'
    );
  }

  return Object.freeze({
    ...structuredClone(
      signing.payload
    ),

    live_authorization_id:
      signing.live_authorization_id,

    owner_signature:
      signature,

    status:
      'VERIFIED_LIVE_TRANSPORT_AUTHORIZATION_SHADOW',

    signature_verified:
      true,

    transport_connected:
      false,

    sendrawtransaction_available:
      false,

    sendrawtransaction_implementation:
      false,

    broadcast_attempted:
      false,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE'
  });
}

export async function verifyLiveTransportAuthorizationV2({
  handoff_receipt,
  fresh_preflight_receipt,
  live_authorization,
  current_height,
  verify_owner_signature
}){
  requireObject(
    live_authorization,
    'live_authorization'
  );

  if(typeof verify_owner_signature !== 'function'){
    fail(
      'W30_OWNER_SIGNATURE_VERIFIER_REQUIRED'
    );
  }

  verifyDisconnectedTransportHandoffReceiptV2(
    handoff_receipt
  );

  validateFreshPreflight({
    handoff_receipt,
    fresh_preflight_receipt,
    current_height
  });

  const currentHeight =
    requireHeight(
      current_height,
      'current_height'
    );

  if(
    live_authorization.schema !==
      ATAN_FEE_V2_W30_LIVE_AUTH_SCHEMA ||
    live_authorization.version !==
      ATAN_FEE_V2_W30_VERSION ||
    live_authorization.scope !==
      ATAN_FEE_V2_W30_LIVE_AUTH_SCOPE ||
    live_authorization.signature_scheme !==
      ATAN_FEE_V2_W30_SIGNATURE_SCHEME ||
    live_authorization.transport_profile_id !==
      ATAN_FEE_V2_W30_TRANSPORT_PROFILE ||
    live_authorization.status !==
      'VERIFIED_LIVE_TRANSPORT_AUTHORIZATION_SHADOW' ||
    live_authorization.signature_verified !==
      true ||
    live_authorization.transport_connected !==
      false ||
    live_authorization.sendrawtransaction_available !==
      false ||
    live_authorization.sendrawtransaction_implementation !==
      false ||
    live_authorization.broadcast_attempted !==
      false ||
    live_authorization.broadcast_allowed !==
      false ||
    live_authorization.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W30_LIVE_AUTH_STATE_INVALID'
    );
  }

  if(
    live_authorization.handoff_id !==
      handoff_receipt.handoff_id ||
    live_authorization.execution_gate_id !==
      handoff_receipt.execution_gate_id ||
    live_authorization.authorization_id !==
      handoff_receipt.authorization_id ||
    live_authorization.claim_id !==
      handoff_receipt.claim_id ||
    live_authorization.guard_id !==
      handoff_receipt.guard_id ||
    live_authorization.signed_transaction_sha256 !==
      handoff_receipt.signed_transaction_sha256 ||
    Number(
      live_authorization.signed_transaction_bytes
    ) !==
      Number(
        handoff_receipt.signed_transaction_bytes
      ) ||
    String(
      live_authorization.network_fee_sats
    ) !==
      String(
        handoff_receipt.network_fee_sats
      ) ||
    live_authorization.fresh_preflight_request_id !==
      fresh_preflight_receipt.request_id ||
    Number(
      live_authorization.fresh_preflight_observed_height
    ) !==
      Number(
        fresh_preflight_receipt.observed_height
      )
  ){
    fail(
      'W30_LIVE_AUTH_BINDING_MISMATCH'
    );
  }

  if(
    currentHeight <
      Number(
        live_authorization.created_height
      ) ||
    currentHeight >
      Number(
        live_authorization.valid_until_height
      )
  ){
    fail(
      'W30_LIVE_AUTH_EXPIRED_OR_NOT_YET_VALID'
    );
  }

  const payload =
    liveAuthorizationPayload({
      handoff_receipt,
      fresh_preflight_receipt,
      owner_signer_address:
        live_authorization.owner_signer_address,
      created_height:
        Number(
          live_authorization.created_height
        ),
      valid_until_height:
        Number(
          live_authorization.valid_until_height
        ),
      live_authorization_nonce:
        live_authorization.live_authorization_nonce
    });

  const message =
    canonicalize(
      payload
    );

  const expectedId =
    sha256Hex(
      message
    );

  if(
    expectedId !==
      live_authorization.live_authorization_id
  ){
    fail(
      'W30_LIVE_AUTH_ID_MISMATCH'
    );
  }

  const verified =
    await verify_owner_signature({
      scheme:
        live_authorization.signature_scheme,

      owner_signer_address:
        live_authorization.owner_signer_address,

      message,

      signature:
        live_authorization.owner_signature
    });

  if(verified !== true){
    fail(
      'W30_OWNER_LIVE_AUTH_SIGNATURE_INVALID'
    );
  }

  return true;
}

export async function createLiveTransportAdmissionBoundaryV2({
  handoff_receipt,
  fresh_preflight_receipt,
  live_authorization,
  current_height,
  verify_owner_signature
}){
  await verifyLiveTransportAuthorizationV2({
    handoff_receipt,
    fresh_preflight_receipt,
    live_authorization,
    current_height,
    verify_owner_signature
  });

  const admission = {
    schema:
      ATAN_FEE_V2_W30_ADMISSION_SCHEMA,

    version:
      ATAN_FEE_V2_W30_VERSION,

    status:
      'LIVE_TRANSPORT_ADMISSION_VALIDATED_SHADOW',

    transport_profile_id:
      ATAN_FEE_V2_W30_TRANSPORT_PROFILE,

    readonly_observer_reused_as_broadcast_transport:
      false,

    handoff_id:
      handoff_receipt.handoff_id,

    execution_gate_id:
      handoff_receipt.execution_gate_id,

    claim_id:
      handoff_receipt.claim_id,

    live_authorization_id:
      live_authorization.live_authorization_id,

    fresh_preflight_request_id:
      fresh_preflight_receipt.request_id,

    fresh_preflight_observed_height:
      fresh_preflight_receipt.observed_height,

    signed_transaction_sha256:
      handoff_receipt.signed_transaction_sha256,

    signed_transaction_bytes:
      handoff_receipt.signed_transaction_bytes,

    network_fee_sats:
      String(
        handoff_receipt.network_fee_sats
      ),

    handoff_consumed:
      true,

    fresh_preflight_accepted:
      true,

    explicit_owner_live_authorization_verified:
      true,

    transport_connected:
      false,

    sendrawtransaction_available:
      false,

    sendrawtransaction_implementation:
      false,

    broadcast_attempted:
      false,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE',

    next_boundary:
      'DURABLE_BROADCAST_ATTEMPT_JOURNAL_REQUIRED_BEFORE_LIVE_TRANSPORT'
  };

  admission.admission_id =
    sha256Hex(
      canonicalize({
        schema:
          admission.schema,

        version:
          admission.version,

        transport_profile_id:
          admission.transport_profile_id,

        handoff_id:
          admission.handoff_id,

        execution_gate_id:
          admission.execution_gate_id,

        claim_id:
          admission.claim_id,

        live_authorization_id:
          admission.live_authorization_id,

        fresh_preflight_request_id:
          admission.fresh_preflight_request_id,

        signed_transaction_sha256:
          admission.signed_transaction_sha256,

        status:
          admission.status
      })
    );

  return Object.freeze(
    structuredClone(
      admission
    )
  );
}

export function verifyLiveTransportAdmissionBoundaryV2(
  admission
){
  requireObject(
    admission,
    'admission'
  );

  if(
    admission.schema !==
      ATAN_FEE_V2_W30_ADMISSION_SCHEMA ||
    admission.version !==
      ATAN_FEE_V2_W30_VERSION ||
    admission.status !==
      'LIVE_TRANSPORT_ADMISSION_VALIDATED_SHADOW' ||
    admission.transport_profile_id !==
      ATAN_FEE_V2_W30_TRANSPORT_PROFILE ||
    admission.readonly_observer_reused_as_broadcast_transport !==
      false ||
    admission.handoff_consumed !==
      true ||
    admission.fresh_preflight_accepted !==
      true ||
    admission.explicit_owner_live_authorization_verified !==
      true ||
    admission.transport_connected !==
      false ||
    admission.sendrawtransaction_available !==
      false ||
    admission.sendrawtransaction_implementation !==
      false ||
    admission.broadcast_attempted !==
      false ||
    admission.broadcast_allowed !==
      false ||
    admission.broadcast_authority !==
      'NONE' ||
    admission.next_boundary !==
      'DURABLE_BROADCAST_ATTEMPT_JOURNAL_REQUIRED_BEFORE_LIVE_TRANSPORT'
  ){
    fail(
      'W30_ADMISSION_STATE_INVALID'
    );
  }

  requireHash(
    admission.admission_id,
    'admission_id'
  );

  requireHash(
    admission.handoff_id,
    'handoff_id'
  );

  requireHash(
    admission.execution_gate_id,
    'execution_gate_id'
  );

  requireHash(
    admission.claim_id,
    'claim_id'
  );

  requireHash(
    admission.live_authorization_id,
    'live_authorization_id'
  );

  requireHash(
    admission.fresh_preflight_request_id,
    'fresh_preflight_request_id'
  );

  requireHash(
    admission.signed_transaction_sha256,
    'signed_transaction_sha256'
  );

  return true;
}

export async function attemptLiveTransportBroadcastV2(
  admission
){
  verifyLiveTransportAdmissionBoundaryV2(
    admission
  );

  fail(
    'W30_LIVE_TRANSPORT_NOT_IMPLEMENTED'
  );
}

export function describeW30BoundaryV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W30_VERSION,

    requires_w29_consumed_handoff:
      true,

    requires_fresh_readonly_testmempoolaccept:
      true,

    fresh_preflight_same_height_as_admission:
      true,

    requires_explicit_owner_live_transport_authorization:
      true,

    live_authorization_scope:
      ATAN_FEE_V2_W30_LIVE_AUTH_SCOPE,

    signature_scheme:
      ATAN_FEE_V2_W30_SIGNATURE_SCHEME,

    transport_profile_id:
      ATAN_FEE_V2_W30_TRANSPORT_PROFILE,

    readonly_observer_reused_as_broadcast_transport:
      false,

    transport_connected:
      false,

    sendrawtransaction_available:
      false,

    sendrawtransaction_implementation:
      false,

    real_owner_signature_created_in_w30:
      false,

    real_mainnet_rpc_requests_w30:
      0,

    transaction_broadcast:
      false,

    broadcast_authority:
      'NONE',

    next_boundary:
      'DURABLE_BROADCAST_ATTEMPT_JOURNAL_REQUIRED_BEFORE_LIVE_TRANSPORT'
  });
}
