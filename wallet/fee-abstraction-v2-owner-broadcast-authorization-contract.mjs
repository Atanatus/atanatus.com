import {
  canonicalizeV2,
  sha256HexV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

import {
  verifyBroadcastAuthorizationChallengeV2,
  ATAN_FEE_V2_FUTURE_BROADCAST_AUTHORIZATION_SCOPE
} from './fee-abstraction-v2-accepted-preflight-broadcast-boundary.mjs';

export const ATAN_FEE_V2_W26_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_OWNER_BROADCAST_AUTHORIZATION_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_OWNER_BROADCAST_AUTHORIZATION';

export const ATAN_FEE_V2_OWNER_BROADCAST_SIGNATURE_SCHEME =
  'BCH_SIGNMESSAGE_P2PKH_V1';

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

function requireMainnetAddress(value, name){
  const text =
    requireString(
      value,
      name
    );

  if(
    !text.startsWith(
      'bitcoincash:'
    )
  ){
    fail(
      `${name.toUpperCase()}_MAINNET_ADDRESS_REQUIRED`
    );
  }

  return text;
}

function requireNonce(value){
  const text =
    requireString(
      value,
      'authorization_nonce'
    );

  if(text.length < 16){
    fail(
      'AUTHORIZATION_NONCE_TOO_SHORT'
    );
  }

  return text;
}

function payloadFromChallenge({
  challenge,
  owner_signer_address,
  created_height,
  valid_until_height,
  authorization_nonce
}){
  return {
    schema:
      ATAN_FEE_V2_OWNER_BROADCAST_AUTHORIZATION_SCHEMA,

    version:
      ATAN_FEE_V2_W26_VERSION,

    scope:
      ATAN_FEE_V2_FUTURE_BROADCAST_AUTHORIZATION_SCOPE,

    signature_scheme:
      ATAN_FEE_V2_OWNER_BROADCAST_SIGNATURE_SCHEME,

    challenge_id:
      challenge.challenge_id,

    consumption_intent_id:
      challenge.consumption_intent_id,

    guard_id:
      challenge.guard_id,

    settlement_plan_id:
      challenge.settlement_plan_id,

    durable_reservation_id:
      challenge.durable_reservation_id,

    owner_claim_id:
      challenge.owner_claim_id,

    preflight_request_id:
      challenge.preflight_request_id,

    signed_transaction_sha256:
      challenge.signed_transaction_sha256,

    economic_core_commitment:
      challenge.economic_core_commitment,

    signed_transaction_bytes:
      challenge.signed_transaction_bytes,

    network_fee_sats:
      challenge.network_fee_sats,

    owner_signer_address,

    created_height,

    valid_until_height,

    authorization_nonce
  };
}

function payloadFromAuthorization(
  authorization
){
  return {
    schema:
      authorization.schema,

    version:
      authorization.version,

    scope:
      authorization.scope,

    signature_scheme:
      authorization.signature_scheme,

    challenge_id:
      authorization.challenge_id,

    consumption_intent_id:
      authorization.consumption_intent_id,

    guard_id:
      authorization.guard_id,

    settlement_plan_id:
      authorization.settlement_plan_id,

    durable_reservation_id:
      authorization.durable_reservation_id,

    owner_claim_id:
      authorization.owner_claim_id,

    preflight_request_id:
      authorization.preflight_request_id,

    signed_transaction_sha256:
      authorization.signed_transaction_sha256,

    economic_core_commitment:
      authorization.economic_core_commitment,

    signed_transaction_bytes:
      authorization.signed_transaction_bytes,

    network_fee_sats:
      authorization.network_fee_sats,

    owner_signer_address:
      authorization.owner_signer_address,

    created_height:
      authorization.created_height,

    valid_until_height:
      authorization.valid_until_height,

    authorization_nonce:
      authorization.authorization_nonce
  };
}

async function normalizeAndValidateChallenge(
  challenge
){
  requireObject(
    challenge,
    'challenge'
  );

  await verifyBroadcastAuthorizationChallengeV2(
    challenge
  );

  if(
    challenge.scope !==
      ATAN_FEE_V2_FUTURE_BROADCAST_AUTHORIZATION_SCOPE ||
    challenge.owner_signature_present !==
      false ||
    challenge.authorization_created !==
      false ||
    challenge.broadcast_allowed !==
      false ||
    challenge.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W26_CHALLENGE_AUTHORITY_INVALID'
    );
  }

  return challenge;
}

export async function buildOwnerBroadcastAuthorizationSigningMessageV2({
  challenge,
  owner_signer_address,
  created_height,
  valid_until_height,
  authorization_nonce
}){
  await normalizeAndValidateChallenge(
    challenge
  );

  const ownerAddress =
    requireMainnetAddress(
      owner_signer_address,
      'owner_signer_address'
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

  if(validUntilHeight < createdHeight){
    fail(
      'W26_VALID_UNTIL_BEFORE_CREATED'
    );
  }

  const nonce =
    requireNonce(
      authorization_nonce
    );

  const payload =
    payloadFromChallenge({
      challenge,
      owner_signer_address:
        ownerAddress,
      created_height:
        createdHeight,
      valid_until_height:
        validUntilHeight,
      authorization_nonce:
        nonce
    });

  const message =
    canonicalizeV2(
      payload
    );

  const authorizationId =
    await sha256HexV2(
      message
    );

  return Object.freeze({
    payload:
      Object.freeze(
        structuredClone(
          payload
        )
      ),

    message,

    authorization_id:
      authorizationId
  });
}

export async function createVerifiedOwnerBroadcastAuthorizationV2({
  challenge,
  owner_signer_address,
  created_height,
  valid_until_height,
  authorization_nonce,
  owner_signature,
  current_height,
  verify_owner_signature
}){
  if(typeof verify_owner_signature !== 'function'){
    fail(
      'W26_OWNER_SIGNATURE_VERIFIER_REQUIRED'
    );
  }

  const currentHeight =
    requireHeight(
      current_height,
      'current_height'
    );

  const signing =
    await buildOwnerBroadcastAuthorizationSigningMessageV2({
      challenge,
      owner_signer_address,
      created_height,
      valid_until_height,
      authorization_nonce
    });

  if(
    currentHeight <
      signing.payload.created_height ||
    currentHeight >
      signing.payload.valid_until_height
  ){
    fail(
      'W26_AUTHORIZATION_HEIGHT_INVALID'
    );
  }

  const signature =
    requireString(
      owner_signature,
      'owner_signature'
    );

  const verified =
    await verify_owner_signature({
      scheme:
        ATAN_FEE_V2_OWNER_BROADCAST_SIGNATURE_SCHEME,

      owner_signer_address:
        signing.payload.owner_signer_address,

      message:
        signing.message,

      signature
    });

  if(verified !== true){
    fail(
      'W26_OWNER_SIGNATURE_INVALID'
    );
  }

  return Object.freeze({
    ...structuredClone(
      signing.payload
    ),

    authorization_id:
      signing.authorization_id,

    owner_signature:
      signature,

    status:
      'VERIFIED_SHADOW_CREDENTIAL',

    signature_verified:
      true,

    durable_one_time_claim_required:
      true,

    durable_claim_present:
      false,

    broadcast_transport_connected:
      false,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE'
  });
}

export async function verifyOwnerBroadcastAuthorizationV2({
  authorization,
  challenge,
  current_height,
  verify_owner_signature
}){
  requireObject(
    authorization,
    'authorization'
  );

  if(typeof verify_owner_signature !== 'function'){
    fail(
      'W26_OWNER_SIGNATURE_VERIFIER_REQUIRED'
    );
  }

  await normalizeAndValidateChallenge(
    challenge
  );

  const currentHeight =
    requireHeight(
      current_height,
      'current_height'
    );

  if(
    authorization.schema !==
      ATAN_FEE_V2_OWNER_BROADCAST_AUTHORIZATION_SCHEMA ||
    authorization.version !==
      ATAN_FEE_V2_W26_VERSION ||
    authorization.scope !==
      ATAN_FEE_V2_FUTURE_BROADCAST_AUTHORIZATION_SCOPE ||
    authorization.signature_scheme !==
      ATAN_FEE_V2_OWNER_BROADCAST_SIGNATURE_SCHEME ||
    authorization.status !==
      'VERIFIED_SHADOW_CREDENTIAL' ||
    authorization.signature_verified !==
      true ||
    authorization.durable_one_time_claim_required !==
      true ||
    authorization.durable_claim_present !==
      false ||
    authorization.broadcast_transport_connected !==
      false ||
    authorization.broadcast_allowed !==
      false ||
    authorization.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W26_AUTHORIZATION_STATE_INVALID'
    );
  }

  if(
    authorization.challenge_id !==
      challenge.challenge_id ||
    authorization.consumption_intent_id !==
      challenge.consumption_intent_id ||
    authorization.guard_id !==
      challenge.guard_id ||
    authorization.settlement_plan_id !==
      challenge.settlement_plan_id ||
    authorization.durable_reservation_id !==
      challenge.durable_reservation_id ||
    authorization.owner_claim_id !==
      challenge.owner_claim_id ||
    authorization.preflight_request_id !==
      challenge.preflight_request_id ||
    authorization.signed_transaction_sha256 !==
      challenge.signed_transaction_sha256 ||
    authorization.economic_core_commitment !==
      challenge.economic_core_commitment ||
    authorization.signed_transaction_bytes !==
      challenge.signed_transaction_bytes ||
    String(
      authorization.network_fee_sats
    ) !==
      String(
        challenge.network_fee_sats
      )
  ){
    fail(
      'W26_AUTHORIZATION_CHALLENGE_BINDING_MISMATCH'
    );
  }

  const payload =
    payloadFromAuthorization(
      authorization
    );

  const message =
    canonicalizeV2(
      payload
    );

  const expectedId =
    await sha256HexV2(
      message
    );

  if(
    expectedId !==
      authorization.authorization_id
  ){
    fail(
      'W26_AUTHORIZATION_ID_MISMATCH'
    );
  }

  if(
    currentHeight <
      authorization.created_height ||
    currentHeight >
      authorization.valid_until_height
  ){
    fail(
      'W26_AUTHORIZATION_EXPIRED_OR_NOT_YET_VALID'
    );
  }

  const verified =
    await verify_owner_signature({
      scheme:
        authorization.signature_scheme,

      owner_signer_address:
        authorization.owner_signer_address,

      message,

      signature:
        authorization.owner_signature
    });

  if(verified !== true){
    fail(
      'W26_OWNER_SIGNATURE_INVALID'
    );
  }

  return true;
}

export function assertOwnerBroadcastCredentialCannotReachTransportV2(
  authorization
){
  requireObject(
    authorization,
    'authorization'
  );

  if(
    authorization.status !==
      'VERIFIED_SHADOW_CREDENTIAL' ||
    authorization.durable_one_time_claim_required !==
      true ||
    authorization.durable_claim_present !==
      false ||
    authorization.broadcast_transport_connected !==
      false ||
    authorization.broadcast_allowed !==
      false ||
    authorization.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W26_CREDENTIAL_TRANSPORT_BOUNDARY_INVALID'
    );
  }

  return true;
}

export function describeW26OwnerBroadcastAuthorizationContractV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W26_VERSION,

    scope:
      ATAN_FEE_V2_FUTURE_BROADCAST_AUTHORIZATION_SCOPE,

    signature_scheme:
      ATAN_FEE_V2_OWNER_BROADCAST_SIGNATURE_SCHEME,

    requires_w25_challenge:
      true,

    challenge_binds_transaction:
      true,

    verified_credential_status:
      'VERIFIED_SHADOW_CREDENTIAL',

    credential_alone_allows_broadcast:
      false,

    durable_one_time_claim_required:
      true,

    broadcast_transport_connected:
      false,

    network_implementation_embedded:
      false,

    rpc_implementation_embedded:
      false,

    signing_implementation_embedded:
      false,

    sendrawtransaction_implementation:
      false,

    transaction_broadcast:
      false,

    broadcast_authority:
      'NONE'
  });
}
