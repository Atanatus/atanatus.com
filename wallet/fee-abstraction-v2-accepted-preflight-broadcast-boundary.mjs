import {
  canonicalizeV2,
  sha256HexV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

export const ATAN_FEE_V2_W25_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_ACCEPTED_PREFLIGHT_CONSUMPTION_INTENT_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_ACCEPTED_PREFLIGHT_CONSUMPTION_INTENT';

export const ATAN_FEE_V2_BROADCAST_AUTHORIZATION_CHALLENGE_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_BROADCAST_AUTHORIZATION_CHALLENGE';

export const ATAN_FEE_V2_FUTURE_BROADCAST_AUTHORIZATION_SCOPE =
  'REAL_TRANSACTION_BROADCAST_ONLY';

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

function requireNonNegativeInteger(value, name){
  const number =
    Number(value);

  if(
    !Number.isSafeInteger(number) ||
    number < 0
  ){
    fail(
      `${name.toUpperCase()}_INTEGER_INVALID`
    );
  }

  return number;
}

function intentPayload(intent){
  return {
    schema:
      intent.schema,

    version:
      intent.version,

    guard_id:
      intent.guard_id,

    settlement_plan_id:
      intent.settlement_plan_id,

    durable_reservation_id:
      intent.durable_reservation_id,

    owner_preflight_authorization_id:
      intent.owner_preflight_authorization_id,

    owner_claim_id:
      intent.owner_claim_id,

    preflight_request_id:
      intent.preflight_request_id,

    signed_transaction_sha256:
      intent.signed_transaction_sha256,

    economic_core_commitment:
      intent.economic_core_commitment,

    signed_transaction_bytes:
      intent.signed_transaction_bytes,

    network_fee_sats:
      intent.network_fee_sats,

    status:
      intent.status
  };
}

function challengePayload(challenge){
  return {
    schema:
      challenge.schema,

    version:
      challenge.version,

    scope:
      challenge.scope,

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
      challenge.network_fee_sats
  };
}

export async function createAcceptedPreflightConsumptionIntentV2({
  guard,
  handoff,
  owner_preflight_authorization,
  owner_claim,
  preflight_receipt,
  current_height
}){
  requireObject(
    guard,
    'guard'
  );

  requireObject(
    handoff,
    'handoff'
  );

  requireObject(
    owner_preflight_authorization,
    'owner_preflight_authorization'
  );

  requireObject(
    owner_claim,
    'owner_claim'
  );

  requireObject(
    preflight_receipt,
    'preflight_receipt'
  );

  const currentHeight =
    requireNonNegativeInteger(
      current_height,
      'current_height'
    );

  if(
    guard.status !==
      'PRE_BROADCAST_VALIDATED' ||
    guard.broadcast_allowed !==
      false
  ){
    fail(
      'W25_GUARD_INVALID'
    );
  }

  if(
    handoff.status !==
      'DISCONNECTED_SHADOW' ||
    handoff.broadcast_allowed !==
      false ||
    handoff.broadcast_attempted !==
      false ||
    handoff.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W25_HANDOFF_INVALID'
    );
  }

  if(
    owner_preflight_authorization.scope !==
      'LIVE_BROADCAST_PREFLIGHT_ONLY' ||
    owner_preflight_authorization.broadcast_allowed !==
      false ||
    owner_preflight_authorization.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W25_OWNER_PREFLIGHT_AUTHORIZATION_SCOPE_INVALID'
    );
  }

  if(
    owner_claim.status !==
      'ACTIVE'
  ){
    fail(
      'W25_OWNER_CLAIM_NOT_ACTIVE'
    );
  }

  if(
    Number.isSafeInteger(
      Number(
        owner_preflight_authorization.valid_until_height
      )
    ) &&
    currentHeight >
      Number(
        owner_preflight_authorization.valid_until_height
      )
  ){
    fail(
      'W25_OWNER_PREFLIGHT_AUTHORIZATION_EXPIRED'
    );
  }

  if(
    Number.isSafeInteger(
      Number(
        owner_claim.valid_until_height
      )
    ) &&
    currentHeight >
      Number(
        owner_claim.valid_until_height
      )
  ){
    fail(
      'W25_OWNER_CLAIM_EXPIRED'
    );
  }

  if(
    preflight_receipt.status !==
      'ACCEPTED_READONLY' ||
    preflight_receipt.allowed !==
      true ||
    preflight_receipt.read_only !==
      true ||
    preflight_receipt.broadcast_attempted !==
      false ||
    preflight_receipt.broadcast_allowed !==
      false ||
    preflight_receipt.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W25_ACCEPTED_READONLY_PREFLIGHT_REQUIRED'
    );
  }

  const guardId =
    requireHash(
      guard.guard_id,
      'guard_id'
    );

  const settlementPlanId =
    requireHash(
      guard.settlement_plan_id,
      'settlement_plan_id'
    );

  const durableReservationId =
    requireHash(
      guard.durable_reservation_id,
      'durable_reservation_id'
    );

  const ownerAuthorizationId =
    requireHash(
      owner_preflight_authorization.authorization_id,
      'owner_preflight_authorization_id'
    );

  const ownerClaimId =
    requireHash(
      owner_claim.claim_id,
      'owner_claim_id'
    );

  const preflightRequestId =
    requireHash(
      preflight_receipt.request_id,
      'preflight_request_id'
    );

  const txHash =
    requireHash(
      guard.signed_transaction_sha256,
      'signed_transaction_sha256'
    );

  const economicCore =
    requireHash(
      guard.economic_core_commitment,
      'economic_core_commitment'
    );

  if(
    handoff.guard_id !==
      guardId ||
    handoff.signed_transaction_sha256 !==
      txHash ||
    handoff.economic_core_commitment !==
      economicCore ||
    handoff.signed_transaction_bytes !==
      guard.signed_transaction_bytes ||
    handoff.network_fee_sats !==
      guard.network_fee_sats
  ){
    fail(
      'W25_HANDOFF_GUARD_BINDING_MISMATCH'
    );
  }

  if(
    owner_claim.authorization_id !==
      ownerAuthorizationId
  ){
    fail(
      'W25_OWNER_CLAIM_AUTHORIZATION_BINDING_MISMATCH'
    );
  }

  if(
    preflight_receipt.guard_id !==
      guardId ||
    preflight_receipt.owner_authorization_id !==
      ownerAuthorizationId ||
    preflight_receipt.owner_claim_id !==
      ownerClaimId ||
    preflight_receipt.signed_transaction_sha256 !==
      txHash ||
    preflight_receipt.signed_transaction_bytes !==
      guard.signed_transaction_bytes ||
    String(
      preflight_receipt.network_fee_sats
    ) !==
      String(
        guard.network_fee_sats
      )
  ){
    fail(
      'W25_PREFLIGHT_RECEIPT_BINDING_MISMATCH'
    );
  }

  const intent = {
    schema:
      ATAN_FEE_V2_ACCEPTED_PREFLIGHT_CONSUMPTION_INTENT_SCHEMA,

    version:
      ATAN_FEE_V2_W25_VERSION,

    guard_id:
      guardId,

    settlement_plan_id:
      settlementPlanId,

    durable_reservation_id:
      durableReservationId,

    owner_preflight_authorization_id:
      ownerAuthorizationId,

    owner_claim_id:
      ownerClaimId,

    preflight_request_id:
      preflightRequestId,

    signed_transaction_sha256:
      txHash,

    economic_core_commitment:
      economicCore,

    signed_transaction_bytes:
      requireNonNegativeInteger(
        guard.signed_transaction_bytes,
        'signed_transaction_bytes'
      ),

    network_fee_sats:
      String(
        guard.network_fee_sats
      ),

    status:
      'PREFLIGHT_ACCEPTED_CONSUMPTION_READY',

    preflight_claim_consumption_permitted:
      true,

    preflight_claim_consumed:
      false,

    broadcast_authorization_present:
      false,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE',

    separate_broadcast_authorization_required:
      true
  };

  intent.consumption_intent_id =
    await sha256HexV2(
      canonicalizeV2(
        intentPayload(
          intent
        )
      )
    );

  return Object.freeze(
    structuredClone(
      intent
    )
  );
}

export async function verifyAcceptedPreflightConsumptionIntentV2(
  intent
){
  requireObject(
    intent,
    'intent'
  );

  if(
    intent.schema !==
      ATAN_FEE_V2_ACCEPTED_PREFLIGHT_CONSUMPTION_INTENT_SCHEMA ||
    intent.version !==
      ATAN_FEE_V2_W25_VERSION ||
    intent.status !==
      'PREFLIGHT_ACCEPTED_CONSUMPTION_READY' ||
    intent.preflight_claim_consumption_permitted !==
      true ||
    intent.preflight_claim_consumed !==
      false ||
    intent.broadcast_authorization_present !==
      false ||
    intent.broadcast_allowed !==
      false ||
    intent.broadcast_authority !==
      'NONE' ||
    intent.separate_broadcast_authorization_required !==
      true
  ){
    fail(
      'W25_CONSUMPTION_INTENT_INVALID'
    );
  }

  const expected =
    await sha256HexV2(
      canonicalizeV2(
        intentPayload(
          intent
        )
      )
    );

  if(
    expected !==
      intent.consumption_intent_id
  ){
    fail(
      'W25_CONSUMPTION_INTENT_ID_MISMATCH'
    );
  }

  return true;
}

export async function createBroadcastAuthorizationChallengeV2({
  consumption_intent
}){
  await verifyAcceptedPreflightConsumptionIntentV2(
    consumption_intent
  );

  const challenge = {
    schema:
      ATAN_FEE_V2_BROADCAST_AUTHORIZATION_CHALLENGE_SCHEMA,

    version:
      ATAN_FEE_V2_W25_VERSION,

    scope:
      ATAN_FEE_V2_FUTURE_BROADCAST_AUTHORIZATION_SCOPE,

    consumption_intent_id:
      consumption_intent.consumption_intent_id,

    guard_id:
      consumption_intent.guard_id,

    settlement_plan_id:
      consumption_intent.settlement_plan_id,

    durable_reservation_id:
      consumption_intent.durable_reservation_id,

    owner_claim_id:
      consumption_intent.owner_claim_id,

    preflight_request_id:
      consumption_intent.preflight_request_id,

    signed_transaction_sha256:
      consumption_intent.signed_transaction_sha256,

    economic_core_commitment:
      consumption_intent.economic_core_commitment,

    signed_transaction_bytes:
      consumption_intent.signed_transaction_bytes,

    network_fee_sats:
      consumption_intent.network_fee_sats,

    owner_signature_present:
      false,

    authorization_created:
      false,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE'
  };

  challenge.challenge_id =
    await sha256HexV2(
      canonicalizeV2(
        challengePayload(
          challenge
        )
      )
    );

  return Object.freeze(
    structuredClone(
      challenge
    )
  );
}

export async function verifyBroadcastAuthorizationChallengeV2(
  challenge
){
  requireObject(
    challenge,
    'challenge'
  );

  if(
    challenge.schema !==
      ATAN_FEE_V2_BROADCAST_AUTHORIZATION_CHALLENGE_SCHEMA ||
    challenge.version !==
      ATAN_FEE_V2_W25_VERSION ||
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
      'W25_BROADCAST_AUTHORIZATION_CHALLENGE_INVALID'
    );
  }

  const expected =
    await sha256HexV2(
      canonicalizeV2(
        challengePayload(
          challenge
        )
      )
    );

  if(
    expected !==
      challenge.challenge_id
  ){
    fail(
      'W25_BROADCAST_AUTHORIZATION_CHALLENGE_ID_MISMATCH'
    );
  }

  return true;
}

export function assertPreflightAuthorizationCannotAuthorizeBroadcastV2(
  owner_preflight_authorization
){
  requireObject(
    owner_preflight_authorization,
    'owner_preflight_authorization'
  );

  if(
    owner_preflight_authorization.scope !==
      'LIVE_BROADCAST_PREFLIGHT_ONLY'
  ){
    fail(
      'W25_NOT_A_PREFLIGHT_ONLY_AUTHORIZATION'
    );
  }

  if(
    owner_preflight_authorization.broadcast_allowed !==
      false ||
    owner_preflight_authorization.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W25_PREFLIGHT_AUTHORIZATION_AUTHORITY_ESCALATION'
    );
  }

  return true;
}

export function describeW25BoundaryV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W25_VERSION,

    accepted_readonly_preflight_required:
      true,

    active_durable_owner_claim_required:
      true,

    rejected_preflight_can_consume_claim:
      false,

    accepted_preflight_can_create_consumption_intent:
      true,

    consumption_intent_authorizes_broadcast:
      false,

    owner_preflight_authorization_can_authorize_broadcast:
      false,

    separate_broadcast_authorization_required:
      true,

    future_broadcast_authorization_scope:
      ATAN_FEE_V2_FUTURE_BROADCAST_AUTHORIZATION_SCOPE,

    broadcast_authorization_created_in_w25:
      false,

    broadcast_transport_created_in_w25:
      false,

    sendrawtransaction_implementation:
      false,

    transaction_broadcast:
      false,

    broadcast_authority:
      'NONE'
  });
}
