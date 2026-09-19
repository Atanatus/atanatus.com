import crypto from 'node:crypto';

import {
  verifyOwnerBroadcastAuthorizationV2
} from './fee-abstraction-v2-owner-broadcast-authorization-contract.mjs';

export const ATAN_FEE_V2_W28_R1_VERSION =
  '1.0.1';

export const ATAN_FEE_V2_DISCONNECTED_BROADCAST_EXECUTION_GATE_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_DISCONNECTED_BROADCAST_EXECUTION_GATE';

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

function requireTransactionHex(value){
  const text =
    requireString(
      value,
      'signed_transaction_hex'
    ).toLowerCase();

  if(
    text.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(text)
  ){
    fail(
      'W28_R1_SIGNED_TRANSACTION_HEX_INVALID'
    );
  }

  return text;
}

function sha256HexFromRawTransaction(
  transactionHex
){
  return crypto
    .createHash('sha256')
    .update(
      Buffer.from(
        transactionHex,
        'hex'
      )
    )
    .digest('hex');
}

function canonicalizeLocal(value){
  if(value === null){
    return 'null';
  }

  if(typeof value === 'string'){
    return JSON.stringify(value);
  }

  if(typeof value === 'boolean'){
    return value ? 'true' : 'false';
  }

  if(typeof value === 'number'){
    if(!Number.isFinite(value)){
      fail(
        'W28_R1_NONFINITE_NUMBER_FORBIDDEN'
      );
    }

    return JSON.stringify(value);
  }

  if(Array.isArray(value)){
    return (
      '[' +
      value
        .map(
          item =>
            canonicalizeLocal(
              item
            )
        )
        .join(',') +
      ']'
    );
  }

  if(
    value &&
    typeof value === 'object'
  ){
    return (
      '{' +
      Object.keys(value)
        .sort()
        .map(
          key =>
            JSON.stringify(key) +
            ':' +
            canonicalizeLocal(
              value[key]
            )
        )
        .join(',') +
      '}'
    );
  }

  fail(
    'W28_R1_CANONICAL_TYPE_FORBIDDEN'
  );
}

function sha256Canonical(value){
  return crypto
    .createHash('sha256')
    .update(
      Buffer.from(
        canonicalizeLocal(
          value
        ),
        'utf8'
      )
    )
    .digest('hex');
}

function gatePayload(gate){
  return {
    schema:
      gate.schema,

    version:
      gate.version,

    authorization_id:
      gate.authorization_id,

    claim_id:
      gate.claim_id,

    nonce_key:
      gate.nonce_key,

    challenge_id:
      gate.challenge_id,

    consumption_intent_id:
      gate.consumption_intent_id,

    guard_id:
      gate.guard_id,

    signed_transaction_sha256:
      gate.signed_transaction_sha256,

    signed_transaction_bytes:
      gate.signed_transaction_bytes,

    network_fee_sats:
      gate.network_fee_sats,

    status:
      gate.status
  };
}

export async function createDisconnectedBroadcastExecutionGateV2({
  ledger,
  authorization,
  challenge,
  durable_claim_receipt,
  signed_transaction_hex,
  current_height,
  verify_owner_signature
}){
  requireObject(
    ledger,
    'ledger'
  );

  requireObject(
    authorization,
    'authorization'
  );

  requireObject(
    challenge,
    'challenge'
  );

  requireObject(
    durable_claim_receipt,
    'durable_claim_receipt'
  );

  if(
    typeof ledger.assertActiveClaim !==
      'function'
  ){
    fail(
      'W28_R1_TRUSTED_LEDGER_ASSERT_ACTIVE_CLAIM_REQUIRED'
    );
  }

  const currentHeight =
    requireHeight(
      current_height,
      'current_height'
    );

  if(typeof verify_owner_signature !== 'function'){
    fail(
      'W28_R1_OWNER_SIGNATURE_VERIFIER_REQUIRED'
    );
  }

  await verifyOwnerBroadcastAuthorizationV2({
    authorization,
    challenge,
    current_height:
      currentHeight,
    verify_owner_signature
  });

  if(
    durable_claim_receipt.status !==
      'ACTIVE_DURABLE_BROADCAST_CLAIM' &&
    durable_claim_receipt.status !==
      'ACTIVE_DURABLE_BROADCAST_CLAIM_RECOVERED'
  ){
    fail(
      'W28_R1_ACTIVE_DURABLE_BROADCAST_CLAIM_REQUIRED'
    );
  }

  if(
    durable_claim_receipt.durable_claim_active !==
      true ||
    durable_claim_receipt.replay_protected !==
      true ||
    durable_claim_receipt.broadcast_transport_connected !==
      false ||
    durable_claim_receipt.sendrawtransaction_implementation !==
      false ||
    durable_claim_receipt.broadcast_attempted !==
      false ||
    durable_claim_receipt.broadcast_allowed !==
      false ||
    durable_claim_receipt.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W28_R1_DURABLE_CLAIM_SAFETY_STATE_INVALID'
    );
  }

  const authorizationId =
    requireHash(
      authorization.authorization_id,
      'authorization_id'
    );

  const claimId =
    requireHash(
      durable_claim_receipt.claim_id,
      'claim_id'
    );

  const nonceKey =
    requireHash(
      durable_claim_receipt.nonce_key,
      'nonce_key'
    );

  const challengeId =
    requireHash(
      authorization.challenge_id,
      'challenge_id'
    );

  const consumptionIntentId =
    requireHash(
      authorization.consumption_intent_id,
      'consumption_intent_id'
    );

  const guardId =
    requireHash(
      authorization.guard_id,
      'guard_id'
    );

  const txHash =
    requireHash(
      authorization.signed_transaction_sha256,
      'signed_transaction_sha256'
    );

  if(
    durable_claim_receipt.authorization_id !==
      authorizationId ||
    durable_claim_receipt.challenge_id !==
      challengeId ||
    durable_claim_receipt.consumption_intent_id !==
      consumptionIntentId ||
    durable_claim_receipt.guard_id !==
      guardId ||
    durable_claim_receipt.signed_transaction_sha256 !==
      txHash
  ){
    fail(
      'W28_R1_DURABLE_RECEIPT_AUTHORIZATION_BINDING_MISMATCH'
    );
  }

  const activeClaim =
    await ledger.assertActiveClaim({
      claim_id:
        claimId,
      authorization_id:
        authorizationId,
      current_height:
        currentHeight
    });

  if(
    activeClaim.status !==
      'ACTIVE' ||
    activeClaim.claim_id !==
      claimId ||
    activeClaim.authorization_id !==
      authorizationId ||
    activeClaim.nonce_key !==
      nonceKey ||
    activeClaim.owner_signer_address !==
      authorization.owner_signer_address ||
    activeClaim.challenge_id !==
      challengeId ||
    activeClaim.consumption_intent_id !==
      consumptionIntentId ||
    activeClaim.guard_id !==
      guardId ||
    activeClaim.signed_transaction_sha256 !==
      txHash ||
    Number(
      activeClaim.valid_until_height
    ) !==
      Number(
        authorization.valid_until_height
      )
  ){
    fail(
      'W28_R1_DURABLE_LEDGER_CLAIM_BINDING_MISMATCH'
    );
  }

  const transactionHex =
    requireTransactionHex(
      signed_transaction_hex
    );

  const transactionBytes =
    transactionHex.length / 2;

  if(
    transactionBytes !==
      Number(
        authorization.signed_transaction_bytes
      )
  ){
    fail(
      'W28_R1_SIGNED_TRANSACTION_BYTE_LENGTH_MISMATCH'
    );
  }

  const actualTxHash =
    sha256HexFromRawTransaction(
      transactionHex
    );

  if(actualTxHash !== txHash){
    fail(
      'W28_R1_SIGNED_TRANSACTION_HASH_MISMATCH'
    );
  }

  const gate = {
    schema:
      ATAN_FEE_V2_DISCONNECTED_BROADCAST_EXECUTION_GATE_SCHEMA,

    version:
      ATAN_FEE_V2_W28_R1_VERSION,

    authorization_id:
      authorizationId,

    claim_id:
      claimId,

    nonce_key:
      nonceKey,

    challenge_id:
      challengeId,

    consumption_intent_id:
      consumptionIntentId,

    guard_id:
      guardId,

    signed_transaction_sha256:
      txHash,

    signed_transaction_bytes:
      transactionBytes,

    network_fee_sats:
      String(
        authorization.network_fee_sats
      ),

    status:
      'DISCONNECTED_BROADCAST_EXECUTION_GATE_VALIDATED',

    durable_claim_verified:
      true,

    durable_ledger_claim_verified:
      true,

    durable_claim_receipt_verified:
      true,

    transaction_bytes_verified:
      true,

    claim_consumed:
      false,

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
      'ATOMIC_CLAIM_CONSUMPTION_AND_TRANSPORT_HANDOFF_REQUIRED'
  };

  gate.execution_gate_id =
    sha256Canonical(
      gatePayload(
        gate
      )
    );

  return Object.freeze(
    structuredClone(
      gate
    )
  );
}

export function verifyDisconnectedBroadcastExecutionGateV2(
  gate
){
  requireObject(
    gate,
    'gate'
  );

  if(
    gate.schema !==
      ATAN_FEE_V2_DISCONNECTED_BROADCAST_EXECUTION_GATE_SCHEMA ||
    gate.version !==
      ATAN_FEE_V2_W28_R1_VERSION ||
    gate.status !==
      'DISCONNECTED_BROADCAST_EXECUTION_GATE_VALIDATED' ||
    gate.durable_claim_verified !==
      true ||
    gate.durable_ledger_claim_verified !==
      true ||
    gate.durable_claim_receipt_verified !==
      true ||
    gate.transaction_bytes_verified !==
      true ||
    gate.claim_consumed !==
      false ||
    gate.transport_connected !==
      false ||
    gate.sendrawtransaction_available !==
      false ||
    gate.sendrawtransaction_implementation !==
      false ||
    gate.broadcast_attempted !==
      false ||
    gate.broadcast_allowed !==
      false ||
    gate.broadcast_authority !==
      'NONE' ||
    gate.next_boundary !==
      'ATOMIC_CLAIM_CONSUMPTION_AND_TRANSPORT_HANDOFF_REQUIRED'
  ){
    fail(
      'W28_R1_EXECUTION_GATE_STATE_INVALID'
    );
  }

  const expected =
    sha256Canonical(
      gatePayload(
        gate
      )
    );

  if(
    expected !==
      gate.execution_gate_id
  ){
    fail(
      'W28_R1_EXECUTION_GATE_ID_MISMATCH'
    );
  }

  return true;
}

export async function attemptDisconnectedBroadcastExecutionV2(
  gate
){
  verifyDisconnectedBroadcastExecutionGateV2(
    gate
  );

  fail(
    'W28_R1_BROADCAST_TRANSPORT_DISCONNECTED'
  );
}

export function describeDisconnectedBroadcastExecutionGateV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W28_R1_VERSION,

    requires_verified_w26_authorization:
      true,

    requires_active_durable_w27_claim:
      true,

    requires_active_durable_w27_ledger_claim:
      true,

    durable_receipt_not_trusted_without_ledger:
      true,

    binds_exact_signed_transaction_bytes:
      true,

    claim_consumed_in_w28:
      false,

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
      'ATOMIC_CLAIM_CONSUMPTION_AND_TRANSPORT_HANDOFF_REQUIRED'
  });
}
