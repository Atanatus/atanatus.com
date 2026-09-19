export const ATAN_FEE_V2_W29_HANDOFF_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_W29_HANDOFF_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_ATOMIC_CLAIM_CONSUMPTION_TRANSPORT_HANDOFF_SHADOW';

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

function requireHash(value, name){
  if(
    typeof value !== 'string' ||
    !/^[0-9a-f]{64}$/.test(
      value
    )
  ){
    fail(
      `${name.toUpperCase()}_HASH_INVALID`
    );
  }

  return value;
}

export function createDisconnectedTransportHandoffReceiptV2({
  execution_gate,
  consumed_claim
}){
  requireObject(
    execution_gate,
    'execution_gate'
  );

  requireObject(
    consumed_claim,
    'consumed_claim'
  );

  const handoffId =
    requireHash(
      consumed_claim.handoff_id,
      'handoff_id'
    );

  if(
    consumed_claim.status !==
      'CONSUMED' ||
    consumed_claim.execution_gate_id !==
      execution_gate.execution_gate_id ||
    consumed_claim.authorization_id !==
      execution_gate.authorization_id ||
    consumed_claim.claim_id !==
      execution_gate.claim_id ||
    consumed_claim.guard_id !==
      execution_gate.guard_id ||
    consumed_claim.signed_transaction_sha256 !==
      execution_gate.signed_transaction_sha256 ||
    consumed_claim.transport_state !==
      'DISCONNECTED_SHADOW' ||
    consumed_claim.sendrawtransaction_implementation !==
      false ||
    consumed_claim.broadcast_attempted !==
      false ||
    consumed_claim.broadcast_allowed !==
      false ||
    consumed_claim.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W29_HANDOFF_CONSUMED_CLAIM_BINDING_INVALID'
    );
  }

  return Object.freeze({
    schema:
      ATAN_FEE_V2_W29_HANDOFF_SCHEMA,

    version:
      ATAN_FEE_V2_W29_HANDOFF_VERSION,

    status:
      'CLAIM_CONSUMED_TRANSPORT_HANDOFF_SHADOW',

    handoff_id:
      handoffId,

    execution_gate_id:
      execution_gate.execution_gate_id,

    authorization_id:
      execution_gate.authorization_id,

    claim_id:
      execution_gate.claim_id,

    guard_id:
      execution_gate.guard_id,

    signed_transaction_sha256:
      execution_gate.signed_transaction_sha256,

    signed_transaction_bytes:
      execution_gate.signed_transaction_bytes,

    network_fee_sats:
      execution_gate.network_fee_sats,

    claim_consumed:
      true,

    claim_reusable:
      false,

    handoff_restart_recoverable:
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
      'LIVE_TRANSPORT_ADAPTER_MUST_REVALIDATE_AND_REQUIRE_EXPLICIT_OWNER_LIVE_BROADCAST_AUTHORIZATION'
  });
}

export function verifyDisconnectedTransportHandoffReceiptV2(
  receipt
){
  requireObject(
    receipt,
    'receipt'
  );

  if(
    receipt.schema !==
      ATAN_FEE_V2_W29_HANDOFF_SCHEMA ||
    receipt.version !==
      ATAN_FEE_V2_W29_HANDOFF_VERSION ||
    receipt.status !==
      'CLAIM_CONSUMED_TRANSPORT_HANDOFF_SHADOW' ||
    receipt.claim_consumed !==
      true ||
    receipt.claim_reusable !==
      false ||
    receipt.handoff_restart_recoverable !==
      true ||
    receipt.transport_connected !==
      false ||
    receipt.sendrawtransaction_available !==
      false ||
    receipt.sendrawtransaction_implementation !==
      false ||
    receipt.broadcast_attempted !==
      false ||
    receipt.broadcast_allowed !==
      false ||
    receipt.broadcast_authority !==
      'NONE' ||
    receipt.next_boundary !==
      'LIVE_TRANSPORT_ADAPTER_MUST_REVALIDATE_AND_REQUIRE_EXPLICIT_OWNER_LIVE_BROADCAST_AUTHORIZATION'
  ){
    fail(
      'W29_HANDOFF_RECEIPT_INVALID'
    );
  }

  requireHash(
    receipt.handoff_id,
    'handoff_id'
  );

  requireHash(
    receipt.execution_gate_id,
    'execution_gate_id'
  );

  requireHash(
    receipt.authorization_id,
    'authorization_id'
  );

  requireHash(
    receipt.claim_id,
    'claim_id'
  );

  requireHash(
    receipt.guard_id,
    'guard_id'
  );

  requireHash(
    receipt.signed_transaction_sha256,
    'signed_transaction_sha256'
  );

  return true;
}

export async function attemptDisconnectedTransportBroadcastV2(
  receipt
){
  verifyDisconnectedTransportHandoffReceiptV2(
    receipt
  );

  fail(
    'W29_LIVE_TRANSPORT_NOT_CONNECTED'
  );
}

export function describeDisconnectedTransportHandoffV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W29_HANDOFF_VERSION,

    claim_consumed:
      true,

    claim_reusable:
      false,

    restart_recoverable:
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
