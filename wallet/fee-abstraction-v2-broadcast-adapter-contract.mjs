import {
  sha256HexV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

export const ATAN_FEE_V2_BROADCAST_ADAPTER_CONTRACT_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_BROADCAST_ADAPTER_CONTRACT_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_BROADCAST_ADAPTER_CONTRACT';

export const ATAN_FEE_V2_BROADCAST_HANDOFF_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_BROADCAST_HANDOFF_SHADOW';

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

function requireBin(value, name){
  if(!(value instanceof Uint8Array)){
    fail(
      `${name.toUpperCase()}_UINT8ARRAY_REQUIRED`
    );
  }

  return value;
}

function binToHex(value){
  return Buffer
    .from(
      requireBin(
        value,
        'binary_value'
      )
    )
    .toString('hex');
}

function equalBins(a, b){
  return (
    a.length === b.length &&
    a.every(
      (value, index) =>
        value === b[index]
    )
  );
}

async function signedTransactionSha256(
  bytes
){
  return sha256HexV2(
    binToHex(
      bytes
    )
  );
}

function assertGuardReadyForHandoff(
  guard
){
  requireObject(
    guard,
    'pre_broadcast_guard'
  );

  if(
    guard.status !==
      'PRE_BROADCAST_VALIDATED'
  ){
    fail(
      'BROADCAST_HANDOFF_GUARD_NOT_VALIDATED'
    );
  }

  if(
    guard.broadcast_allowed !==
      false
  ){
    fail(
      'BROADCAST_HANDOFF_GUARD_AUTHORITY_INVALID'
    );
  }

  if(
    guard.explicit_real_broadcast_authorization_required !==
      true
  ){
    fail(
      'BROADCAST_HANDOFF_EXPLICIT_AUTHORIZATION_REQUIREMENT_MISSING'
    );
  }

  if(
    typeof guard.guard_id !==
      'string' ||
    !/^[0-9a-f]{64}$/.test(
      guard.guard_id
    )
  ){
    fail(
      'BROADCAST_HANDOFF_GUARD_ID_INVALID'
    );
  }

  if(
    typeof guard.signed_transaction_sha256 !==
      'string' ||
    !/^[0-9a-f]{64}$/.test(
      guard.signed_transaction_sha256
    )
  ){
    fail(
      'BROADCAST_HANDOFF_SIGNED_TX_HASH_INVALID'
    );
  }

  if(
    !Number.isSafeInteger(
      guard.signed_transaction_bytes
    ) ||
    guard.signed_transaction_bytes <= 0
  ){
    fail(
      'BROADCAST_HANDOFF_SIGNED_TX_BYTES_INVALID'
    );
  }
}

export function createDisconnectedBroadcastAdapterV2({
  adapter_id =
    'ATAN_FEE_V2_DISCONNECTED_SHADOW_ADAPTER'
} = {}){
  const id =
    requireString(
      adapter_id,
      'adapter_id'
    );

  return Object.freeze({
    schema:
      ATAN_FEE_V2_BROADCAST_ADAPTER_CONTRACT_SCHEMA,

    version:
      ATAN_FEE_V2_BROADCAST_ADAPTER_CONTRACT_VERSION,

    adapter_id:
      id,

    mode:
      'DISCONNECTED_SHADOW_ONLY',

    connected:
      false,

    live:
      false,

    network_implementation:
      false,

    rpc_implementation:
      false,

    sendrawtransaction_implementation:
      false,

    broadcast_authority:
      'NONE',

    async broadcast(){
      fail(
        'BROADCAST_ADAPTER_DISCONNECTED'
      );
    }
  });
}

export async function createBroadcastHandoffShadowV2({
  guard,
  fully_signed_package,
  adapter
}){
  assertGuardReadyForHandoff(
    guard
  );

  requireObject(
    fully_signed_package,
    'fully_signed_package'
  );

  requireObject(
    adapter,
    'adapter'
  );

  if(
    adapter.mode !==
      'DISCONNECTED_SHADOW_ONLY' ||
    adapter.connected !==
      false ||
    adapter.live !==
      false ||
    adapter.network_implementation !==
      false ||
    adapter.rpc_implementation !==
      false ||
    adapter.sendrawtransaction_implementation !==
      false ||
    adapter.broadcast_authority !==
      'NONE'
  ){
    fail(
      'BROADCAST_HANDOFF_ADAPTER_NOT_DISCONNECTED_SHADOW'
    );
  }

  if(
    fully_signed_package
      .transaction_fully_signed !==
      true ||
    fully_signed_package
      .real_transaction_signed !==
      false ||
    fully_signed_package
      .broadcast_allowed !==
      false
  ){
    fail(
      'BROADCAST_HANDOFF_SIGNED_PACKAGE_AUTHORITY_INVALID'
    );
  }

  const bytes =
    requireBin(
      fully_signed_package
        .encoded_transaction,
      'signed_transaction'
    );

  if(
    bytes.length !==
      guard.signed_transaction_bytes
  ){
    fail(
      'BROADCAST_HANDOFF_SIGNED_TX_LENGTH_MISMATCH'
    );
  }

  const hash =
    await signedTransactionSha256(
      bytes
    );

  if(
    hash !==
      guard.signed_transaction_sha256
  ){
    fail(
      'BROADCAST_HANDOFF_SIGNED_TX_HASH_MISMATCH'
    );
  }

  if(
    fully_signed_package
      .economic_core_commitment !==
      guard.economic_core_commitment
  ){
    fail(
      'BROADCAST_HANDOFF_ECONOMIC_CORE_MISMATCH'
    );
  }

  return Object.freeze({
    schema:
      ATAN_FEE_V2_BROADCAST_HANDOFF_SCHEMA,

    version:
      ATAN_FEE_V2_BROADCAST_ADAPTER_CONTRACT_VERSION,

    status:
      'DISCONNECTED_SHADOW',

    adapter_id:
      adapter.adapter_id,

    guard_id:
      guard.guard_id,

    settlement_plan_id:
      guard.settlement_plan_id,

    durable_reservation_id:
      guard.durable_reservation_id,

    signed_transaction_sha256:
      hash,

    signed_transaction_bytes:
      bytes.length,

    economic_core_commitment:
      guard.economic_core_commitment,

    network_fee_sats:
      guard.network_fee_sats,

    encoded_transaction:
      Uint8Array.from(
        bytes
      ),

    adapter_connected:
      false,

    live_transport_connected:
      false,

    explicit_real_broadcast_authorization_present:
      false,

    broadcast_allowed:
      false,

    broadcast_attempted:
      false,

    broadcast_authority:
      'NONE'
  });
}

export async function validateBroadcastHandoffShadowV2({
  handoff,
  guard,
  fully_signed_package,
  adapter
}){
  requireObject(
    handoff,
    'broadcast_handoff'
  );

  if(
    handoff.schema !==
      ATAN_FEE_V2_BROADCAST_HANDOFF_SCHEMA ||
    handoff.version !==
      ATAN_FEE_V2_BROADCAST_ADAPTER_CONTRACT_VERSION ||
    handoff.status !==
      'DISCONNECTED_SHADOW' ||
    handoff.adapter_connected !==
      false ||
    handoff.live_transport_connected !==
      false ||
    handoff.explicit_real_broadcast_authorization_present !==
      false ||
    handoff.broadcast_allowed !==
      false ||
    handoff.broadcast_attempted !==
      false ||
    handoff.broadcast_authority !==
      'NONE'
  ){
    fail(
      'BROADCAST_HANDOFF_HEADER_INVALID'
    );
  }

  const rebuilt =
    await createBroadcastHandoffShadowV2({
      guard,
      fully_signed_package,
      adapter
    });

  if(
    handoff.guard_id !==
      rebuilt.guard_id ||
    handoff.signed_transaction_sha256 !==
      rebuilt.signed_transaction_sha256 ||
    handoff.signed_transaction_bytes !==
      rebuilt.signed_transaction_bytes ||
    handoff.economic_core_commitment !==
      rebuilt.economic_core_commitment ||
    handoff.network_fee_sats !==
      rebuilt.network_fee_sats
  ){
    fail(
      'BROADCAST_HANDOFF_BINDING_MISMATCH'
    );
  }

  if(
    !(
      handoff.encoded_transaction
      instanceof Uint8Array
    ) ||
    !equalBins(
      handoff.encoded_transaction,
      rebuilt.encoded_transaction
    )
  ){
    fail(
      'BROADCAST_HANDOFF_BYTES_MISMATCH'
    );
  }

  return true;
}

export async function attemptBroadcastShadowV2({
  handoff,
  adapter,
  explicit_real_broadcast_authorization =
    false
}){
  requireObject(
    handoff,
    'broadcast_handoff'
  );

  requireObject(
    adapter,
    'adapter'
  );

  if(
    explicit_real_broadcast_authorization ===
      true
  ){
    fail(
      'REAL_BROADCAST_AUTHORIZATION_FORBIDDEN_IN_SHADOW_CONTRACT'
    );
  }

  if(
    explicit_real_broadcast_authorization !==
      false
  ){
    fail(
      'REAL_BROADCAST_AUTHORIZATION_BOOLEAN_REQUIRED'
    );
  }

  if(
    handoff.broadcast_allowed !==
      false ||
    handoff.broadcast_authority !==
      'NONE'
  ){
    fail(
      'BROADCAST_HANDOFF_AUTHORITY_INVALID'
    );
  }

  if(
    adapter.connected !==
      false ||
    adapter.live !==
      false ||
    adapter.broadcast_authority !==
      'NONE'
  ){
    fail(
      'BROADCAST_ADAPTER_SHADOW_STATE_INVALID'
    );
  }

  /*
   * Deliberately do not call adapter.broadcast().
   * W19 proves the contract stops before any transport invocation.
   */
  fail(
    'BROADCAST_BLOCKED_DISCONNECTED_SHADOW'
  );
}

export function describeBroadcastAdapterContractV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_BROADCAST_ADAPTER_CONTRACT_VERSION,

    schema:
      ATAN_FEE_V2_BROADCAST_ADAPTER_CONTRACT_SCHEMA,

    mode:
      'DISCONNECTED_SHADOW_ONLY',

    final_guard_required:
      true,

    signed_transaction_hash_binding_required:
      true,

    economic_core_binding_required:
      true,

    exact_signed_bytes_binding_required:
      true,

    explicit_real_broadcast_authorization_required:
      true,

    explicit_real_broadcast_authorization_supported_in_w19:
      false,

    live_transport_supported_in_w19:
      false,

    sendrawtransaction_implementation:
      false,

    network_implementation:
      false,

    rpc_implementation:
      false,

    real_signing_authority:
      'NONE',

    broadcast_authority:
      'NONE'
  });
}
