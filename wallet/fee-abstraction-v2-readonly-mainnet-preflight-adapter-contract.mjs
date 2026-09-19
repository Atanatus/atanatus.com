import {
  canonicalizeV2,
  sha256HexV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

export const ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_REQUEST_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_READONLY_MAINNET_PREFLIGHT_REQUEST';

export const ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_RECEIPT_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_READONLY_MAINNET_PREFLIGHT_RECEIPT';

export const ATAN_FEE_V2_REQUIRED_PREFLIGHT_RPC_METHOD =
  'testmempoolaccept';

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

function requireHex(value, name){
  const text =
    requireString(
      value,
      name
    ).toLowerCase();

  if(
    text.length === 0 ||
    text.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(text)
  ){
    fail(
      `${name.toUpperCase()}_HEX_INVALID`
    );
  }

  return text;
}

function requestPayload(request){
  return {
    schema:
      request.schema,

    version:
      request.version,

    rpc_method:
      request.rpc_method,

    guard_id:
      request.guard_id,

    settlement_plan_id:
      request.settlement_plan_id,

    durable_reservation_id:
      request.durable_reservation_id,

    owner_authorization_id:
      request.owner_authorization_id,

    owner_claim_id:
      request.owner_claim_id,

    signed_transaction_sha256:
      request.signed_transaction_sha256,

    economic_core_commitment:
      request.economic_core_commitment,

    signed_transaction_bytes:
      request.signed_transaction_bytes,

    network_fee_sats:
      request.network_fee_sats,

    raw_transaction_hex:
      request.raw_transaction_hex
  };
}

export async function createReadonlyMainnetPreflightRequestV2({
  guard,
  handoff,
  authorization,
  owner_claim,
  raw_transaction_hex
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
    authorization,
    'authorization'
  );

  requireObject(
    owner_claim,
    'owner_claim'
  );

  if(
    guard.status !==
      'PRE_BROADCAST_VALIDATED' ||
    guard.broadcast_allowed !==
      false
  ){
    fail(
      'READONLY_PREFLIGHT_GUARD_INVALID'
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
      'READONLY_PREFLIGHT_HANDOFF_INVALID'
    );
  }

  if(
    authorization.scope !==
      'LIVE_BROADCAST_PREFLIGHT_ONLY' ||
    authorization.broadcast_allowed !==
      false ||
    authorization.broadcast_authority !==
      'NONE'
  ){
    fail(
      'READONLY_PREFLIGHT_AUTHORIZATION_SCOPE_INVALID'
    );
  }

  if(owner_claim.status !== 'ACTIVE'){
    fail(
      'READONLY_PREFLIGHT_OWNER_CLAIM_NOT_ACTIVE'
    );
  }

  if(
    authorization.authorization_id !==
      owner_claim.authorization_id ||
    guard.guard_id !==
      handoff.guard_id ||
    guard.signed_transaction_sha256 !==
      handoff.signed_transaction_sha256 ||
    guard.economic_core_commitment !==
      handoff.economic_core_commitment ||
    guard.signed_transaction_bytes !==
      handoff.signed_transaction_bytes ||
    guard.network_fee_sats !==
      handoff.network_fee_sats
  ){
    fail(
      'READONLY_PREFLIGHT_BINDING_MISMATCH'
    );
  }

  const rawHex =
    requireHex(
      raw_transaction_hex,
      'raw_transaction_hex'
    );

  const rawHash =
    await sha256HexV2(
      rawHex
    );

  if(
    rawHash !==
      guard.signed_transaction_sha256
  ){
    fail(
      'READONLY_PREFLIGHT_RAW_TX_HASH_MISMATCH'
    );
  }

  if(
    rawHex.length / 2 !==
      guard.signed_transaction_bytes
  ){
    fail(
      'READONLY_PREFLIGHT_RAW_TX_LENGTH_MISMATCH'
    );
  }

  const request = {
    schema:
      ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_REQUEST_SCHEMA,

    version:
      ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_VERSION,

    rpc_method:
      ATAN_FEE_V2_REQUIRED_PREFLIGHT_RPC_METHOD,

    guard_id:
      requireHash(
        guard.guard_id,
        'guard_id'
      ),

    settlement_plan_id:
      requireHash(
        guard.settlement_plan_id,
        'settlement_plan_id'
      ),

    durable_reservation_id:
      requireHash(
        guard.durable_reservation_id,
        'durable_reservation_id'
      ),

    owner_authorization_id:
      requireHash(
        authorization.authorization_id,
        'owner_authorization_id'
      ),

    owner_claim_id:
      requireHash(
        owner_claim.claim_id,
        'owner_claim_id'
      ),

    signed_transaction_sha256:
      requireHash(
        guard.signed_transaction_sha256,
        'signed_transaction_sha256'
      ),

    economic_core_commitment:
      requireHash(
        guard.economic_core_commitment,
        'economic_core_commitment'
      ),

    signed_transaction_bytes:
      Number(
        guard.signed_transaction_bytes
      ),

    network_fee_sats:
      String(
        guard.network_fee_sats
      ),

    raw_transaction_hex:
      rawHex,

    params: [
      [
        rawHex
      ]
    ],

    read_only:
      true,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE'
  };

  request.request_id =
    await sha256HexV2(
      canonicalizeV2(
        requestPayload(
          request
        )
      )
    );

  return Object.freeze(
    structuredClone(
      request
    )
  );
}

export function createInjectedReadonlyMainnetPreflightAdapterV2({
  invoke_readonly_rpc
}){
  if(typeof invoke_readonly_rpc !== 'function'){
    fail(
      'READONLY_PREFLIGHT_RPC_INJECTOR_REQUIRED'
    );
  }

  return Object.freeze({
    version:
      ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_VERSION,

    mode:
      'INJECTED_READONLY_PREFLIGHT_SHADOW',

    live:
      false,

    connected:
      false,

    read_only:
      true,

    required_rpc_method:
      ATAN_FEE_V2_REQUIRED_PREFLIGHT_RPC_METHOD,

    network_implementation_embedded:
      false,

    rpc_implementation_embedded:
      false,

    broadcast_implementation_embedded:
      false,

    sendrawtransaction_implementation:
      false,

    broadcast_authority:
      'NONE',

    async preflight(request){
      requireObject(
        request,
        'request'
      );

      if(
        request.rpc_method !==
          ATAN_FEE_V2_REQUIRED_PREFLIGHT_RPC_METHOD ||
        request.read_only !==
          true ||
        request.broadcast_allowed !==
          false ||
        request.broadcast_authority !==
          'NONE'
      ){
        fail(
          'READONLY_PREFLIGHT_REQUEST_AUTHORITY_INVALID'
        );
      }

      const response =
        await invoke_readonly_rpc({
          method:
            ATAN_FEE_V2_REQUIRED_PREFLIGHT_RPC_METHOD,

          params:
            structuredClone(
              request.params
            ),

          request_id:
            request.request_id
        });

      return normalizeReadonlyMainnetPreflightResponseV2({
        request,
        response
      });
    }
  });
}

export function normalizeReadonlyMainnetPreflightResponseV2({
  request,
  response
}){
  requireObject(
    request,
    'request'
  );

  if(
    !Array.isArray(response) ||
    response.length !== 1
  ){
    fail(
      'READONLY_PREFLIGHT_RESPONSE_ARRAY_ONE_REQUIRED'
    );
  }

  const result =
    response[0];

  requireObject(
    result,
    'preflight_result'
  );

  if(typeof result.allowed !== 'boolean'){
    fail(
      'READONLY_PREFLIGHT_ALLOWED_BOOLEAN_REQUIRED'
    );
  }

  let txid;

  if(
    typeof result.txid === 'string' &&
    /^[0-9a-fA-F]{64}$/.test(
      result.txid
    )
  ){
    txid =
      result.txid.toLowerCase();
  }

  const rejectReason =
    typeof result['reject-reason'] ===
      'string'
      ? result['reject-reason']
      : (
          typeof result.reject_reason ===
            'string'
            ? result.reject_reason
            : ''
        );

  return Object.freeze({
    schema:
      ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_RECEIPT_SCHEMA,

    version:
      ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_VERSION,

    status:
      result.allowed
        ? 'ACCEPTED_READONLY'
        : 'REJECTED_READONLY',

    request_id:
      request.request_id,

    rpc_method:
      ATAN_FEE_V2_REQUIRED_PREFLIGHT_RPC_METHOD,

    guard_id:
      request.guard_id,

    owner_authorization_id:
      request.owner_authorization_id,

    owner_claim_id:
      request.owner_claim_id,

    signed_transaction_sha256:
      request.signed_transaction_sha256,

    signed_transaction_bytes:
      request.signed_transaction_bytes,

    network_fee_sats:
      request.network_fee_sats,

    txid,

    allowed:
      result.allowed,

    reject_reason:
      rejectReason,

    read_only:
      true,

    broadcast_attempted:
      false,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE'
  });
}

export function assertReadonlyMainnetPreflightAcceptedV2(
  receipt
){
  requireObject(
    receipt,
    'receipt'
  );

  if(
    receipt.schema !==
      ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_RECEIPT_SCHEMA ||
    receipt.status !==
      'ACCEPTED_READONLY' ||
    receipt.allowed !==
      true ||
    receipt.read_only !==
      true ||
    receipt.broadcast_attempted !==
      false ||
    receipt.broadcast_allowed !==
      false ||
    receipt.broadcast_authority !==
      'NONE'
  ){
    fail(
      'READONLY_MAINNET_PREFLIGHT_NOT_ACCEPTED'
    );
  }

  return true;
}

export function describeReadonlyMainnetPreflightAdapterV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_READONLY_MAINNET_PREFLIGHT_VERSION,

    required_rpc_method:
      ATAN_FEE_V2_REQUIRED_PREFLIGHT_RPC_METHOD,

    semantic_role:
      'MEMPOOL_POLICY_ACCEPTANCE_CHECK_ONLY',

    current_observer_wrapper_expected_to_support_method:
      false,

    existing_observer_wrapper_must_not_be_weakened:
      true,

    separate_narrow_readonly_wrapper_required:
      true,

    signed_transaction_hash_binding_required:
      true,

    owner_preflight_authorization_required:
      true,

    active_durable_owner_claim_required:
      true,

    network_implementation_embedded:
      false,

    rpc_implementation_embedded:
      false,

    broadcast_implementation_embedded:
      false,

    sendrawtransaction_implementation:
      false,

    broadcast_authority:
      'NONE'
  });
}
