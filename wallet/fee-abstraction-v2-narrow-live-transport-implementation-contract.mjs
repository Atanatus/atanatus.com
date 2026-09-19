import crypto from 'node:crypto';

import {
  verifyDisconnectedLiveTransportAdapterBindingV2
} from './fee-abstraction-v2-disconnected-live-transport-adapter-with-journal-guard.mjs';

export const ATAN_FEE_V2_W33_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_W33_CONTRACT_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_NARROW_LIVE_TRANSPORT_IMPLEMENTATION_CONTRACT';

export const ATAN_FEE_V2_W33_TRANSPORT_PROFILE =
  'ATAN_FEE_ABSTRACTION_V2_BROADCAST_TRANSPORT_V1';

export const ATAN_FEE_V2_W33_ALLOWED_RPC_METHOD =
  'sendrawtransaction';

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
        'W33_NONFINITE_NUMBER_FORBIDDEN'
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
          'W33_UNDEFINED_FORBIDDEN'
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
    'W33_CANONICAL_TYPE_FORBIDDEN'
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

export function createNarrowLiveTransportImplementationContractV2({
  w32_binding,
  live_transport_runtime_identity
}){
  requireObject(
    w32_binding,
    'w32_binding'
  );

  requireObject(
    live_transport_runtime_identity,
    'live_transport_runtime_identity'
  );

  verifyDisconnectedLiveTransportAdapterBindingV2(
    w32_binding
  );

  const runtimeId =
    requireHash(
      live_transport_runtime_identity.runtime_id,
      'runtime_id'
    );

  const runtimeConfigHash =
    requireHash(
      live_transport_runtime_identity.config_sha256,
      'config_sha256'
    );

  const binaryHash =
    requireHash(
      live_transport_runtime_identity.binary_sha256,
      'binary_sha256'
    );

  if(
    live_transport_runtime_identity.role !==
      'LIVE_BROADCAST_TRANSPORT' ||
    live_transport_runtime_identity.network !==
      'mainnet' ||
    live_transport_runtime_identity.wallet_enabled !==
      false ||
    live_transport_runtime_identity.signing_enabled !==
      false ||
    live_transport_runtime_identity.transaction_mutation_enabled !==
      false ||
    live_transport_runtime_identity.readonly_observer_reused !==
      false
  ){
    fail(
      'W33_LIVE_TRANSPORT_RUNTIME_IDENTITY_INVALID'
    );
  }

  if(
    live_transport_runtime_identity.rpc_method !==
      ATAN_FEE_V2_W33_ALLOWED_RPC_METHOD
  ){
    fail(
      'W33_RPC_METHOD_NOT_PERMITTED'
    );
  }

  const contract = {
    schema:
      ATAN_FEE_V2_W33_CONTRACT_SCHEMA,

    version:
      ATAN_FEE_V2_W33_VERSION,

    status:
      'NARROW_LIVE_TRANSPORT_CONTRACT_VALIDATED_SHADOW',

    transport_profile_id:
      ATAN_FEE_V2_W33_TRANSPORT_PROFILE,

    runtime_id:
      runtimeId,

    runtime_config_sha256:
      runtimeConfigHash,

    runtime_binary_sha256:
      binaryHash,

    rpc_method:
      ATAN_FEE_V2_W33_ALLOWED_RPC_METHOD,

    rpc_method_count:
      1,

    binding_id:
      w32_binding.binding_id,

    admission_id:
      w32_binding.admission_id,

    attempt_id:
      w32_binding.attempt_id,

    durable_attempt_fingerprint:
      w32_binding.durable_attempt_fingerprint,

    signed_transaction_sha256:
      w32_binding.signed_transaction_sha256,

    signed_transaction_bytes:
      w32_binding.signed_transaction_bytes,

    network_fee_sats:
      String(
        w32_binding.network_fee_sats
      ),

    dispatch_intent_persisted:
      true,

    exact_signed_transaction_required:
      true,

    exact_signed_transaction_bytes_required:
      true,

    transaction_mutation_allowed:
      false,

    wallet_use_allowed:
      false,

    transaction_signing_allowed:
      false,

    automatic_retry_allowed:
      false,

    batch_broadcast_allowed:
      false,

    fallback_transport_allowed:
      false,

    readonly_observer_reuse_allowed:
      false,

    requires_future_explicit_activation:
      true,

    transport_connected:
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
      'AUDIT_AND_BUILD_DISTINCT_LIVE_BROADCAST_RUNTIME_READINESS_NO_BROADCAST'
  };

  contract.contract_id =
    sha256Hex(
      canonicalize({
        schema:
          contract.schema,

        version:
          contract.version,

        transport_profile_id:
          contract.transport_profile_id,

        runtime_id:
          contract.runtime_id,

        runtime_config_sha256:
          contract.runtime_config_sha256,

        runtime_binary_sha256:
          contract.runtime_binary_sha256,

        rpc_method:
          contract.rpc_method,

        binding_id:
          contract.binding_id,

        attempt_id:
          contract.attempt_id,

        signed_transaction_sha256:
          contract.signed_transaction_sha256,

        status:
          contract.status
      })
    );

  return Object.freeze(
    structuredClone(
      contract
    )
  );
}

export function verifyNarrowLiveTransportImplementationContractV2(
  contract
){
  requireObject(
    contract,
    'contract'
  );

  if(
    contract.schema !==
      ATAN_FEE_V2_W33_CONTRACT_SCHEMA ||
    contract.version !==
      ATAN_FEE_V2_W33_VERSION ||
    contract.status !==
      'NARROW_LIVE_TRANSPORT_CONTRACT_VALIDATED_SHADOW' ||
    contract.transport_profile_id !==
      ATAN_FEE_V2_W33_TRANSPORT_PROFILE ||
    contract.rpc_method !==
      ATAN_FEE_V2_W33_ALLOWED_RPC_METHOD ||
    contract.rpc_method_count !==
      1 ||
    contract.dispatch_intent_persisted !==
      true ||
    contract.exact_signed_transaction_required !==
      true ||
    contract.exact_signed_transaction_bytes_required !==
      true ||
    contract.transaction_mutation_allowed !==
      false ||
    contract.wallet_use_allowed !==
      false ||
    contract.transaction_signing_allowed !==
      false ||
    contract.automatic_retry_allowed !==
      false ||
    contract.batch_broadcast_allowed !==
      false ||
    contract.fallback_transport_allowed !==
      false ||
    contract.readonly_observer_reuse_allowed !==
      false ||
    contract.requires_future_explicit_activation !==
      true ||
    contract.transport_connected !==
      false ||
    contract.sendrawtransaction_implementation !==
      false ||
    contract.broadcast_attempted !==
      false ||
    contract.broadcast_allowed !==
      false ||
    contract.broadcast_authority !==
      'NONE' ||
    contract.next_boundary !==
      'AUDIT_AND_BUILD_DISTINCT_LIVE_BROADCAST_RUNTIME_READINESS_NO_BROADCAST'
  ){
    fail(
      'W33_CONTRACT_STATE_INVALID'
    );
  }

  for(const [value, name] of [
    [contract.contract_id, 'contract_id'],
    [contract.runtime_id, 'runtime_id'],
    [contract.runtime_config_sha256, 'runtime_config_sha256'],
    [contract.runtime_binary_sha256, 'runtime_binary_sha256'],
    [contract.binding_id, 'binding_id'],
    [contract.admission_id, 'admission_id'],
    [contract.attempt_id, 'attempt_id'],
    [contract.durable_attempt_fingerprint, 'durable_attempt_fingerprint'],
    [contract.signed_transaction_sha256, 'signed_transaction_sha256']
  ]){
    requireHash(
      value,
      name
    );
  }

  return true;
}

export async function executeNarrowLiveTransportV2(
  contract
){
  verifyNarrowLiveTransportImplementationContractV2(
    contract
  );

  fail(
    'W33_LIVE_TRANSPORT_EXECUTION_NOT_IMPLEMENTED'
  );
}

export function describeW33ContractV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W33_VERSION,

    transport_profile_id:
      ATAN_FEE_V2_W33_TRANSPORT_PROFILE,

    allowed_rpc_method:
      ATAN_FEE_V2_W33_ALLOWED_RPC_METHOD,

    allowed_rpc_method_count:
      1,

    requires_w32_binding:
      true,

    requires_distinct_live_transport_runtime_identity:
      true,

    readonly_observer_reuse_allowed:
      false,

    wallet_use_allowed:
      false,

    transaction_signing_allowed:
      false,

    transaction_mutation_allowed:
      false,

    automatic_retry_allowed:
      false,

    batch_broadcast_allowed:
      false,

    fallback_transport_allowed:
      false,

    sendrawtransaction_implementation:
      false,

    network_implementation:
      false,

    transaction_broadcast:
      false,

    broadcast_authority:
      'NONE',

    next_boundary:
      'AUDIT_AND_BUILD_DISTINCT_LIVE_BROADCAST_RUNTIME_READINESS_NO_BROADCAST'
  });
}
