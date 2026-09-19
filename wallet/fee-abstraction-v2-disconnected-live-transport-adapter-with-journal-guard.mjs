import crypto from 'node:crypto';

import {
  verifyLiveTransportAdmissionBoundaryV2
} from './fee-abstraction-v2-live-transport-adapter-revalidation-boundary.mjs';

export const ATAN_FEE_V2_W32_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_W32_BINDING_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_DISCONNECTED_LIVE_TRANSPORT_ADAPTER_JOURNAL_BINDING';

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
        'W32_NONFINITE_NUMBER_FORBIDDEN'
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
          'W32_UNDEFINED_FORBIDDEN'
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
    'W32_CANONICAL_TYPE_FORBIDDEN'
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

function assertDispatchIntentShape(
  attempt
){
  requireObject(
    attempt,
    'attempt'
  );

  if(
    attempt.status !==
      'DISPATCH_INTENT_PERSISTED' ||
    attempt.dispatch_intent_persisted !==
      true ||
    attempt.outcome_known !==
      false ||
    attempt.automatic_retry_allowed !==
      false ||
    attempt.read_only_reconciliation_required !==
      true ||
    attempt.transport_connected !==
      false ||
    attempt.sendrawtransaction_implementation !==
      false ||
    attempt.broadcast_attempted !==
      false ||
    attempt.broadcast_allowed !==
      false ||
    attempt.broadcast_authority !==
      'NONE'
  ){
    fail(
      'W32_DISPATCH_INTENT_STATE_INVALID'
    );
  }

  requireHash(
    attempt.attempt_id,
    'attempt_id'
  );

  requireHash(
    attempt.admission_id,
    'admission_id'
  );

  requireHash(
    attempt.handoff_id,
    'handoff_id'
  );

  requireHash(
    attempt.execution_gate_id,
    'execution_gate_id'
  );

  requireHash(
    attempt.claim_id,
    'claim_id'
  );

  requireHash(
    attempt.live_authorization_id,
    'live_authorization_id'
  );

  requireHash(
    attempt.fresh_preflight_request_id,
    'fresh_preflight_request_id'
  );

  requireHash(
    attempt.signed_transaction_sha256,
    'signed_transaction_sha256'
  );

  return true;
}

function assertAttemptAdmissionBinding({
  attempt,
  admission
}){
  if(
    attempt.admission_id !==
      admission.admission_id ||
    attempt.handoff_id !==
      admission.handoff_id ||
    attempt.execution_gate_id !==
      admission.execution_gate_id ||
    attempt.claim_id !==
      admission.claim_id ||
    attempt.live_authorization_id !==
      admission.live_authorization_id ||
    attempt.fresh_preflight_request_id !==
      admission.fresh_preflight_request_id ||
    attempt.signed_transaction_sha256 !==
      admission.signed_transaction_sha256 ||
    Number(
      attempt.signed_transaction_bytes
    ) !==
      Number(
        admission.signed_transaction_bytes
      ) ||
    String(
      attempt.network_fee_sats
    ) !==
      String(
        admission.network_fee_sats
      ) ||
    attempt.transport_profile_id !==
      admission.transport_profile_id
  ){
    fail(
      'W32_ATTEMPT_ADMISSION_BINDING_MISMATCH'
    );
  }

  return true;
}

function durableAttemptFingerprint(
  attempt
){
  return sha256Hex(
    canonicalize({
      attempt_id:
        attempt.attempt_id,

      admission_id:
        attempt.admission_id,

      handoff_id:
        attempt.handoff_id,

      execution_gate_id:
        attempt.execution_gate_id,

      claim_id:
        attempt.claim_id,

      live_authorization_id:
        attempt.live_authorization_id,

      fresh_preflight_request_id:
        attempt.fresh_preflight_request_id,

      signed_transaction_sha256:
        attempt.signed_transaction_sha256,

      signed_transaction_bytes:
        Number(
          attempt.signed_transaction_bytes
        ),

      network_fee_sats:
        String(
          attempt.network_fee_sats
        ),

      transport_profile_id:
        attempt.transport_profile_id,

      status:
        attempt.status,

      dispatch_intent_persisted:
        attempt.dispatch_intent_persisted,

      outcome_known:
        attempt.outcome_known,

      automatic_retry_allowed:
        attempt.automatic_retry_allowed,

      read_only_reconciliation_required:
        attempt.read_only_reconciliation_required
    })
  );
}

export async function createDisconnectedLiveTransportAdapterBindingV2({
  journal,
  admission,
  dispatch_intent_receipt
}){
  requireObject(
    journal,
    'journal'
  );

  requireObject(
    admission,
    'admission'
  );

  requireObject(
    dispatch_intent_receipt,
    'dispatch_intent_receipt'
  );

  if(typeof journal.inspect !== 'function'){
    fail(
      'W32_TRUSTED_JOURNAL_INSPECT_REQUIRED'
    );
  }

  verifyLiveTransportAdmissionBoundaryV2(
    admission
  );

  assertDispatchIntentShape(
    dispatch_intent_receipt
  );

  assertAttemptAdmissionBinding({
    attempt:
      dispatch_intent_receipt,

    admission
  });

  const state =
    await journal.inspect();

  if(
    !state ||
    !Array.isArray(
      state.attempts
    )
  ){
    fail(
      'W32_JOURNAL_STATE_INVALID'
    );
  }

  const durableAttempt =
    state.attempts.find(
      attempt =>
        attempt.attempt_id ===
          dispatch_intent_receipt.attempt_id
    );

  if(!durableAttempt){
    fail(
      'W32_DURABLE_ATTEMPT_NOT_FOUND'
    );
  }

  assertDispatchIntentShape(
    durableAttempt
  );

  assertAttemptAdmissionBinding({
    attempt:
      durableAttempt,

    admission
  });

  const receiptFingerprint =
    durableAttemptFingerprint(
      dispatch_intent_receipt
    );

  const durableFingerprint =
    durableAttemptFingerprint(
      durableAttempt
    );

  if(
    receiptFingerprint !==
      durableFingerprint
  ){
    fail(
      'W32_DISPATCH_RECEIPT_DURABLE_STATE_MISMATCH'
    );
  }

  const binding = {
    schema:
      ATAN_FEE_V2_W32_BINDING_SCHEMA,

    version:
      ATAN_FEE_V2_W32_VERSION,

    status:
      'DISCONNECTED_LIVE_TRANSPORT_ADAPTER_VALIDATED',

    admission_id:
      admission.admission_id,

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

    attempt_id:
      durableAttempt.attempt_id,

    durable_attempt_fingerprint:
      durableFingerprint,

    signed_transaction_sha256:
      admission.signed_transaction_sha256,

    signed_transaction_bytes:
      admission.signed_transaction_bytes,

    network_fee_sats:
      String(
        admission.network_fee_sats
      ),

    transport_profile_id:
      admission.transport_profile_id,

    journal_guard_verified:
      true,

    dispatch_intent_persisted:
      true,

    durable_state_revalidated_directly:
      true,

    automatic_retry_allowed:
      false,

    read_only_reconciliation_required_if_outcome_unknown:
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
      'NARROW_LIVE_TRANSPORT_IMPLEMENTATION_CONTRACT_WITHOUT_EXECUTION'
  };

  binding.binding_id =
    sha256Hex(
      canonicalize({
        schema:
          binding.schema,

        version:
          binding.version,

        admission_id:
          binding.admission_id,

        attempt_id:
          binding.attempt_id,

        durable_attempt_fingerprint:
          binding.durable_attempt_fingerprint,

        signed_transaction_sha256:
          binding.signed_transaction_sha256,

        transport_profile_id:
          binding.transport_profile_id,

        status:
          binding.status
      })
    );

  return Object.freeze(
    structuredClone(
      binding
    )
  );
}

export function verifyDisconnectedLiveTransportAdapterBindingV2(
  binding
){
  requireObject(
    binding,
    'binding'
  );

  if(
    binding.schema !==
      ATAN_FEE_V2_W32_BINDING_SCHEMA ||
    binding.version !==
      ATAN_FEE_V2_W32_VERSION ||
    binding.status !==
      'DISCONNECTED_LIVE_TRANSPORT_ADAPTER_VALIDATED' ||
    binding.journal_guard_verified !==
      true ||
    binding.dispatch_intent_persisted !==
      true ||
    binding.durable_state_revalidated_directly !==
      true ||
    binding.automatic_retry_allowed !==
      false ||
    binding.read_only_reconciliation_required_if_outcome_unknown !==
      true ||
    binding.transport_connected !==
      false ||
    binding.sendrawtransaction_available !==
      false ||
    binding.sendrawtransaction_implementation !==
      false ||
    binding.broadcast_attempted !==
      false ||
    binding.broadcast_allowed !==
      false ||
    binding.broadcast_authority !==
      'NONE' ||
    binding.next_boundary !==
      'NARROW_LIVE_TRANSPORT_IMPLEMENTATION_CONTRACT_WITHOUT_EXECUTION'
  ){
    fail(
      'W32_BINDING_STATE_INVALID'
    );
  }

  requireHash(
    binding.binding_id,
    'binding_id'
  );

  requireHash(
    binding.admission_id,
    'admission_id'
  );

  requireHash(
    binding.attempt_id,
    'attempt_id'
  );

  requireHash(
    binding.durable_attempt_fingerprint,
    'durable_attempt_fingerprint'
  );

  requireHash(
    binding.signed_transaction_sha256,
    'signed_transaction_sha256'
  );

  return true;
}

export async function attemptDisconnectedLiveTransportV2(
  binding
){
  verifyDisconnectedLiveTransportAdapterBindingV2(
    binding
  );

  fail(
    'W32_LIVE_TRANSPORT_DISCONNECTED'
  );
}

export function describeW32DisconnectedTransportAdapterV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W32_VERSION,

    requires_w30_admission:
      true,

    requires_w31_dispatch_intent_persisted:
      true,

    trusts_dispatch_receipt_without_journal:
      false,

    revalidates_durable_attempt_directly:
      true,

    automatic_retry_allowed:
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
      'NARROW_LIVE_TRANSPORT_IMPLEMENTATION_CONTRACT_WITHOUT_EXECUTION'
  });
}
