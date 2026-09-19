import {
  verifyOwnerBroadcastAuthorizationV2,
  assertOwnerBroadcastCredentialCannotReachTransportV2
} from './fee-abstraction-v2-owner-broadcast-authorization-contract.mjs';

export const ATAN_FEE_V2_W27_DURABLE_BROADCAST_BRIDGE_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_W27_DURABLE_BROADCAST_CLAIM_RECEIPT_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_DURABLE_BROADCAST_AUTHORIZATION_CLAIM_RECEIPT';

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

export async function claimVerifiedOwnerBroadcastAuthorizationDurablyV2({
  ledger,
  authorization,
  challenge,
  current_height,
  verify_owner_signature
}){
  requireObject(
    ledger,
    'ledger'
  );

  await verifyOwnerBroadcastAuthorizationV2({
    authorization,
    challenge,
    current_height,
    verify_owner_signature
  });

  assertOwnerBroadcastCredentialCannotReachTransportV2(
    authorization
  );

  if(typeof ledger.claim !== 'function'){
    fail(
      'W27_LEDGER_CLAIM_REQUIRED'
    );
  }

  const claim =
    await ledger.claim({
      authorization,
      current_height
    });

  return Object.freeze({
    schema:
      ATAN_FEE_V2_W27_DURABLE_BROADCAST_CLAIM_RECEIPT_SCHEMA,

    version:
      ATAN_FEE_V2_W27_DURABLE_BROADCAST_BRIDGE_VERSION,

    status:
      'ACTIVE_DURABLE_BROADCAST_CLAIM',

    authorization_id:
      authorization.authorization_id,

    claim_id:
      claim.claim_id,

    nonce_key:
      claim.nonce_key,

    challenge_id:
      authorization.challenge_id,

    consumption_intent_id:
      authorization.consumption_intent_id,

    guard_id:
      authorization.guard_id,

    signed_transaction_sha256:
      authorization.signed_transaction_sha256,

    valid_until_height:
      authorization.valid_until_height,

    durable_claim_active:
      true,

    replay_protected:
      true,

    broadcast_transport_connected:
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

export async function recoverDurableOwnerBroadcastAuthorizationClaimV2({
  ledger,
  authorization,
  challenge,
  claim_id,
  current_height,
  verify_owner_signature
}){
  requireObject(
    ledger,
    'ledger'
  );

  await verifyOwnerBroadcastAuthorizationV2({
    authorization,
    challenge,
    current_height,
    verify_owner_signature
  });

  assertOwnerBroadcastCredentialCannotReachTransportV2(
    authorization
  );

  if(
    typeof ledger.recover !==
      'function' ||
    typeof ledger.assertActiveClaim !==
      'function'
  ){
    fail(
      'W27_LEDGER_RECOVERY_INTERFACE_REQUIRED'
    );
  }

  await ledger.recover({
    current_height
  });

  const claim =
    await ledger.assertActiveClaim({
      claim_id,
      authorization_id:
        authorization.authorization_id,
      current_height
    });

  if(
    claim.guard_id !==
      authorization.guard_id ||
    claim.challenge_id !==
      authorization.challenge_id ||
    claim.consumption_intent_id !==
      authorization.consumption_intent_id ||
    claim.signed_transaction_sha256 !==
      authorization.signed_transaction_sha256
  ){
    fail(
      'W27_DURABLE_CLAIM_AUTHORIZATION_BINDING_MISMATCH'
    );
  }

  return Object.freeze({
    schema:
      ATAN_FEE_V2_W27_DURABLE_BROADCAST_CLAIM_RECEIPT_SCHEMA,

    version:
      ATAN_FEE_V2_W27_DURABLE_BROADCAST_BRIDGE_VERSION,

    status:
      'ACTIVE_DURABLE_BROADCAST_CLAIM_RECOVERED',

    authorization_id:
      authorization.authorization_id,

    claim_id:
      claim.claim_id,

    nonce_key:
      claim.nonce_key,

    challenge_id:
      authorization.challenge_id,

    consumption_intent_id:
      authorization.consumption_intent_id,

    guard_id:
      authorization.guard_id,

    signed_transaction_sha256:
      authorization.signed_transaction_sha256,

    valid_until_height:
      authorization.valid_until_height,

    durable_claim_active:
      true,

    replay_protected:
      true,

    broadcast_transport_connected:
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

export function describeDurableBroadcastAuthorizationBridgeV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W27_DURABLE_BROADCAST_BRIDGE_VERSION,

    verifies_w26_credential_before_claim:
      true,

    durable_claim_required:
      true,

    authorization_id_replay_protected:
      true,

    owner_nonce_reuse_protected:
      true,

    actual_process_restart_recovery:
      true,

    expired_claim_fail_closed:
      true,

    credential_or_claim_alone_allows_broadcast:
      false,

    broadcast_transport_connected:
      false,

    network_implementation:
      false,

    rpc_implementation:
      false,

    real_signing_implementation:
      false,

    sendrawtransaction_implementation:
      false,

    broadcast_implementation:
      false,

    broadcast_authority:
      'NONE'
  });
}
