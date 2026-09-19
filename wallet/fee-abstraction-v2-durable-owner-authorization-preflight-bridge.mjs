import {
  verifyOwnerPreflightAuthorizationV2,
  executeOwnerAuthorizedPreflightV2
} from './fee-abstraction-v2-owner-authorization-preflight-contract.mjs';

export const ATAN_FEE_V2_DURABLE_OWNER_AUTH_BRIDGE_VERSION =
  '1.0.0';

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

function requireBackend(
  ledger_backend
){
  requireObject(
    ledger_backend,
    'ledger_backend'
  );

  for(const method of [
    'claim',
    'recover',
    'assertClaimUsable',
    'consume',
    'inspect',
    'getEntry'
  ]){
    if(
      typeof ledger_backend[method] !==
        'function'
    ){
      fail(
        `OWNER_AUTH_LEDGER_BACKEND_METHOD_REQUIRED:${method}`
      );
    }
  }

  return ledger_backend;
}

export async function claimVerifiedOwnerAuthorizationV2({
  ledger_backend,
  authorization,
  guard,
  handoff,
  mainnet,
  current_height
}){
  const backend =
    requireBackend(
      ledger_backend
    );

  await verifyOwnerPreflightAuthorizationV2({
    authorization,
    guard,
    handoff,
    mainnet,
    current_height
  });

  const claim =
    backend.claim({
      authorization,
      current_height
    });

  return Object.freeze({
    status:
      'OWNER_AUTHORIZATION_CLAIMED_DURABLY',

    claim,

    authorization_id:
      authorization.authorization_id,

    guard_id:
      guard.guard_id,

    signed_transaction_sha256:
      guard.signed_transaction_sha256,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE'
  });
}

export async function resumeClaimedOwnerAuthorizationPreflightV2({
  ledger_backend,
  claim_id,
  authorization,
  guard,
  handoff,
  mainnet,
  current_height,
  preflight_contract
}){
  const backend =
    requireBackend(
      ledger_backend
    );

  await verifyOwnerPreflightAuthorizationV2({
    authorization,
    guard,
    handoff,
    mainnet,
    current_height
  });

  const activeClaim =
    backend.assertClaimUsable({
      claim_id,
      authorization,
      current_height
    });

  const receipt =
    await executeOwnerAuthorizedPreflightV2({
      authorization,
      guard,
      handoff,
      mainnet,
      current_height,
      preflight_contract
    });

  const consumed =
    backend.consume({
      claim_id:
        activeClaim.claim_id,

      authorization,

      preflight_receipt:
        receipt,

      current_height
    });

  return Object.freeze({
    status:
      'OWNER_AUTHORIZATION_PREFLIGHT_CONSUMED',

    claim:
      activeClaim,

    consumed,

    receipt,

    broadcast_attempted:
      false,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE'
  });
}

export async function executeDurableOwnerAuthorizedPreflightV2({
  ledger_backend,
  authorization,
  guard,
  handoff,
  mainnet,
  current_height,
  preflight_contract
}){
  const claimed =
    await claimVerifiedOwnerAuthorizationV2({
      ledger_backend,
      authorization,
      guard,
      handoff,
      mainnet,
      current_height
    });

  return resumeClaimedOwnerAuthorizationPreflightV2({
    ledger_backend,
    claim_id:
      claimed.claim.claim_id,
    authorization,
    guard,
    handoff,
    mainnet,
    current_height,
    preflight_contract
  });
}

export function describeDurableOwnerAuthorizationBridgeV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_DURABLE_OWNER_AUTH_BRIDGE_VERSION,

    authorization_crypto_verified_before_claim:
      true,

    durable_claim_persisted_before_preflight:
      true,

    preflight_receipt_required_before_consumption:
      true,

    consumed_authorization_replay_allowed:
      false,

    nonce_reuse_allowed:
      false,

    restart_resume_supported:
      true,

    failed_preflight_leaves_claim_active_for_same_claim_resume:
      true,

    real_owner_authorization_consumed:
      false,

    live_network_implementation:
      false,

    broadcast_implementation:
      false,

    broadcast_authority:
      'NONE'
  });
}
