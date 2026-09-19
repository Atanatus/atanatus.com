import {
  createExactSponsoredFeeEnvelopeV2
} from './fee-abstraction-v2-exact-fee-planner.mjs';

import {
  validateReadOnlyFeePolicySnapshotV2
} from './fee-abstraction-v2-readonly-fee-policy.mjs';

import {
  createSponsorProtocolShadowState
} from './fee-abstraction-v2-sponsor-shadow-controller.mjs';

import {
  createDisconnectedSponsorTransportV2
} from './fee-abstraction-v2-sponsor-transport-contract.mjs';

export const ATAN_FEE_V2_FEE_POLICY_SHADOW_BRIDGE_VERSION =
  '1.0.0';

function fail(code){
  throw new Error(code);
}

function requireTransport(transport){
  if(
    !transport ||
    typeof transport !== 'object' ||
    typeof transport.discoverQuotes !== 'function' ||
    typeof transport.reserveFunding !== 'function' ||
    typeof transport.acknowledgeAcceptance !== 'function'
  ){
    fail('FEE_POLICY_BRIDGE_TRANSPORT_INVALID');
  }
}

export async function createFeePolicyBoundSponsorShadowV2({
  preview,
  atanCategory,
  feePolicySnapshot,
  nowUnixMs = Date.now(),
  maxFeePolicyAgeMs = 300000,
  userBchInputCount,
  userTokenInputCount,
  ordinaryOutputCount = 3,
  tokenOutputCount = 2,
  safetyMarginBytes = 0,
  requestValidUntilHeight,
  requestNonce,
  sponsorTransport = null
}){
  const policy =
    validateReadOnlyFeePolicySnapshotV2(
      feePolicySnapshot,
      {
        nowUnixMs,
        maxAgeMs:
          maxFeePolicyAgeMs
      }
    );

  const envelope =
    await createExactSponsoredFeeEnvelopeV2({
      user_bch_input_count:
        userBchInputCount,

      user_token_input_count:
        userTokenInputCount,

      fee_rate_sats_per_kb:
        policy.selectedFeeRateSatsPerKb,

      ordinary_output_count:
        ordinaryOutputCount,

      token_output_count:
        tokenOutputCount,

      safety_margin_bytes:
        safetyMarginBytes
    });

  const transport =
    sponsorTransport ||
    createDisconnectedSponsorTransportV2();

  requireTransport(transport);

  const protocolState =
    await createSponsorProtocolShadowState({
      preview,
      atanCategory,

      exactNetworkFeeSats:
        envelope.network_fee_sats,

      currentHeight:
        policy.observedHeight,

      requestValidUntilHeight,
      requestNonce,

      quotes:
        null
    });

  if(
    protocolState.requestStatus !== 'CREATED' ||
    protocolState.quoteStatus !== 'AWAITING_SPONSOR_QUOTES'
  ){
    fail('FEE_POLICY_BRIDGE_PROTOCOL_STATE_INVALID');
  }

  if(
    protocolState.signingAllowed !== false ||
    protocolState.broadcastAllowed !== false
  ){
    fail('FEE_POLICY_BRIDGE_SAFETY_LOCK_INVALID');
  }

  return Object.freeze({
    bridgeVersion:
      ATAN_FEE_V2_FEE_POLICY_SHADOW_BRIDGE_VERSION,

    stage:
      'FEE_POLICY_BOUND_SPONSOR_TRANSPORT_SHADOW',

    feePolicyStatus:
      'BOUND',

    feePolicySource:
      policy.source,

    feePolicySourceClass:
      policy.sourceClass,

    feeEstimator:
      policy.feeEstimator,

    congestionSignal:
      policy.congestionSignal,

    feeRateSatsPerKb:
      policy.selectedFeeRateSatsPerKb,

    feeEnvelope:
      envelope,

    sponsorTransportContractBound:
      true,

    liveSponsorTransportConnected:
      transport.live === true,

    protocolState,

    signingAllowed:
      false,

    broadcastAllowed:
      false
  });
}
