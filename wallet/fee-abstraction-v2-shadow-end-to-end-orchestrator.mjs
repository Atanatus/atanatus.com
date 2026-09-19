import {
  createExactSponsoredFeeEnvelopeV2,
  validateExactSponsoredFeeEnvelopeV2
} from './fee-abstraction-v2-exact-fee-planner.mjs';

import {
  createFeeRequestV2,
  validateSponsorQuoteV2,
  selectSponsorQuoteV2,
  createReservationV2,
  createAcceptanceV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

import {
  deriveAuthenticatedSponsorQuoteFactsV2
} from './fee-abstraction-v2-sponsor-auth-facts-bridge.mjs';

export const ATAN_FEE_V2_SHADOW_ORCHESTRATOR_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_SHADOW_ORCHESTRATOR_STAGE =
  'AUTH_FACTS_TRANSPORT_DURABILITY_CONNECTED';

function fail(code){
  throw new Error(code);
}

function requireObject(value, name){
  if(
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ){
    fail(`${name.toUpperCase()}_OBJECT_REQUIRED`);
  }
}

function requireString(value, name){
  if(
    typeof value !== 'string' ||
    value.length === 0
  ){
    fail(`${name.toUpperCase()}_STRING_REQUIRED`);
  }
}

function requireHeight(value, name){
  if(
    !Number.isSafeInteger(value) ||
    value < 0
  ){
    fail(`${name.toUpperCase()}_HEIGHT_INVALID`);
  }
}

function requireTransportBridge(
  durableTransportBridge
){
  requireObject(
    durableTransportBridge,
    'durable_transport_bridge'
  );

  if(
    durableTransportBridge.live !==
    false
  ){
    fail(
      'SHADOW_ORCHESTRATOR_LIVE_BRIDGE_FORBIDDEN'
    );
  }

  requireObject(
    durableTransportBridge.transport,
    'durable_transport'
  );

  if(
    durableTransportBridge
      .transport
      .live !==
    false
  ){
    fail(
      'SHADOW_ORCHESTRATOR_LIVE_TRANSPORT_FORBIDDEN'
    );
  }

  for(const operation of [
    'discoverQuotes',
    'reserveFunding',
    'acknowledgeAcceptance'
  ]){
    if(
      typeof durableTransportBridge
        .transport[
          operation
        ] !==
      'function'
    ){
      fail(
        `SHADOW_ORCHESTRATOR_TRANSPORT_OPERATION_MISSING:${operation}`
      );
    }
  }
}

function requireMainnet(mainnet){
  requireObject(
    mainnet,
    'mainnet'
  );

  if(
    !mainnet.SignedMessage ||
    typeof mainnet
      .SignedMessage
      .verify !==
      'function'
  ){
    fail(
      'SHADOW_ORCHESTRATOR_SIGNEDMESSAGE_VERIFY_REQUIRED'
    );
  }
}

function requireCandidateBundle(bundle){
  requireObject(
    bundle,
    'sponsor_candidate_bundle'
  );

  requireObject(
    bundle.quote,
    'sponsor_candidate_quote'
  );

  requireObject(
    bundle.observation,
    'sponsor_candidate_observation'
  );
}

export async function createSponsoredFeeShadowOrchestrationV2({
  durableTransportBridge,
  mainnet,
  network = 'mainnet',
  token_category,
  recipient,
  payment_sats,
  fee_rate_sats_per_kb,
  user_bch_input_count = 1,
  user_token_input_count = 1,
  ordinary_output_count = 3,
  token_output_count = 2,
  safety_margin_bytes = 0,
  current_height,
  request_valid_until_height,
  request_nonce,
  reservation_valid_until_height,
  reservation_nonce,
  acceptance_nonce,
  wallet_id
}){
  requireTransportBridge(
    durableTransportBridge
  );

  requireMainnet(
    mainnet
  );

  requireString(
    network,
    'network'
  );

  requireString(
    token_category,
    'token_category'
  );

  requireString(
    recipient,
    'recipient'
  );

  requireString(
    String(payment_sats),
    'payment_sats'
  );

  requireString(
    String(fee_rate_sats_per_kb),
    'fee_rate_sats_per_kb'
  );

  requireHeight(
    current_height,
    'current_height'
  );

  requireHeight(
    request_valid_until_height,
    'request_valid_until_height'
  );

  requireHeight(
    reservation_valid_until_height,
    'reservation_valid_until_height'
  );

  requireString(
    request_nonce,
    'request_nonce'
  );

  requireString(
    reservation_nonce,
    'reservation_nonce'
  );

  requireString(
    acceptance_nonce,
    'acceptance_nonce'
  );

  requireString(
    wallet_id,
    'wallet_id'
  );

  if(
    request_valid_until_height <
    current_height
  ){
    fail(
      'SHADOW_ORCHESTRATOR_REQUEST_ALREADY_EXPIRED'
    );
  }

  if(
    reservation_valid_until_height <
    current_height
  ){
    fail(
      'SHADOW_ORCHESTRATOR_RESERVATION_ALREADY_EXPIRED'
    );
  }

  const envelope =
    await createExactSponsoredFeeEnvelopeV2({
      user_bch_input_count,
      user_token_input_count,
      fee_rate_sats_per_kb:
        String(
          fee_rate_sats_per_kb
        ),
      ordinary_output_count,
      token_output_count,
      safety_margin_bytes
    });

  await validateExactSponsoredFeeEnvelopeV2(
    envelope
  );

  const request =
    await createFeeRequestV2({
      network,
      token_category,
      recipient,
      payment_sats:
        String(
          payment_sats
        ),
      network_fee_sats:
        envelope.network_fee_sats,
      valid_until_height:
        request_valid_until_height,
      request_nonce
    });

  const discovered =
    await durableTransportBridge
      .transport
      .discoverQuotes({
        request,
        envelope,
        current_height
      });

  if(
    !Array.isArray(discovered) ||
    discovered.length === 0
  ){
    fail(
      'SHADOW_ORCHESTRATOR_NO_SPONSOR_CANDIDATES'
    );
  }

  const quotes = [];
  const factsByQuoteId = {};
  const observationsByQuoteId = {};

  for(const bundle of discovered){
    requireCandidateBundle(
      bundle
    );

    const quote =
      bundle.quote;

    await validateSponsorQuoteV2(
      request,
      quote
    );

    const facts =
      deriveAuthenticatedSponsorQuoteFactsV2({
        quote,
        observation:
          bundle.observation,
        mainnet
      });

    quotes.push(
      quote
    );

    factsByQuoteId[
      quote.quote_id
    ] =
      facts;

    observationsByQuoteId[
      quote.quote_id
    ] =
      bundle.observation;
  }

  const selection =
    await selectSponsorQuoteV2({
      request,
      quotes,
      factsByQuoteId,
      currentHeight:
        current_height
    });

  requireObject(
    selection.selected_quote,
    'selected_quote'
  );

  const selectedQuote =
    selection.selected_quote;

  const selectedFacts =
    factsByQuoteId[
      selectedQuote.quote_id
    ];

  if(!selectedFacts){
    fail(
      'SHADOW_ORCHESTRATOR_SELECTED_FACTS_MISSING'
    );
  }

  const reservation =
    await createReservationV2({
      request,
      quote:
        selectedQuote,
      current_height,
      valid_until_height:
        reservation_valid_until_height,
      reservation_nonce,
      facts:
        selectedFacts
    });

  const durableReservation =
    await durableTransportBridge
      .transport
      .reserveFunding({
        request,
        quote:
          selectedQuote,
        reservation,
        wallet_id
      });

  if(
    durableReservation.status !==
    'ACTIVE'
  ){
    fail(
      'SHADOW_ORCHESTRATOR_DURABLE_RESERVATION_NOT_ACTIVE'
    );
  }

  const acceptance =
    await createAcceptanceV2({
      request,
      quote:
        selectedQuote,
      reservation,
      current_height,
      acceptance_nonce,
      facts:
        selectedFacts
    });

  const acknowledgement =
    await durableTransportBridge
      .transport
      .acknowledgeAcceptance({
        request,
        quote:
          selectedQuote,
        reservation,
        acceptance,
        wallet_id
      });

  if(
    acknowledgement.status !==
    'ACKNOWLEDGED'
  ){
    fail(
      'SHADOW_ORCHESTRATOR_ACCEPTANCE_NOT_ACKNOWLEDGED'
    );
  }

  return Object.freeze({
    orchestrator_version:
      ATAN_FEE_V2_SHADOW_ORCHESTRATOR_VERSION,

    stage:
      ATAN_FEE_V2_SHADOW_ORCHESTRATOR_STAGE,

    shadow:
      true,

    exact_fee_envelope:
      envelope,

    request,

    discovery_count:
      discovered.length,

    selected_quote:
      selectedQuote,

    selected_facts:
      selectedFacts,

    selected_observation:
      observationsByQuoteId[
        selectedQuote.quote_id
      ],

    reservation,

    durable_reservation:
      durableReservation,

    acceptance,

    acknowledgement,

    signing_allowed:
      false,

    broadcast_allowed:
      false,

    live_sponsor_transport_connected:
      false,

    ready_for_shadow_settlement_planning:
      true
  });
}

export function describeSponsoredFeeShadowOrchestratorV2(){
  return Object.freeze({
    orchestrator_version:
      ATAN_FEE_V2_SHADOW_ORCHESTRATOR_VERSION,

    stage:
      ATAN_FEE_V2_SHADOW_ORCHESTRATOR_STAGE,

    exact_fee_planner:
      true,

    sponsor_protocol:
      true,

    signed_message_authentication:
      true,

    chain_fact_derivation:
      true,

    durable_transport_reservation:
      true,

    acceptance_revalidation:
      true,

    live_transport:
      false,

    signing_authority:
      'NONE',

    broadcast_authority:
      'NONE',

    network_implementation_embedded:
      false,

    rpc_implementation_embedded:
      false
  });
}
