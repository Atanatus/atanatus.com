import {
  verifySponsorQuoteSignatureV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

import {
  deriveSponsorQuoteFactsV2
} from './fee-abstraction-v2-sponsor-facts-observer.mjs';

export const ATAN_FEE_V2_AUTH_FACTS_BRIDGE_VERSION =
  '1.0.0';

function fail(code){
  throw new Error(code);
}

export function deriveAuthenticatedSponsorQuoteFactsV2({
  quote,
  observation,
  mainnet
}){
  if(
    !quote ||
    typeof quote !== 'object' ||
    Array.isArray(quote)
  ){
    fail('AUTH_FACTS_QUOTE_REQUIRED');
  }

  if(
    !observation ||
    typeof observation !== 'object' ||
    Array.isArray(observation)
  ){
    fail('AUTH_FACTS_OBSERVATION_REQUIRED');
  }

  if(
    !mainnet ||
    typeof mainnet !== 'object' ||
    !mainnet.SignedMessage ||
    typeof mainnet.SignedMessage.verify !== 'function'
  ){
    fail('AUTH_FACTS_MAINNET_SIGNEDMESSAGE_REQUIRED');
  }

  const chainFacts =
    deriveSponsorQuoteFactsV2({
      quote,
      observation
    });

  const authenticationValid =
    verifySponsorQuoteSignatureV2({
      quote,
      mainnet
    });

  return Object.freeze({
    authentication_valid:
      authenticationValid === true,

    funding_outpoint_unspent:
      chainFacts.protocol_facts
        .funding_outpoint_unspent === true,

    signer_controls_funding_outpoint:
      chainFacts.protocol_facts
        .signer_controls_funding_outpoint === true,

    token_receive_address_token_aware:
      chainFacts.protocol_facts
        .token_receive_address_token_aware === true,

    evidence:
      chainFacts
  });
}
