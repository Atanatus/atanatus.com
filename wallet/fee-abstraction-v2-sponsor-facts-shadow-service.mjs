import {
  deriveSponsorQuoteFactsV2
} from './fee-abstraction-v2-sponsor-facts-observer.mjs';

export const ATAN_FEE_V2_SPONSOR_FACTS_SHADOW_SERVICE_VERSION =
  '1.0.0';

function fail(code){
  throw new Error(code);
}

export function createDisconnectedSponsorFactsShadowServiceV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_SPONSOR_FACTS_SHADOW_SERVICE_VERSION,

    live:
      false,

    readOnly:
      true,

    async observeQuoteFacts(){
      fail(
        'SPONSOR_FACTS_SHADOW_SERVICE_NOT_CONNECTED'
      );
    }
  });
}

export function createInjectedSponsorFactsShadowServiceV2({
  observeQuote
}){
  if(typeof observeQuote !== 'function'){
    fail('SPONSOR_FACTS_OBSERVER_FUNCTION_REQUIRED');
  }

  return Object.freeze({
    version:
      ATAN_FEE_V2_SPONSOR_FACTS_SHADOW_SERVICE_VERSION,

    live:
      false,

    readOnly:
      true,

    async observeQuoteFacts(quote){
      const observation =
        await observeQuote(quote);

      const derived =
        deriveSponsorQuoteFactsV2({
          quote,
          observation
        });

      return Object.freeze({
        service_version:
          ATAN_FEE_V2_SPONSOR_FACTS_SHADOW_SERVICE_VERSION,

        live:
          false,

        read_only:
          true,

        observation,

        derived
      });
    }
  });
}
