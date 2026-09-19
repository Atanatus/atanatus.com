export const ATAN_FEE_V2_SPONSOR_TRANSPORT_CONTRACT_VERSION =
  '1.0.0';

function fail(code){
  throw new Error(code);
}

function requireFunction(
  value,
  field
){
  if(typeof value !== 'function'){
    fail(
      `TRANSPORT_FUNCTION_REQUIRED:${field}`
    );
  }
}

function requireObject(
  value,
  field
){
  if(
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ){
    fail(
      `TRANSPORT_OBJECT_REQUIRED:${field}`
    );
  }
}

export function createDisconnectedSponsorTransportV2(){
  const disconnected =
    async () => {
      fail(
        'LIVE_SPONSOR_TRANSPORT_NOT_CONNECTED'
      );
    };

  return Object.freeze({
    contract_version:
      ATAN_FEE_V2_SPONSOR_TRANSPORT_CONTRACT_VERSION,

    live:
      false,

    discoverQuotes:
      disconnected,

    reserveFunding:
      disconnected,

    acknowledgeAcceptance:
      disconnected
  });
}

export function createInjectedSponsorTransportV2({
  discoverQuotes,
  reserveFunding,
  acknowledgeAcceptance
}){
  requireFunction(
    discoverQuotes,
    'discoverQuotes'
  );

  requireFunction(
    reserveFunding,
    'reserveFunding'
  );

  requireFunction(
    acknowledgeAcceptance,
    'acknowledgeAcceptance'
  );

  return Object.freeze({
    contract_version:
      ATAN_FEE_V2_SPONSOR_TRANSPORT_CONTRACT_VERSION,

    live:
      false,

    discoverQuotes:
      async context => {
        requireObject(
          context,
          'discover_context'
        );

        const result =
          await discoverQuotes(
            context
          );

        if(!Array.isArray(result)){
          fail(
            'TRANSPORT_DISCOVERY_RESULT_MUST_BE_ARRAY'
          );
        }

        return result;
      },

    reserveFunding:
      async context => {
        requireObject(
          context,
          'reservation_context'
        );

        const result =
          await reserveFunding(
            context
          );

        requireObject(
          result,
          'reservation_result'
        );

        if(
          result.status !==
          'ACTIVE'
        ){
          fail(
            'TRANSPORT_RESERVATION_NOT_ACTIVE'
          );
        }

        return result;
      },

    acknowledgeAcceptance:
      async context => {
        requireObject(
          context,
          'acceptance_context'
        );

        const result =
          await acknowledgeAcceptance(
            context
          );

        requireObject(
          result,
          'acceptance_result'
        );

        if(
          result.status !==
          'ACKNOWLEDGED'
        ){
          fail(
            'TRANSPORT_ACCEPTANCE_NOT_ACKNOWLEDGED'
          );
        }

        return result;
      }
  });
}

export function describeSponsorTransportContractV2(){
  return Object.freeze({
    contract_version:
      ATAN_FEE_V2_SPONSOR_TRANSPORT_CONTRACT_VERSION,

    transport_agnostic:
      true,

    network_implementation_embedded:
      false,

    required_operations: [
      'discoverQuotes',
      'reserveFunding',
      'acknowledgeAcceptance'
    ],

    discovery_result:
      'ARRAY_OF_SPONSOR_QUOTES',

    reservation_result_status:
      'ACTIVE',

    acceptance_result_status:
      'ACKNOWLEDGED',

    signing_authority:
      'NONE',

    broadcast_authority:
      'NONE'
  });
}
