import {
  createInjectedSponsorTransportV2
} from './fee-abstraction-v2-sponsor-transport-contract.mjs';

export const ATAN_FEE_V2_DURABLE_TRANSPORT_BRIDGE_VERSION =
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
    fail(`${name.toUpperCase()}_OBJECT_REQUIRED`);
  }
}

function requireFunction(value, name){
  if(typeof value !== 'function'){
    fail(`${name.toUpperCase()}_FUNCTION_REQUIRED`);
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

function assertProtocolReservationBinding({
  request,
  quote,
  reservation
}){
  requireObject(
    request,
    'request'
  );

  requireObject(
    quote,
    'quote'
  );

  requireObject(
    reservation,
    'reservation'
  );

  if(
    reservation.request_id !==
    request.request_id
  ){
    fail(
      'DURABLE_TRANSPORT_REQUEST_BINDING_MISMATCH'
    );
  }

  if(
    reservation.quote_id !==
    quote.quote_id
  ){
    fail(
      'DURABLE_TRANSPORT_QUOTE_BINDING_MISMATCH'
    );
  }

  if(
    reservation.sponsor_id !==
    quote.sponsor_id
  ){
    fail(
      'DURABLE_TRANSPORT_SPONSOR_BINDING_MISMATCH'
    );
  }

  if(
    reservation
      .sponsor_funding_outpoint !==
    quote
      .sponsor_funding_outpoint
  ){
    fail(
      'DURABLE_TRANSPORT_OUTPOINT_BINDING_MISMATCH'
    );
  }

  requireString(
    reservation.reservation_id,
    'protocol_reservation_id'
  );

  requireString(
    reservation.reservation_nonce,
    'reservation_nonce'
  );
}

function assertAcceptanceBinding({
  request,
  quote,
  reservation,
  acceptance
}){
  assertProtocolReservationBinding({
    request,
    quote,
    reservation
  });

  requireObject(
    acceptance,
    'acceptance'
  );

  if(
    acceptance.request_id !==
    request.request_id
  ){
    fail(
      'DURABLE_TRANSPORT_ACCEPTANCE_REQUEST_MISMATCH'
    );
  }

  if(
    acceptance.quote_id !==
    quote.quote_id
  ){
    fail(
      'DURABLE_TRANSPORT_ACCEPTANCE_QUOTE_MISMATCH'
    );
  }

  if(
    acceptance.reservation_id !==
    reservation.reservation_id
  ){
    fail(
      'DURABLE_TRANSPORT_ACCEPTANCE_RESERVATION_MISMATCH'
    );
  }

  requireString(
    acceptance.acceptance_id,
    'acceptance_id'
  );
}

function durableMatchesProtocol({
  durable,
  reservation,
  wallet_id
}){
  return (
    durable.request_id ===
      reservation.request_id &&
    durable.quote_id ===
      reservation.quote_id &&
    durable.sponsor_id ===
      reservation.sponsor_id &&
    durable.wallet_id ===
      wallet_id &&
    durable.funding_outpoint ===
      reservation.sponsor_funding_outpoint &&
    durable.created_height ===
      reservation.created_height &&
    durable.valid_until_height ===
      reservation.valid_until_height &&
    durable.reservation_nonce ===
      reservation.reservation_nonce
  );
}

export function createDurableSponsorTransportBridgeV2({
  durableBackend,
  discoverQuotes
}){
  requireObject(
    durableBackend,
    'durable_backend'
  );

  for(const name of [
    'reserve',
    'recoverAll',
    'assertPreSign',
    'inspect'
  ]){
    requireFunction(
      durableBackend[name],
      `durable_backend_${name}`
    );
  }

  requireFunction(
    discoverQuotes,
    'discover_quotes'
  );

  async function findDurableBinding({
    reservation,
    wallet_id
  }){
    requireString(
      wallet_id,
      'wallet_id'
    );

    const ledger =
      await durableBackend
        .inspect();

    requireObject(
      ledger,
      'durable_ledger'
    );

    if(!Array.isArray(ledger.entries)){
      fail(
        'DURABLE_TRANSPORT_LEDGER_ENTRIES_REQUIRED'
      );
    }

    const matches =
      ledger.entries.filter(
        entry =>
          entry &&
          entry.effective_status ===
            'ACTIVE' &&
          entry.reservation &&
          durableMatchesProtocol({
            durable:
              entry.reservation,

            reservation,

            wallet_id
          })
      );

    if(matches.length !== 1){
      fail(
        `DURABLE_BINDING_ACTIVE_COUNT_${matches.length}`
      );
    }

    return matches[0]
      .reservation;
  }

  const transport =
    createInjectedSponsorTransportV2({
      discoverQuotes:
        async context => {
          requireObject(
            context,
            'discover_context'
          );

          return discoverQuotes(
            context
          );
        },

      reserveFunding:
        async context => {
          requireObject(
            context,
            'reservation_context'
          );

          const {
            request,
            quote,
            reservation,
            wallet_id
          } =
            context;

          requireString(
            wallet_id,
            'wallet_id'
          );

          assertProtocolReservationBinding({
            request,
            quote,
            reservation
          });

          const durable =
            await durableBackend
              .reserve({
                request_id:
                  reservation.request_id,

                quote_id:
                  reservation.quote_id,

                sponsor_id:
                  reservation.sponsor_id,

                wallet_id,

                funding_outpoint:
                  reservation
                    .sponsor_funding_outpoint,

                created_height:
                  reservation.created_height,

                valid_until_height:
                  reservation.valid_until_height,

                reservation_nonce:
                  reservation.reservation_nonce
              });

          return {
            status:
              'ACTIVE',

            protocol_reservation_id:
              reservation.reservation_id,

            durable_reservation_id:
              durable.reservation_id,

            funding_outpoint:
              durable.funding_outpoint,

            wallet_id:
              durable.wallet_id
          };
        },

      acknowledgeAcceptance:
        async context => {
          requireObject(
            context,
            'acceptance_context'
          );

          const {
            request,
            quote,
            reservation,
            acceptance,
            wallet_id
          } =
            context;

          requireString(
            wallet_id,
            'wallet_id'
          );

          assertAcceptanceBinding({
            request,
            quote,
            reservation,
            acceptance
          });

          const durable =
            await findDurableBinding({
              reservation,
              wallet_id
            });

          await durableBackend
            .assertPreSign(
              durable.reservation_id
            );

          return {
            status:
              'ACKNOWLEDGED',

            acceptance_id:
              acceptance.acceptance_id,

            protocol_reservation_id:
              reservation.reservation_id,

            durable_reservation_id:
              durable.reservation_id,

            funding_outpoint:
              durable.funding_outpoint,

            wallet_id:
              durable.wallet_id
          };
        }
    });

  if(transport.live !== false){
    fail(
      'DURABLE_TRANSPORT_BRIDGE_MUST_REMAIN_SHADOW'
    );
  }

  return Object.freeze({
    bridge_version:
      ATAN_FEE_V2_DURABLE_TRANSPORT_BRIDGE_VERSION,

    live:
      false,

    transport,

    recoverAll:
      async () =>
        durableBackend
          .recoverAll(),

    inspect:
      async () =>
        durableBackend
          .inspect(),

    findDurableBinding
  });
}

export function describeDurableSponsorTransportBridgeV2(){
  return Object.freeze({
    bridge_version:
      ATAN_FEE_V2_DURABLE_TRANSPORT_BRIDGE_VERSION,

    mode:
      'SHADOW_ONLY',

    transport_contract:
      'ATAN_FEE_V2_SPONSOR_TRANSPORT_CONTRACT',

    reserve_operation:
      'reserveFunding',

    acceptance_operation:
      'acknowledgeAcceptance',

    persistent_reservation_backend:
      'INJECTED',

    protocol_to_durable_binding:
      [
        'request_id',
        'quote_id',
        'sponsor_id',
        'wallet_id',
        'funding_outpoint',
        'created_height',
        'valid_until_height',
        'reservation_nonce'
      ],

    restart_recovery:
      true,

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
