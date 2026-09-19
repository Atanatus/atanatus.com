import {
  createInjectedReadonlyMainnetPreflightAdapterV2
} from './fee-abstraction-v2-readonly-mainnet-preflight-adapter-contract.mjs';

export const ATAN_FEE_V2_W23_WRAPPER_BRIDGE_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_W23_WRAPPER_BRIDGE_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_W23_READONLY_WRAPPER_BRIDGE';

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

function normalizeWrapperResponse(
  wrapperResponse
){
  requireObject(
    wrapperResponse,
    'wrapper_response'
  );

  if(
    wrapperResponse.rpc_method !==
      'testmempoolaccept' ||
    wrapperResponse.rpc_http_status !==
      200 ||
    wrapperResponse.rpc_result_count !==
      1 ||
    wrapperResponse.local_rpc_request_count !==
      1 ||
    wrapperResponse.readonly_preflight_call_completed !==
      true ||
    wrapperResponse.transaction_signing_implementation !==
      false ||
    wrapperResponse.sendrawtransaction_implementation !==
      false ||
    wrapperResponse.transaction_broadcast !==
      false ||
    wrapperResponse.broadcast_allowed !==
      false ||
    wrapperResponse.broadcast_authority !==
      'NONE' ||
    typeof wrapperResponse.allowed !==
      'boolean'
  ){
    fail(
      'W23_WRAPPER_RESPONSE_CONTRACT_INVALID'
    );
  }

  const result = {
    allowed:
      wrapperResponse.allowed
  };

  if(
    typeof wrapperResponse.txid ===
      'string' &&
    /^[0-9a-f]{64}$/.test(
      wrapperResponse.txid
    )
  ){
    result.txid =
      wrapperResponse.txid;
  }

  if(
    typeof wrapperResponse.reject_reason ===
      'string' &&
    wrapperResponse.reject_reason.length > 0
  ){
    result['reject-reason'] =
      wrapperResponse.reject_reason;
  }

  return [
    result
  ];
}

export function createW23WrapperBoundReadonlyPreflightAdapterV2({
  run_readonly_wrapper
}){
  if(typeof run_readonly_wrapper !== 'function'){
    fail(
      'W23_READONLY_WRAPPER_RUNNER_REQUIRED'
    );
  }

  let wrapperCallCount =
    0;

  const adapter =
    createInjectedReadonlyMainnetPreflightAdapterV2({
      invoke_readonly_rpc:
        async context => {
          requireObject(
            context,
            'readonly_rpc_context'
          );

          if(
            context.method !==
              'testmempoolaccept' ||
            !Array.isArray(
              context.params
            ) ||
            context.params.length !==
              1 ||
            !Array.isArray(
              context.params[0]
            ) ||
            context.params[0].length !==
              1
          ){
            fail(
              'W23_WRAPPER_BRIDGE_RPC_CONTEXT_INVALID'
            );
          }

          const rawTransactionHex =
            requireString(
              context.params[0][0],
              'raw_transaction_hex'
            );

          if(
            rawTransactionHex.length % 2 !== 0 ||
            !/^[0-9a-f]+$/.test(
              rawTransactionHex
            )
          ){
            fail(
              'W23_WRAPPER_BRIDGE_RAW_TX_HEX_INVALID'
            );
          }

          wrapperCallCount += 1;

          if(wrapperCallCount !== 1){
            fail(
              'W23_WRAPPER_BRIDGE_SINGLE_CALL_VIOLATION'
            );
          }

          const wrapperResponse =
            await run_readonly_wrapper({
              method:
                context.method,

              raw_transaction_hex:
                rawTransactionHex,

              request_id:
                context.request_id
            });

          return normalizeWrapperResponse(
            wrapperResponse
          );
        }
    });

  return Object.freeze({
    schema:
      ATAN_FEE_V2_W23_WRAPPER_BRIDGE_SCHEMA,

    version:
      ATAN_FEE_V2_W23_WRAPPER_BRIDGE_VERSION,

    mode:
      'REAL_LOCAL_READONLY_WRAPPER_BOUND',

    live:
      false,

    broadcast_authority:
      'NONE',

    adapter,

    wrapperCallCount(){
      return wrapperCallCount;
    }
  });
}

export function describeW23WrapperBoundReadonlyPreflightAdapterV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W23_WRAPPER_BRIDGE_VERSION,

    schema:
      ATAN_FEE_V2_W23_WRAPPER_BRIDGE_SCHEMA,

    rpc_method:
      'testmempoolaccept',

    wrapper_role:
      'SEPARATE_NARROW_READONLY_LOCAL_RPC',

    wrapper_call_limit_per_adapter_instance:
      1,

    adapter_contract_reused_from_w22:
      true,

    real_local_mainnet_rpc_expected:
      true,

    real_mainnet_broadcast_expected:
      false,

    network_implementation_embedded:
      false,

    rpc_implementation_embedded:
      false,

    signing_implementation_embedded:
      false,

    sendrawtransaction_implementation:
      false,

    broadcast_implementation_embedded:
      false,

    broadcast_authority:
      'NONE'
  });
}
