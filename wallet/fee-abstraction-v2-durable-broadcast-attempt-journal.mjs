import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

import {
  verifyLiveTransportAdmissionBoundaryV2
} from './fee-abstraction-v2-live-transport-adapter-revalidation-boundary.mjs';

export const ATAN_FEE_V2_W31_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_W31_JOURNAL_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_DURABLE_BROADCAST_ATTEMPT_JOURNAL';

const STATUS_PREPARED =
  'PREPARED';

const STATUS_DISPATCH_INTENT_PERSISTED =
  'DISPATCH_INTENT_PERSISTED';

const STATUS_AMBIGUOUS_RECONCILIATION_REQUIRED =
  'AMBIGUOUS_RECONCILIATION_REQUIRED';

const STATUS_AMBIGUOUS_NOT_OBSERVED =
  'AMBIGUOUS_NOT_OBSERVED';

const STATUS_BROADCAST_OBSERVED =
  'BROADCAST_OBSERVED';

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

function requireHeight(value, name){
  const number =
    Number(value);

  if(
    !Number.isSafeInteger(number) ||
    number < 0
  ){
    fail(
      `${name.toUpperCase()}_HEIGHT_INVALID`
    );
  }

  return number;
}

function requireNonce(value){
  const text =
    requireString(
      value,
      'attempt_nonce'
    );

  if(text.length < 16){
    fail(
      'W31_ATTEMPT_NONCE_TOO_SHORT'
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
        'W31_NONFINITE_NUMBER_FORBIDDEN'
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
          'W31_UNDEFINED_FORBIDDEN'
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
    'W31_CANONICAL_TYPE_FORBIDDEN'
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

function journalPayload(state){
  return {
    schema:
      state.schema,

    version:
      state.version,

    sequence:
      state.sequence,

    attempts:
      state.attempts
  };
}

function computeJournalHash(state){
  return sha256Hex(
    canonicalize(
      journalPayload(
        state
      )
    )
  );
}

function initialState(){
  return {
    schema:
      ATAN_FEE_V2_W31_JOURNAL_SCHEMA,

    version:
      ATAN_FEE_V2_W31_VERSION,

    sequence:
      0,

    attempts:
      []
  };
}

async function readVerifiedState(
  journalPath,
  {
    allow_missing = false
  } = {}
){
  if(!fs.existsSync(journalPath)){
    if(allow_missing){
      const state =
        initialState();

      state.journal_hash =
        computeJournalHash(
          state
        );

      return state;
    }

    fail(
      'W31_JOURNAL_MISSING'
    );
  }

  let state;

  try{
    state =
      JSON.parse(
        await fsp.readFile(
          journalPath,
          'utf8'
        )
      );
  }
  catch{
    fail(
      'W31_JOURNAL_PARSE_FAILED'
    );
  }

  requireObject(
    state,
    'journal'
  );

  if(
    state.schema !==
      ATAN_FEE_V2_W31_JOURNAL_SCHEMA ||
    state.version !==
      ATAN_FEE_V2_W31_VERSION ||
    !Number.isSafeInteger(
      Number(
        state.sequence
      )
    ) ||
    Number(state.sequence) < 0 ||
    !Array.isArray(
      state.attempts
    ) ||
    typeof state.journal_hash !==
      'string'
  ){
    fail(
      'W31_JOURNAL_STRUCTURE_INVALID'
    );
  }

  const expected =
    computeJournalHash(
      state
    );

  if(expected !== state.journal_hash){
    fail(
      'W31_JOURNAL_HASH_MISMATCH'
    );
  }

  return state;
}

async function writeAtomicState(
  journalPath,
  state
){
  await fsp.mkdir(
    path.dirname(
      journalPath
    ),
    {
      recursive:
        true
    }
  );

  const next = {
    ...state
  };

  next.journal_hash =
    computeJournalHash(
      next
    );

  const tempPath =
    journalPath +
    '.' +
    process.pid +
    '.' +
    Date.now() +
    '.tmp';

  await fsp.writeFile(
    tempPath,
    JSON.stringify(
      next,
      null,
      2
    ) + '\n',
    {
      encoding:
        'utf8',

      flag:
        'wx'
    }
  );

  await fsp.rename(
    tempPath,
    journalPath
  );

  return next;
}

function processAlive(pid){
  if(
    !Number.isSafeInteger(pid) ||
    pid <= 0
  ){
    return false;
  }

  try{
    process.kill(
      pid,
      0
    );

    return true;
  }
  catch(error){
    if(
      error &&
      error.code ===
        'ESRCH'
    ){
      return false;
    }

    return true;
  }
}

async function acquireLock(lockPath){
  await fsp.mkdir(
    path.dirname(
      lockPath
    ),
    {
      recursive:
        true
    }
  );

  for(let attempt = 0; attempt < 2; attempt += 1){
    try{
      const handle =
        await fsp.open(
          lockPath,
          'wx'
        );

      await handle.writeFile(
        JSON.stringify({
          pid:
            process.pid,

          created_at_ms:
            Date.now()
        }) + '\n',
        'utf8'
      );

      return handle;
    }
    catch(error){
      if(
        !error ||
        error.code !==
          'EEXIST'
      ){
        throw error;
      }

      let lock;

      try{
        lock =
          JSON.parse(
            await fsp.readFile(
              lockPath,
              'utf8'
            )
          );
      }
      catch{
        fail(
          'W31_JOURNAL_LOCK_BUSY_MALFORMED'
        );
      }

      const pid =
        Number(
          lock.pid
        );

      if(processAlive(pid)){
        fail(
          'W31_JOURNAL_LOCK_BUSY'
        );
      }

      await fsp.unlink(
        lockPath
      );
    }
  }

  fail(
    'W31_JOURNAL_LOCK_ACQUIRE_FAILED'
  );
}

async function withExclusiveLock(
  journalPath,
  operation
){
  const lockPath =
    journalPath +
    '.lock';

  const handle =
    await acquireLock(
      lockPath
    );

  try{
    return await operation();
  }
  finally{
    try{
      await handle.close();
    }
    catch{
      // Best effort close.
    }

    try{
      await fsp.unlink(
        lockPath
      );
    }
    catch(error){
      if(
        !error ||
        error.code !==
          'ENOENT'
      ){
        throw error;
      }
    }
  }
}

function attemptCore({
  admission,
  current_height,
  attempt_nonce
}){
  return {
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

    created_height:
      current_height,

    attempt_nonce
  };
}

function findAttempt(
  state,
  attemptId
){
  return state.attempts.find(
    attempt =>
      attempt.attempt_id ===
        attemptId
  );
}

export function createDurableBroadcastAttemptJournalV2({
  journal_path
}){
  const journalPath =
    requireString(
      journal_path,
      'journal_path'
    );

  return Object.freeze({
    version:
      ATAN_FEE_V2_W31_VERSION,

    journal_path:
      journalPath,

    storage:
      'ATOMIC_JSON_FILE',

    process_locking:
      'EXCLUSIVE_LOCK_FILE_FAIL_CLOSED',

    async inspect(){
      return structuredClone(
        await readVerifiedState(
          journalPath
        )
      );
    },

    async prepareAttempt({
      admission,
      current_height,
      attempt_nonce
    }){
      verifyLiveTransportAdmissionBoundaryV2(
        admission
      );

      const currentHeight =
        requireHeight(
          current_height,
          'current_height'
        );

      const nonce =
        requireNonce(
          attempt_nonce
        );

      const core =
        attemptCore({
          admission,
          current_height:
            currentHeight,
          attempt_nonce:
            nonce
        });

      const attemptId =
        sha256Hex(
          canonicalize(
            core
          )
        );

      const nonceKey =
        sha256Hex(
          canonicalize({
            admission_id:
              admission.admission_id,

            attempt_nonce:
              nonce
          })
        );

      return await withExclusiveLock(
        journalPath,
        async () => {
          const state =
            await readVerifiedState(
              journalPath,
              {
                allow_missing:
                  true
              }
            );

          if(
            state.attempts.some(
              attempt =>
                attempt.admission_id ===
                  admission.admission_id
            )
          ){
            fail(
              'W31_ADMISSION_ALREADY_JOURNALED'
            );
          }

          if(
            state.attempts.some(
              attempt =>
                attempt.attempt_nonce_key ===
                  nonceKey
            )
          ){
            fail(
              'W31_ATTEMPT_NONCE_REUSE'
            );
          }

          const attempt = {
            ...core,

            attempt_id:
              attemptId,

            attempt_nonce_key:
              nonceKey,

            status:
              STATUS_PREPARED,

            dispatch_intent_persisted:
              false,

            outcome_known:
              false,

            automatic_retry_allowed:
              false,

            read_only_reconciliation_required:
              false,

            transport_connected:
              false,

            sendrawtransaction_implementation:
              false,

            broadcast_attempted:
              false,

            broadcast_allowed:
              false,

            broadcast_authority:
              'NONE'
          };

          const next = {
            ...state,

            sequence:
              Number(
                state.sequence
              ) + 1,

            attempts:
              [
                ...state.attempts,
                attempt
              ]
          };

          await writeAtomicState(
            journalPath,
            next
          );

          return Object.freeze(
            structuredClone(
              attempt
            )
          );
        }
      );
    },

    async persistDispatchIntent({
      attempt_id,
      current_height
    }){
      const attemptId =
        requireHash(
          attempt_id,
          'attempt_id'
        );

      const currentHeight =
        requireHeight(
          current_height,
          'current_height'
        );

      return await withExclusiveLock(
        journalPath,
        async () => {
          const state =
            await readVerifiedState(
              journalPath
            );

          const index =
            state.attempts.findIndex(
              attempt =>
                attempt.attempt_id ===
                  attemptId
            );

          if(index < 0){
            fail(
              'W31_ATTEMPT_NOT_FOUND'
            );
          }

          const current =
            state.attempts[index];

          if(current.status !== STATUS_PREPARED){
            fail(
              'W31_ATTEMPT_NOT_PREPARED'
            );
          }

          const updated = {
            ...current,

            status:
              STATUS_DISPATCH_INTENT_PERSISTED,

            dispatch_intent_persisted:
              true,

            dispatch_intent_height:
              currentHeight,

            outcome_known:
              false,

            automatic_retry_allowed:
              false,

            read_only_reconciliation_required:
              true,

            transport_connected:
              false,

            sendrawtransaction_implementation:
              false,

            broadcast_attempted:
              false,

            broadcast_allowed:
              false,

            broadcast_authority:
              'NONE'
          };

          const attempts =
            state.attempts.slice();

          attempts[index] =
            updated;

          await writeAtomicState(
            journalPath,
            {
              ...state,

              sequence:
                Number(
                  state.sequence
                ) + 1,

              attempts
            }
          );

          return Object.freeze(
            structuredClone(
              updated
            )
          );
        }
      );
    },

    async recoverAttempt({
      attempt_id,
      current_height
    }){
      const attemptId =
        requireHash(
          attempt_id,
          'attempt_id'
        );

      const currentHeight =
        requireHeight(
          current_height,
          'current_height'
        );

      return await withExclusiveLock(
        journalPath,
        async () => {
          const state =
            await readVerifiedState(
              journalPath
            );

          const index =
            state.attempts.findIndex(
              attempt =>
                attempt.attempt_id ===
                  attemptId
            );

          if(index < 0){
            fail(
              'W31_ATTEMPT_NOT_FOUND'
            );
          }

          const current =
            state.attempts[index];

          if(current.status === STATUS_PREPARED){
            return Object.freeze({
              ...structuredClone(
                current
              ),

              recovery_classification:
                'PREPARED_NO_DISPATCH_INTENT',

              automatic_retry_allowed:
                false
            });
          }

          if(
            current.status ===
              STATUS_DISPATCH_INTENT_PERSISTED
          ){
            const updated = {
              ...current,

              status:
                STATUS_AMBIGUOUS_RECONCILIATION_REQUIRED,

              recovered_height:
                currentHeight,

              outcome_known:
                false,

              automatic_retry_allowed:
                false,

              read_only_reconciliation_required:
                true,

              broadcast_allowed:
                false,

              broadcast_authority:
                'NONE'
            };

            const attempts =
              state.attempts.slice();

            attempts[index] =
              updated;

            await writeAtomicState(
              journalPath,
              {
                ...state,

                sequence:
                  Number(
                    state.sequence
                  ) + 1,

                attempts
              }
            );

            return Object.freeze(
              structuredClone(
                updated
              )
            );
          }

          return Object.freeze(
            structuredClone(
              current
            )
          );
        }
      );
    },

    async applyReadOnlyReconciliation({
      attempt_id,
      evidence,
      current_height
    }){
      const attemptId =
        requireHash(
          attempt_id,
          'attempt_id'
        );

      requireObject(
        evidence,
        'evidence'
      );

      const currentHeight =
        requireHeight(
          current_height,
          'current_height'
        );

      if(
        evidence.observation_source !==
          'BCHN_MAINNET_READONLY_OBSERVER' ||
        evidence.read_only !==
          true ||
        evidence.rpc_method !==
          'getrawtransaction'
      ){
        fail(
          'W31_READONLY_RECONCILIATION_EVIDENCE_INVALID'
        );
      }

      const observedHeight =
        requireHeight(
          evidence.observed_height,
          'observed_height'
        );

      if(observedHeight > currentHeight){
        fail(
          'W31_RECONCILIATION_HEIGHT_IN_FUTURE'
        );
      }

      if(
        evidence.outcome !==
          'TX_OBSERVED_MEMPOOL_OR_CHAIN' &&
        evidence.outcome !==
          'TX_NOT_OBSERVED'
      ){
        fail(
          'W31_RECONCILIATION_OUTCOME_INVALID'
        );
      }

      return await withExclusiveLock(
        journalPath,
        async () => {
          const state =
            await readVerifiedState(
              journalPath
            );

          const index =
            state.attempts.findIndex(
              attempt =>
                attempt.attempt_id ===
                  attemptId
            );

          if(index < 0){
            fail(
              'W31_ATTEMPT_NOT_FOUND'
            );
          }

          const current =
            state.attempts[index];

          if(
            current.status !==
              STATUS_AMBIGUOUS_RECONCILIATION_REQUIRED &&
            current.status !==
              STATUS_AMBIGUOUS_NOT_OBSERVED
          ){
            fail(
              'W31_ATTEMPT_NOT_AMBIGUOUS'
            );
          }

          if(
            evidence.signed_transaction_sha256 !==
              current.signed_transaction_sha256
          ){
            fail(
              'W31_RECONCILIATION_TX_BINDING_MISMATCH'
            );
          }

          let updated;

          if(
            evidence.outcome ===
              'TX_OBSERVED_MEMPOOL_OR_CHAIN'
          ){
            updated = {
              ...current,

              status:
                STATUS_BROADCAST_OBSERVED,

              outcome_known:
                true,

              observed_height:
                observedHeight,

              observation_outcome:
                evidence.outcome,

              read_only_reconciliation_required:
                false,

              automatic_retry_allowed:
                false,

              broadcast_allowed:
                false,

              broadcast_authority:
                'NONE'
            };
          }
          else{
            updated = {
              ...current,

              status:
                STATUS_AMBIGUOUS_NOT_OBSERVED,

              outcome_known:
                false,

              last_not_observed_height:
                observedHeight,

              observation_outcome:
                evidence.outcome,

              read_only_reconciliation_required:
                true,

              automatic_retry_allowed:
                false,

              owner_reauthorization_required_before_any_future_retry:
                true,

              broadcast_allowed:
                false,

              broadcast_authority:
                'NONE'
            };
          }

          const attempts =
            state.attempts.slice();

          attempts[index] =
            updated;

          await writeAtomicState(
            journalPath,
            {
              ...state,

              sequence:
                Number(
                  state.sequence
                ) + 1,

              attempts
            }
          );

          return Object.freeze(
            structuredClone(
              updated
            )
          );
        }
      );
    }
  });
}

export function describeDurableBroadcastAttemptJournalV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_W31_VERSION,

    storage:
      'ATOMIC_JSON_FILE',

    journal_hash:
      'SHA256_CANONICAL_JSON',

    process_locking:
      'EXCLUSIVE_LOCK_FILE_FAIL_CLOSED',

    dispatch_intent_persisted_before_transport_call:
      true,

    admission_id_one_time:
      true,

    attempt_nonce_one_time:
      true,

    ambiguous_recovery_requires_readonly_reconciliation:
      true,

    automatic_retry_after_ambiguous_outcome:
      false,

    not_observed_does_not_prove_not_broadcast:
      true,

    observed_transaction_terminal:
      true,

    transport_connected:
      false,

    sendrawtransaction_implementation:
      false,

    real_mainnet_rpc_requests:
      0,

    transaction_broadcast:
      false,

    broadcast_authority:
      'NONE'
  });
}
