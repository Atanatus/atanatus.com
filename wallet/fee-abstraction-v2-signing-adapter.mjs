import {
  ATAN_FEE_ABSTRACTION_SIGHASH_BYTE,
  assertFeeAbstractionSighash,
  createFeeAbstractionCompiler,
  getP2pkhSignatureSighashByte
} from './fee-abstraction-v2-kernel.mjs';


function cloneBin(value){
  if(!(value instanceof Uint8Array)){
    throw new Error(
      'FEE_V2_EXPECTED_UINT8ARRAY'
    );
  }

  return Uint8Array.from(value);
}


function equalBin(a,b){

  if(
    !(a instanceof Uint8Array) ||
    !(b instanceof Uint8Array) ||
    a.length !== b.length
  ){
    return false;
  }

  for(let i=0;i<a.length;i++){
    if(a[i] !== b[i]){
      return false;
    }
  }

  return true;
}


function cloneToken(token){

  if(token === undefined){
    return undefined;
  }

  const cloned = {
    category:
      cloneBin(token.category),

    amount:
      BigInt(token.amount)
  };

  if(token.nft !== undefined){

    cloned.nft = {
      capability:
        token.nft.capability,

      commitment:
        cloneBin(
          token.nft.commitment ??
          new Uint8Array()
        )
    };
  }

  return cloned;
}


function cloneInput(input){

  return {
    outpointIndex:
      Number(input.outpointIndex),

    outpointTransactionHash:
      cloneBin(
        input.outpointTransactionHash
      ),

    sequenceNumber:
      Number(input.sequenceNumber),

    unlockingBytecode:
      cloneBin(
        input.unlockingBytecode
      )
  };
}


function cloneOutput(output){

  const cloned = {
    lockingBytecode:
      cloneBin(
        output.lockingBytecode
      ),

    valueSatoshis:
      BigInt(
        output.valueSatoshis
      )
  };

  if(output.token !== undefined){
    cloned.token =
      cloneToken(output.token);
  }

  return cloned;
}


function cloneTransaction(transaction){

  return {
    version:
      Number(transaction.version),

    inputs:
      transaction.inputs.map(
        cloneInput
      ),

    outputs:
      transaction.outputs.map(
        cloneOutput
      ),

    locktime:
      Number(transaction.locktime)
  };
}


function cloneSourceOutputs(sourceOutputs){

  return sourceOutputs.map(
    output => {

      const cloned = {
        lockingBytecode:
          cloneBin(
            output.lockingBytecode
          ),

        valueSatoshis:
          BigInt(
            output.valueSatoshis
          )
      };

      if(output.token !== undefined){
        cloned.token =
          cloneToken(output.token);
      }

      return cloned;
    }
  );
}


function hex(bin){

  return Array.from(bin)
    .map(
      value =>
        value
          .toString(16)
          .padStart(2,'0')
    )
    .join('');
}


function tokenDescriptor(token){

  if(token === undefined){
    return null;
  }

  return {
    category:
      hex(token.category),

    amount:
      BigInt(
        token.amount
      ).toString(),

    nft:
      token.nft === undefined
        ? null
        : {
            capability:
              token.nft.capability,

            commitment:
              hex(
                token.nft.commitment
              )
          }
  };
}


export function describeFeeAbstractionCore(
  transaction
){
  return JSON.stringify({
    version:
      transaction.version,

    locktime:
      transaction.locktime,

    inputs:
      transaction.inputs.map(
        input => ({
          outpointIndex:
            input.outpointIndex,

          outpointTransactionHash:
            hex(
              input.outpointTransactionHash
            ),

          sequenceNumber:
            input.sequenceNumber
        })
      ),

    outputs:
      transaction.outputs.map(
        output => ({
          lockingBytecode:
            hex(
              output.lockingBytecode
            ),

          valueSatoshis:
            BigInt(
              output.valueSatoshis
            ).toString(),

          token:
            tokenDescriptor(
              output.token
            )
        })
      )
  });
}


export function describeFeeAbstractionSourceOutputs(
  sourceOutputs
){
  return JSON.stringify(
    sourceOutputs.map(
      output => ({
        lockingBytecode:
          hex(
            output.lockingBytecode
          ),

        valueSatoshis:
          BigInt(
            output.valueSatoshis
          ).toString(),

        token:
          tokenDescriptor(
            output.token
          )
      })
    )
  );
}


function normalizeInputIndexes(
  inputIndexes,
  inputCount
){
  if(
    !Array.isArray(inputIndexes) ||
    inputIndexes.length === 0
  ){
    throw new Error(
      'FEE_V2_USER_INPUT_INDEXES_REQUIRED'
    );
  }

  const normalized =
    inputIndexes.map(
      value => Number(value)
    );

  for(const index of normalized){

    if(
      !Number.isInteger(index) ||
      index < 0 ||
      index >= inputCount
    ){
      throw new Error(
        'FEE_V2_USER_INPUT_INDEX_INVALID_' +
        index
      );
    }
  }

  if(
    new Set(normalized).size !==
    normalized.length
  ){
    throw new Error(
      'FEE_V2_DUPLICATE_USER_INPUT_INDEX'
    );
  }

  return normalized.sort(
    (a,b) => a-b
  );
}


async function compileControlledLock(
  compiler,
  privateKey
){
  const result =
    await compiler.generateBytecode({
      data:{
        keys:{
          privateKeys:{
            key:
              privateKey
          }
        }
      },

      scriptId:
        'lock'
    });

  if(!result.success){

    throw new Error(
      'FEE_V2_LOCK_SCRIPT_COMPILATION_FAILED'
    );
  }

  return result.bytecode;
}


export async function signFeeAbstractionUserInputs({
  libauth,
  transaction,
  sourceOutputs,
  inputIndexes,
  privateKey
}){
  if(
    !libauth ||
    typeof libauth.encodeTransaction !==
      'function'
  ){
    throw new Error(
      'FEE_V2_LIBAUTH_REQUIRED'
    );
  }

  if(
    !(privateKey instanceof Uint8Array) ||
    privateKey.length !== 32
  ){
    throw new Error(
      'FEE_V2_EXPECTED_32_BYTE_PRIVATE_KEY'
    );
  }

  if(
    !transaction ||
    !Array.isArray(transaction.inputs) ||
    !Array.isArray(transaction.outputs)
  ){
    throw new Error(
      'FEE_V2_TRANSACTION_INVALID'
    );
  }

  if(
    !Array.isArray(sourceOutputs) ||
    sourceOutputs.length !==
      transaction.inputs.length
  ){
    throw new Error(
      'FEE_V2_SOURCE_OUTPUT_COUNT_MISMATCH'
    );
  }

  const selected =
    normalizeInputIndexes(
      inputIndexes,
      transaction.inputs.length
    );

  const working =
    cloneTransaction(
      transaction
    );

  const fullSourceOutputs =
    cloneSourceOutputs(
      sourceOutputs
    );

  const originalCore =
    describeFeeAbstractionCore(
      working
    );

  const originalSources =
    describeFeeAbstractionSourceOutputs(
      fullSourceOutputs
    );

  const untouchedInputs =
    new Map();

  for(
    let index=0;
    index<working.inputs.length;
    index++
  ){
    if(!selected.includes(index)){
      untouchedInputs.set(
        index,
        cloneBin(
          working.inputs[index]
            .unlockingBytecode
        )
      );
    }
  }

  const compiler =
    await createFeeAbstractionCompiler(
      libauth
    );

  const expectedLock =
    await compileControlledLock(
      compiler,
      privateKey
    );

  /*
   * Critical ownership gate:
   * never sign an input unless its source locking
   * bytecode is exactly controlled by this key.
   */
  for(const index of selected){

    const source =
      fullSourceOutputs[index];

    if(
      !source ||
      !(source.lockingBytecode
        instanceof Uint8Array)
    ){
      throw new Error(
        'FEE_V2_SOURCE_OUTPUT_INVALID_' +
        index
      );
    }

    if(
      !equalBin(
        source.lockingBytecode,
        expectedLock
      )
    ){
      throw new Error(
        'FEE_V2_SELECTED_INPUT_NOT_CONTROLLED_BY_KEY_' +
        index
      );
    }

    if(
      working.inputs[index]
        .unlockingBytecode.length !== 0
    ){
      throw new Error(
        'FEE_V2_SELECTED_INPUT_ALREADY_SIGNED_' +
        index
      );
    }
  }

  /*
   * Important:
   *
   * Do NOT use libauth.generateTransaction() here.
   *
   * SIGHASH_UTXOS must receive the COMPLETE prevout set,
   * including inputs owned by other parties.
   *
   * Therefore each selected input is compiled directly
   * using compiler.generateBytecode() and an explicit
   * full CompilationContextBCH.
   */
  for(const index of selected){

    const result =
      await compiler.generateBytecode({
        data:{
          keys:{
            privateKeys:{
              key:
                privateKey
            }
          },

          compilationContext:{
            inputIndex:
              index,

            sourceOutputs:
              fullSourceOutputs,

            transaction:
              working
          }
        },

        debug:
          true,

        scriptId:
          'unlock'
      });

    if(!result.success){

      const messages =
        Array.isArray(result.errors)
          ? result.errors
              .map(
                error =>
                  String(
                    error?.error ||
                    error
                  )
              )
              .join(' | ')
          : 'UNKNOWN';

      throw new Error(
        'FEE_V2_USER_SIGNATURE_COMPILATION_FAILED_' +
        index +
        ':' +
        messages
      );
    }

    assertFeeAbstractionSighash(
      result.bytecode
    );

    working.inputs[index]
      .unlockingBytecode =
        Uint8Array.from(
          result.bytecode
        );
  }

  /*
   * Economic core must be unchanged.
   */
  if(
    describeFeeAbstractionCore(
      working
    ) !==
    originalCore
  ){
    throw new Error(
      'FEE_V2_SIGNING_CHANGED_TRANSACTION_CORE'
    );
  }

  /*
   * Prevout truth supplied to SIGHASH_UTXOS
   * must also remain unchanged.
   */
  if(
    describeFeeAbstractionSourceOutputs(
      fullSourceOutputs
    ) !==
    originalSources
  ){
    throw new Error(
      'FEE_V2_SIGNING_CHANGED_SOURCE_OUTPUTS'
    );
  }

  /*
   * Every non-user input must remain exactly
   * byte-identical.
   */
  for(
    const [
      index,
      original
    ] of untouchedInputs.entries()
  ){
    if(
      !equalBin(
        working.inputs[index]
          .unlockingBytecode,
        original
      )
    ){
      throw new Error(
        'FEE_V2_NON_USER_INPUT_MODIFIED_' +
        index
      );
    }
  }

  const signatureSighashes =
    selected.map(
      index =>
        getP2pkhSignatureSighashByte(
          working.inputs[index]
            .unlockingBytecode
        )
    );

  for(
    const value of signatureSighashes
  ){
    if(
      value !==
      ATAN_FEE_ABSTRACTION_SIGHASH_BYTE
    ){
      throw new Error(
        'FEE_V2_NON_0X61_SIGNATURE'
      );
    }
  }

  return {
    transaction:
      working,

    encodedTransaction:
      libauth.encodeTransaction(
        working
      ),

    signedInputIndexes:
      selected,

    signatureSighashes,

    sighashByte:
      ATAN_FEE_ABSTRACTION_SIGHASH_BYTE
  };
}