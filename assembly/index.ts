import { u128, storage, PersistentMap, PersistentSet, Context, base58, ContractPromiseBatch, PersistentVector } from 'near-sdk-as'

import { 
  AccountId,
  RequestId,
  PublicKey
} from './types'

import { 
  MultiSigContract, 
  MultiSigRequest,
  MultiSigRequestWithSigner 
} from './models'

/// Unlimited allowance for multisig keys.
const DEFAULT_ALLOWANCE: u128 = u128.Zero

// Request cooldown period (time before a request can be deleted)
const REQUEST_COOLDOWN: u64 = 900000000000

// Sets to collect certain information
const request_ids_vec = new PersistentVector<string>('iv')
const request_ids_set = new PersistentSet<string>('is')
const request_ids_map = new PersistentMap<string, u32>('im')

let contract: MultiSigContract


/*********/
/* Main  */
/*********/

/// Initialize multisig contract.
/// @params num_confirmations: k of n signatures required to perform operations.
export function initContract(num_confirmations: u32): MultiSigContract {
  /// Initializes the contract with the given NEAR foundation account ID.
  assert(!storage.hasKey('init'), 'Already initialized')
  let request_nonce = 0
  let requests = new PersistentMap<RequestId, MultiSigRequestWithSigner>('r')
  let confirmations = new PersistentMap<RequestId, PersistentSet<PublicKey>>('c')
  let num_requests_pk = new PersistentMap<PublicKey, u32>('k')
  let active_requests_limit = 12
  contract = new MultiSigContract(
    num_confirmations,
    request_nonce = 0,
    requests,
    confirmations,
    num_requests_pk,
    active_requests_limit
    )
  storage.set('init', true)
  return contract
}

/// Add request for multisig.
export function add_request(request: MultiSigRequest): RequestId {
  assert(Context.sender == Context.predecessor, 'Predecessor account must match current sender account')
  // track how many requests this key has made
  let num_requests = contract.num_requests_pk.getSome(base58.decode(Context.senderPublicKey)) + 1
  assert(num_requests <= contract.active_requests_limit, 'Account has too many active requests.  Confirm or delete some.')
  contract.num_requests_pk.set(base58.decode(Context.senderPublicKey), num_requests)
  // add the request
  let signer_pk = base58.decode(Context.senderPublicKey)
  let added_timestamp = Context.blockTimestamp
  let request_added = new MultiSigRequestWithSigner (
    request,
    signer_pk,
    added_timestamp
  )
  contract.requests.set(contract.request_nonce, request_added)
  let confirmations = new PersistentSet<PublicKey>('p')
  contract.confirmations.set(contract.request_nonce, confirmations)
  contract.request_nonce += 1
  let stringId = (contract.request_nonce - 1).toString()
  request_ids_map.set(request.public_key, contract.request_nonce -1)
  request_ids_set.add(stringId)
  request_ids_vec.push(request.public_key + ':' + stringId)
  return contract.request_nonce - 1
}

/// Add request for multisig and confirm with the pk that added.
export function add_request_and_confirm(request: MultiSigRequest): RequestId {
  let request_id = add_request(request)
  confirm(request_id)
  return request_id
}

/// Remove given request and associated confirmations
export function delete_request(request_id: RequestId): void {
  _assert_valid_request(request_id)
  assert(contract.requests.get(request_id) != null, 'No such request')
  let request_with_signer = contract.requests.getSome(request_id)
  // can't delete requests before 15min
  assert(Context.blockTimestamp > request_with_signer.added_timestamp + REQUEST_COOLDOWN, 'Request cannot be deleted immediately after creation.')
  _remove_request(request_id)
  let k = 0
  let request_ids_length = request_ids_vec.length
  while(k < request_ids_length) {
    let key = request_ids_vec[k].split(':')
    if (key[1] == request_id.toString()) {
      request_ids_map.delete(key[0])
      request_ids_set.delete(key[1])
      request_ids_vec.swap_remove(k)
    }
    k++
  }
}

export function execute_request(request: MultiSigRequest): bool {
  let promise = ContractPromiseBatch.create(request.receiver_id)
  let receiver_id = request.receiver_id
  let num_actions = request.actions.length
  let i = 0
  while (i < num_actions) {
    switch (request.actions[i]) {
      case 0: // Transfer
        if (u128.gt(request.amount, u128.Zero)) {
          promise.transfer(request.amount)
        }
        break
      case 1: // CreateAccount
        promise.create_account()
        break
      case 2: // DeployContract
        let code = includeBytes('../out/multisig.wasm')
        promise.deploy_contract(Uint8Array.wrap(changetype<ArrayBuffer>(code)))
        break
      case 3: // AddKey
        if(request.receiver_id && request.methodNames != [''] && request.public_key != '') {
          promise.add_access_key(
            base58.decode(request.public_key),
            request.allowance ? request.allowance : DEFAULT_ALLOWANCE,
            request.receiver_id,
            request.methodNames)
          } else if(request.public_key){
            promise.add_full_access_key(base58.decode(request.public_key))
          }
          break
      case 4: // DeleteKey
        if(request.public_key != '') {
          _assert_self_request(receiver_id)
          let pk: PublicKey = base58.decode(request.public_key)
          // delete outstanding requests by public_key
          let j = 0
          let request_ids = new Array<u32>()
          let request_ids_length = request_ids_vec.length
          while(j < request_ids_length) {
            let key = request_ids_vec[j].split(':')
            if(request_ids_map.contains(key[0])){
              let rKey = request_ids_map.getSome(key[0])
              request_ids.push(rKey)
            }
            j++
          }
          let n = 0
          while(n < request_ids.length) {
            contract.confirmations.delete(request_ids[n])
            contract.requests.delete(request_ids[n])
            n++
          }
          //remove num_requests_pk entry for public key
          contract.num_requests_pk.delete(pk)
          promise.delete_key(pk)
        }
        break
      case 5: // FunctionCall
        if(request.args != {} && request.method != '' && request.deposit != u128.Zero && request.gas != 0) {
          promise.function_call(
            request.method,
            request.args,
            request.deposit,
            request.gas
          )
        }
        break
      case 6: // SetNumConfirmations
        if(request.num_confirmations != 0) {
          _assert_one_action_only(receiver_id, num_actions)
          contract.num_confirmations = request.num_confirmations
          return true
        }
        break
      case 7: // SetActiveRequestsLimit
        if(request.active_request_limit != 0){
          _assert_one_action_only(receiver_id, num_actions)
          contract.active_requests_limit = request.active_request_limit
          return true
        }
        break
      default:
        break
    }
    i++
  }
  return true
}

/// Confirm given request with given signing key.
/// If with this, there has been enough confirmation, a promise with request will be scheduled.
export function confirm(request_id: RequestId): bool {
  _assert_valid_request(request_id)
  assert(contract.confirmations.contains(request_id), 'request id does not exit')
  let confirmations = contract.confirmations.getSome(request_id)
  assert(confirmations.has(base58.decode(Context.senderPublicKey)), 'Already confirmed this request with this key')
  if (u32(confirmations.size) + 1 >= contract.num_confirmations) {
    let request = _remove_request(request_id)
  
  /********************************
  NOTE: If the tx execution fails for any reason, the request and confirmations are removed already, so the client has to start all over
  ********************************/
  execute_request(request)
  } else {
    confirmations.add(base58.decode(Context.senderPublicKey))
    contract.confirmations.set(request_id, confirmations)
    return true
  }
  return false
}



/******************/
/* Helper Methods */
/******************/

function _isInit(): void {
  assert(storage.hasKey('init') && storage.getSome<bool>('init') == true, 'The contract should be initialized before usage.')
}

// removes request, removes confirmations and reduces num_requests_pk - used in delete, delete_key, and confirm
function _remove_request(request_id: RequestId): MultiSigRequest {
  //remove confirmations for this request
  contract.confirmations.delete(request_id)
  //remove the original request
  let request_with_signer = contract.requests
  request_with_signer.delete(request_id)
  assert(!request_with_signer.contains(request_id), 'Failed to remove existing element')
  //decrement num_requests for original request signer
  let original_signer_pk = request_with_signer.getSome(request_id).signer_pk
  let num_requests = contract.num_requests_pk.getSome(original_signer_pk)
  // safety check for underrun (unlikely since original_signer_pk must have num_requests_pk > 0)
  if (num_requests > 0) {
    num_requests = num_requests -1
  }
  contract.num_requests_pk.set(original_signer_pk, num_requests)
  //return request
  return request_with_signer.getSome(request_id).request
}

// Prevents access to calling requests and make sure request_id is valid - used in delete and confirm
function _assert_valid_request(request_id: RequestId): void {
  // request must come from key added to contract account
  assert(Context.sender == Context.predecessor, 'Predecessor account must match sender account.')
  // request must exist
  assert(contract.requests.get(request_id)!=null, 'No such request: either wrong number or already confirmed')
  // request must have
  assert(contract.confirmations.get(request_id)!=null, 'Internal error: confirmations mismatch requests')
}

// Prevents request from approving tx on another account
function _assert_self_request(receiver_id: AccountId): void {
  assert(receiver_id == Context.sender, 'This method only works when receiver_id is equal to sender')
}

// Prevents a request from being bundled with other actions
function _assert_one_action_only(receiver_id: AccountId, num_actions: usize): void {
  _assert_self_request(receiver_id)
  assert(num_actions == 1, 'This method should be a separate request)')
}


/********************************
*   View methods                *
********************************/

export function get_request(request_id: RequestId): MultiSigRequest {
  assert(contract.requests.contains(request_id), 'No such request')
  return contract.requests.getSome(request_id).request
}

export function get_num_requests_pk(public_key: Uint8Array): u32 {
  return contract.num_requests_pk.getSome(public_key)
}

export function list_request_ids(): Array<string> {
  return request_ids_set.values()
}

export function get_confirmations(request_id: RequestId): Array<Uint8Array> {
  assert(contract.confirmations.contains(request_id), 'No such request')
  return contract.confirmations.getSome(request_id).values()
}

export function get_num_confirmations(): u32 {
  return contract.num_confirmations
}

export function get_request_nonce(): u32 {
  return contract.request_nonce
}