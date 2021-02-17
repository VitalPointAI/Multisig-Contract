import { PersistentMap, u128, PersistentSet, storage, base58, env, Context } from "near-sdk-as";
import { AccountId, PublicKey, RequestId } from './types'

/// Permissions for function call access key.
@nearBindgen
export class FunctionCallPermission {
    allowance: u128;
    receiver_id: AccountId;
    method_names: Array<string>;

    constructor(
        allowance: u128,
        receiver_id: AccountId,
        method_names: Array<string>
    ) {
        allowance = this.allowance;
        receiver_id = this.receiver_id;
        method_names = this.method_names;
    }
}

export enum MultiSigRequestAction {
    /// Transfers given amount to receiver.
    Transfer,

    /// Create a new account
    CreateAccount,

    /// Deploys contract to receiver's account. Can upgrade given contract as well.
    DeployContract,

    /// Adds key, either new key for multisig or full access key to another account.
    AddKey, 

    /// Deletes key, either one of the keys from multisig or key from another account.
    DeleteKey, 

    /// Call function on behalf of this contract.
    FunctionCall,

    /// Sets number of confirmations required to authorize requests.
    /// Can not be bundled with any other actions or transactions.
    SetNumConfirmations,

    /// Sets number of active requests (unconfirmed requests) per access key
    /// Default is 12 unconfirmed requests at a time
    /// The REQUEST_COOLDOWN for requests is 15min
    /// Worst gas attack a malicious keyholder could do is 12 requests every 15min
    SetActiveRequestsLimit, // { active_requests_limit: u32 },
}

// The request the user makes specifying the receiving account and actions they want to execute (1 tx)
@nearBindgen
export class MultiSigRequest {
    receiver_id: AccountId;
    actions: Array<MultiSigRequestAction>;
    active_request_limit: u32;
    amount: u128;
    public_key: string;
    methodNames: Array<string>;
    allowance: u128;
    method: string;
    gas: u64;
    deposit: u128;
    args: Object;
    num_confirmations: u32;
    
    constructor(
        receiver_id: AccountId,
        actions: Array<MultiSigRequestAction>,
        active_request_limit: u32 = 12,
        amount: u128 = u128.Zero,
        public_key: string = '',
        methodNames: Array<string> = [''],
        allowance: u128 = u128.Zero,
        method: string = '',
        gas: u64 = 0,
        deposit: u128 = u128.Zero,
        args: Object = {},
        num_confirmations: u32 = 0     
    ) {
        receiver_id = this.receiver_id;
        actions = this.actions;
        active_request_limit = this.active_request_limit;
        amount = this.amount;
        public_key = this.public_key;
        methodNames = this.methodNames;
        allowance = this.allowance;
        method = this.method;
        gas = this.gas;
        deposit = this.deposit;
        args = this.args;
        num_confirmations = this.num_confirmations;
    }
}

// An internal request wrapped with the signer_pk and added timestamp to determine num_requests_pk and prevent against malicious key holder gas attacks
@nearBindgen
export class MultiSigRequestWithSigner {
    request: MultiSigRequest;
    signer_pk: PublicKey;
    added_timestamp: u64;

    constructor(
        request: MultiSigRequest,
        signer_pk: PublicKey,
        added_timestamp: u64
    ) {
        request = this.request;
        signer_pk = this.signer_pk;
        added_timestamp = this.added_timestamp;
    }
}

@nearBindgen
export class MultiSigContract {
    num_confirmations: u32;
    request_nonce: RequestId;
    requests: PersistentMap<RequestId, MultiSigRequestWithSigner>;
    confirmations: PersistentMap<RequestId, PersistentSet<PublicKey>>;
    num_requests_pk: PersistentMap<PublicKey, u32>;
    // per key
    active_requests_limit: u32;

    constructor(
        num_confirmations: u32,
        request_nonce: RequestId,
        requests: PersistentMap<RequestId, MultiSigRequestWithSigner>,
        confirmations: PersistentMap<RequestId, PersistentSet<PublicKey>>,
        num_requests_pk: PersistentMap<PublicKey, u32>,
        active_requests_limit: u32
    ) {
        num_confirmations = this.num_confirmations;
        request_nonce = this.request_nonce;
        requests = this.requests;
        confirmations = this.confirmations;
        num_requests_pk = this.num_requests_pk;
        active_requests_limit = this.active_requests_limit;
    }

}