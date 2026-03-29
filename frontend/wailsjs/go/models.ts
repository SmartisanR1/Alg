export namespace asymmetric {
	
	export class ECCRequest {
	    privateKey: string;
	    data: string;
	    hash: string;
	    curve: string;
	
	    static createFrom(source: any = {}) {
	        return new ECCRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.data = source["data"];
	        this.hash = source["hash"];
	        this.curve = source["curve"];
	    }
	}
	export class ECCVerifyRequest {
	    publicKey: string;
	    data: string;
	    signature: string;
	    hash: string;
	    curve: string;
	
	    static createFrom(source: any = {}) {
	        return new ECCVerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.publicKey = source["publicKey"];
	        this.data = source["data"];
	        this.signature = source["signature"];
	        this.hash = source["hash"];
	        this.curve = source["curve"];
	    }
	}
	export class ECDHRequest {
	    privateKey: string;
	    peerPublicKey: string;
	    curve: string;
	
	    static createFrom(source: any = {}) {
	        return new ECDHRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.peerPublicKey = source["peerPublicKey"];
	        this.curve = source["curve"];
	    }
	}
	export class Ed448Request {
	    privateKey: string;
	    data: string;
	    context: string;
	
	    static createFrom(source: any = {}) {
	        return new Ed448Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.data = source["data"];
	        this.context = source["context"];
	    }
	}
	export class Ed448VerifyRequest {
	    publicKey: string;
	    data: string;
	    signature: string;
	    context: string;
	
	    static createFrom(source: any = {}) {
	        return new Ed448VerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.publicKey = source["publicKey"];
	        this.data = source["data"];
	        this.signature = source["signature"];
	        this.context = source["context"];
	    }
	}
	export class EdDSARequest {
	    privateKey: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new EdDSARequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.data = source["data"];
	    }
	}
	export class EdDSAVerifyRequest {
	    publicKey: string;
	    data: string;
	    signature: string;
	
	    static createFrom(source: any = {}) {
	        return new EdDSAVerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.publicKey = source["publicKey"];
	        this.data = source["data"];
	        this.signature = source["signature"];
	    }
	}
	export class KeyPairResult {
	    success: boolean;
	    privateKey: string;
	    publicKey: string;
	    privHex: string;
	    pubHex: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyPairResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.privateKey = source["privateKey"];
	        this.publicKey = source["publicKey"];
	        this.privHex = source["privHex"];
	        this.pubHex = source["pubHex"];
	        this.error = source["error"];
	    }
	}
	export class RSARequest {
	    key: string;
	    data: string;
	    padding: string;
	    hash: string;
	
	    static createFrom(source: any = {}) {
	        return new RSARequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	        this.padding = source["padding"];
	        this.hash = source["hash"];
	    }
	}
	export class RSASignRequest {
	    privateKey: string;
	    data: string;
	    hash: string;
	    padding: string;
	
	    static createFrom(source: any = {}) {
	        return new RSASignRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.data = source["data"];
	        this.hash = source["hash"];
	        this.padding = source["padding"];
	    }
	}
	export class RSAVerifyRequest {
	    publicKey: string;
	    data: string;
	    signature: string;
	    hash: string;
	    padding: string;
	
	    static createFrom(source: any = {}) {
	        return new RSAVerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.publicKey = source["publicKey"];
	        this.data = source["data"];
	        this.signature = source["signature"];
	        this.hash = source["hash"];
	        this.padding = source["padding"];
	    }
	}
	export class X25519Request {
	    privateKey: string;
	    peerPublicKey: string;
	
	    static createFrom(source: any = {}) {
	        return new X25519Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.peerPublicKey = source["peerPublicKey"];
	    }
	}

}

export namespace finance {
	
	export class CVVRequest {
	    cvk: string;
	    pan: string;
	    exp: string;
	    service: string;
	    decTable: string;
	    length: number;
	
	    static createFrom(source: any = {}) {
	        return new CVVRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.cvk = source["cvk"];
	        this.pan = source["pan"];
	        this.exp = source["exp"];
	        this.service = source["service"];
	        this.decTable = source["decTable"];
	        this.length = source["length"];
	    }
	}
	export class CVVResult {
	    success: boolean;
	    cvv: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new CVVResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.cvv = source["cvv"];
	        this.error = source["error"];
	    }
	}
	export class DOWRequest {
	    key: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new DOWRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	    }
	}
	export class DOWResult {
	    success: boolean;
	    out: string;
	    left: string;
	    right: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new DOWResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.out = source["out"];
	        this.left = source["left"];
	        this.right = source["right"];
	        this.error = source["error"];
	    }
	}
	export class EMVACRequest {
	    key: string;
	    data: string;
	    padding: string;
	
	    static createFrom(source: any = {}) {
	        return new EMVACRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	        this.padding = source["padding"];
	    }
	}
	export class PINBlockParseRequest {
	    format: string;
	    block: string;
	    pan: string;
	
	    static createFrom(source: any = {}) {
	        return new PINBlockParseRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.format = source["format"];
	        this.block = source["block"];
	        this.pan = source["pan"];
	    }
	}
	export class PINBlockRequest {
	    format: string;
	    pin: string;
	    pan: string;
	    random: string;
	
	    static createFrom(source: any = {}) {
	        return new PINBlockRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.format = source["format"];
	        this.pin = source["pin"];
	        this.pan = source["pan"];
	        this.random = source["random"];
	    }
	}
	export class PINBlockResult {
	    success: boolean;
	    block: string;
	    random: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new PINBlockResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.block = source["block"];
	        this.random = source["random"];
	        this.error = source["error"];
	    }
	}
	export class PINEncryptRequest {
	    key: string;
	    block: string;
	
	    static createFrom(source: any = {}) {
	        return new PINEncryptRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.block = source["block"];
	    }
	}
	export class PINParseResult {
	    success: boolean;
	    pin: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new PINParseResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.pin = source["pin"];
	        this.error = source["error"];
	    }
	}
	export class PVVRequest {
	    pvk: string;
	    pvki: string;
	    pin: string;
	    pan11: string;
	    decTable: string;
	
	    static createFrom(source: any = {}) {
	        return new PVVRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pvk = source["pvk"];
	        this.pvki = source["pvki"];
	        this.pin = source["pin"];
	        this.pan11 = source["pan11"];
	        this.decTable = source["decTable"];
	    }
	}
	export class PVVResult {
	    success: boolean;
	    pvv: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new PVVResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.pvv = source["pvv"];
	        this.error = source["error"];
	    }
	}
	export class RetailMACRequest {
	    key: string;
	    data: string;
	    padding: string;
	
	    static createFrom(source: any = {}) {
	        return new RetailMACRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	        this.padding = source["padding"];
	    }
	}
	export class SM2PINRequest {
	    key: string;
	    block: string;
	
	    static createFrom(source: any = {}) {
	        return new SM2PINRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.block = source["block"];
	    }
	}
	export class SM4CMACRequest {
	    key: string;
	    data: string;
	    padding: string;
	
	    static createFrom(source: any = {}) {
	        return new SM4CMACRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	        this.padding = source["padding"];
	    }
	}
	export class SM4FinanceRequest {
	    key: string;
	    data: string;
	    mode: string;
	    iv: string;
	    padding: string;
	
	    static createFrom(source: any = {}) {
	        return new SM4FinanceRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	        this.mode = source["mode"];
	        this.iv = source["iv"];
	        this.padding = source["padding"];
	    }
	}
	export class SM4MACRequest {
	    key: string;
	    data: string;
	    padding: string;
	
	    static createFrom(source: any = {}) {
	        return new SM4MACRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	        this.padding = source["padding"];
	    }
	}
	export class SM4PINRequest {
	    key: string;
	    block: string;
	
	    static createFrom(source: any = {}) {
	        return new SM4PINRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.block = source["block"];
	    }
	}
	export class SM4UDKRequest {
	    mdk: string;
	    pan: string;
	    psn: string;
	
	    static createFrom(source: any = {}) {
	        return new SM4UDKRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mdk = source["mdk"];
	        this.pan = source["pan"];
	        this.psn = source["psn"];
	    }
	}
	export class TDESRequest {
	    key: string;
	    data: string;
	    mode: string;
	    iv: string;
	    padding: string;
	
	    static createFrom(source: any = {}) {
	        return new TDESRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	        this.mode = source["mode"];
	        this.iv = source["iv"];
	        this.padding = source["padding"];
	    }
	}
	export class UDKRequest {
	    mdk: string;
	    pan: string;
	    psn: string;
	
	    static createFrom(source: any = {}) {
	        return new UDKRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mdk = source["mdk"];
	        this.pan = source["pan"];
	        this.psn = source["psn"];
	    }
	}
	export class UDKResult {
	    success: boolean;
	    udk: string;
	    left: string;
	    right: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new UDKResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.udk = source["udk"];
	        this.left = source["left"];
	        this.right = source["right"];
	        this.error = source["error"];
	    }
	}

}

export namespace gm {
	
	export class GMEnvelopeOpenRequest {
	    receiverPriv: string;
	    senderPub: string;
	    envelopeData: string;
	
	    static createFrom(source: any = {}) {
	        return new GMEnvelopeOpenRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.receiverPriv = source["receiverPriv"];
	        this.senderPub = source["senderPub"];
	        this.envelopeData = source["envelopeData"];
	    }
	}
	export class GMEnvelopeRequest {
	    senderPriv: string;
	    receiverPub: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new GMEnvelopeRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.senderPriv = source["senderPriv"];
	        this.receiverPub = source["receiverPub"];
	        this.data = source["data"];
	    }
	}
	export class SM2KeyAgreementRequest {
	    privateKey: string;
	    peerPublicKey: string;
	    myId: string;
	    peerId: string;
	    keyLen: number;
	    initiator: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SM2KeyAgreementRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.peerPublicKey = source["peerPublicKey"];
	        this.myId = source["myId"];
	        this.peerId = source["peerId"];
	        this.keyLen = source["keyLen"];
	        this.initiator = source["initiator"];
	    }
	}
	export class SM2KeyResult {
	    success: boolean;
	    privateKey: string;
	    publicKey: string;
	    privHex: string;
	    pubHex: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new SM2KeyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.privateKey = source["privateKey"];
	        this.publicKey = source["publicKey"];
	        this.privHex = source["privHex"];
	        this.pubHex = source["pubHex"];
	        this.error = source["error"];
	    }
	}
	export class SM2Request {
	    key: string;
	    data: string;
	    mode: string;
	
	    static createFrom(source: any = {}) {
	        return new SM2Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	        this.mode = source["mode"];
	    }
	}
	export class SM2SignRequest {
	    privateKey: string;
	    data: string;
	    id: string;
	
	    static createFrom(source: any = {}) {
	        return new SM2SignRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.data = source["data"];
	        this.id = source["id"];
	    }
	}
	export class SM2VerifyRequest {
	    publicKey: string;
	    data: string;
	    signature: string;
	    id: string;
	
	    static createFrom(source: any = {}) {
	        return new SM2VerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.publicKey = source["publicKey"];
	        this.data = source["data"];
	        this.signature = source["signature"];
	        this.id = source["id"];
	    }
	}
	export class SM3HMACRequest {
	    key: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new SM3HMACRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	    }
	}
	export class SM3Request {
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new SM3Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = source["data"];
	    }
	}
	export class SM4Request {
	    key: string;
	    iv: string;
	    nonce: string;
	    aad: string;
	    data: string;
	    mode: string;
	    padding: string;
	
	    static createFrom(source: any = {}) {
	        return new SM4Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.iv = source["iv"];
	        this.nonce = source["nonce"];
	        this.aad = source["aad"];
	        this.data = source["data"];
	        this.mode = source["mode"];
	        this.padding = source["padding"];
	    }
	}
	export class SM9KeyResult {
	    success: boolean;
	    privateKey: string;
	    publicKey: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new SM9KeyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.privateKey = source["privateKey"];
	        this.publicKey = source["publicKey"];
	        this.error = source["error"];
	    }
	}
	export class SM9MasterKeyResult {
	    success: boolean;
	    masterPrivateKey: string;
	    masterPublicKey: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new SM9MasterKeyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.masterPrivateKey = source["masterPrivateKey"];
	        this.masterPublicKey = source["masterPublicKey"];
	        this.error = source["error"];
	    }
	}
	export class SM9Request {
	    masterPublicKey: string;
	    userPrivateKey: string;
	    uid: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new SM9Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.masterPublicKey = source["masterPublicKey"];
	        this.userPrivateKey = source["userPrivateKey"];
	        this.uid = source["uid"];
	        this.data = source["data"];
	    }
	}
	export class SM9SignRequest {
	    userPrivateKey: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new SM9SignRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.userPrivateKey = source["userPrivateKey"];
	        this.data = source["data"];
	    }
	}
	export class SM9VerifyRequest {
	    masterPublicKey: string;
	    uid: string;
	    data: string;
	    signature: string;
	
	    static createFrom(source: any = {}) {
	        return new SM9VerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.masterPublicKey = source["masterPublicKey"];
	        this.uid = source["uid"];
	        this.data = source["data"];
	        this.signature = source["signature"];
	    }
	}
	export class ZUCRequest {
	    key: string;
	    iv: string;
	    data: string;
	    type: string;
	
	    static createFrom(source: any = {}) {
	        return new ZUCRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.iv = source["iv"];
	        this.data = source["data"];
	        this.type = source["type"];
	    }
	}

}

export namespace hash {
	
	export class HMACRequest {
	    algorithm: string;
	    key: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new HMACRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.algorithm = source["algorithm"];
	        this.key = source["key"];
	        this.data = source["data"];
	    }
	}
	export class HashRequest {
	    algorithm: string;
	    data: string;
	    outputSize: number;
	
	    static createFrom(source: any = {}) {
	        return new HashRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.algorithm = source["algorithm"];
	        this.data = source["data"];
	        this.outputSize = source["outputSize"];
	    }
	}

}

export namespace kdf {
	
	export class KDFRequest {
	    algorithm: string;
	    password: string;
	    salt: string;
	    info: string;
	    iterations: number;
	    keyLen: number;
	    cost: number;
	    n: number;
	    r: number;
	    p: number;
	    time: number;
	    memory: number;
	    threads: number;
	
	    static createFrom(source: any = {}) {
	        return new KDFRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.algorithm = source["algorithm"];
	        this.password = source["password"];
	        this.salt = source["salt"];
	        this.info = source["info"];
	        this.iterations = source["iterations"];
	        this.keyLen = source["keyLen"];
	        this.cost = source["cost"];
	        this.n = source["n"];
	        this.r = source["r"];
	        this.p = source["p"];
	        this.time = source["time"];
	        this.memory = source["memory"];
	        this.threads = source["threads"];
	    }
	}

}

export namespace mac {
	
	export class MACRequest {
	    algorithm: string;
	    key: string;
	    data: string;
	    iv: string;
	
	    static createFrom(source: any = {}) {
	        return new MACRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.algorithm = source["algorithm"];
	        this.key = source["key"];
	        this.data = source["data"];
	        this.iv = source["iv"];
	    }
	}

}

export namespace pqc {
	
	export class MLDSARequest {
	    privateKey: string;
	    data: string;
	    paramSet: string;
	
	    static createFrom(source: any = {}) {
	        return new MLDSARequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.data = source["data"];
	        this.paramSet = source["paramSet"];
	    }
	}
	export class MLDSAVerifyRequest {
	    publicKey: string;
	    data: string;
	    signature: string;
	    paramSet: string;
	
	    static createFrom(source: any = {}) {
	        return new MLDSAVerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.publicKey = source["publicKey"];
	        this.data = source["data"];
	        this.signature = source["signature"];
	        this.paramSet = source["paramSet"];
	    }
	}
	export class MLKEMDecapRequest {
	    privateKey: string;
	    ciphertext: string;
	    paramSet: string;
	
	    static createFrom(source: any = {}) {
	        return new MLKEMDecapRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.ciphertext = source["ciphertext"];
	        this.paramSet = source["paramSet"];
	    }
	}
	export class MLKEMRequest {
	    publicKey: string;
	    paramSet: string;
	
	    static createFrom(source: any = {}) {
	        return new MLKEMRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.publicKey = source["publicKey"];
	        this.paramSet = source["paramSet"];
	    }
	}
	export class PQCEncapResult {
	    success: boolean;
	    ciphertext: string;
	    sharedSecret: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new PQCEncapResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.ciphertext = source["ciphertext"];
	        this.sharedSecret = source["sharedSecret"];
	        this.error = source["error"];
	    }
	}
	export class PQCKeyResult {
	    success: boolean;
	    privateKey: string;
	    publicKey: string;
	    paramSet: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new PQCKeyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.privateKey = source["privateKey"];
	        this.publicKey = source["publicKey"];
	        this.paramSet = source["paramSet"];
	        this.error = source["error"];
	    }
	}
	export class SLHDSARequest {
	    privateKey: string;
	    data: string;
	    paramSet: string;
	
	    static createFrom(source: any = {}) {
	        return new SLHDSARequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.privateKey = source["privateKey"];
	        this.data = source["data"];
	        this.paramSet = source["paramSet"];
	    }
	}
	export class SLHDSAVerifyRequest {
	    publicKey: string;
	    data: string;
	    signature: string;
	    paramSet: string;
	
	    static createFrom(source: any = {}) {
	        return new SLHDSAVerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.publicKey = source["publicKey"];
	        this.data = source["data"];
	        this.signature = source["signature"];
	        this.paramSet = source["paramSet"];
	    }
	}

}

export namespace symmetric {
	
	export class AESRequest {
	    key: string;
	    iv: string;
	    nonce: string;
	    aad: string;
	    data: string;
	    mode: string;
	    padding: string;
	    keySize: number;
	    tagSize: number;
	
	    static createFrom(source: any = {}) {
	        return new AESRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.iv = source["iv"];
	        this.nonce = source["nonce"];
	        this.aad = source["aad"];
	        this.data = source["data"];
	        this.mode = source["mode"];
	        this.padding = source["padding"];
	        this.keySize = source["keySize"];
	        this.tagSize = source["tagSize"];
	    }
	}
	export class ChaChaRequest {
	    key: string;
	    nonce: string;
	    data: string;
	    type: string;
	    aad: string;
	    tag: string;
	
	    static createFrom(source: any = {}) {
	        return new ChaChaRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.nonce = source["nonce"];
	        this.data = source["data"];
	        this.type = source["type"];
	        this.aad = source["aad"];
	        this.tag = source["tag"];
	    }
	}
	export class CryptoResult {
	    success: boolean;
	    data: string;
	    error: string;
	    extra: string;
	
	    static createFrom(source: any = {}) {
	        return new CryptoResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.data = source["data"];
	        this.error = source["error"];
	        this.extra = source["extra"];
	    }
	}
	export class DESRequest {
	    key: string;
	    iv: string;
	    data: string;
	    mode: string;
	    padding: string;
	    type: string;
	
	    static createFrom(source: any = {}) {
	        return new DESRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.iv = source["iv"];
	        this.data = source["data"];
	        this.mode = source["mode"];
	        this.padding = source["padding"];
	        this.type = source["type"];
	    }
	}
	export class FPERequest {
	    key: string;
	    tweak: string;
	    data: string;
	    alphabet: string;
	    cipher: string;
	    mode: string;
	
	    static createFrom(source: any = {}) {
	        return new FPERequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.tweak = source["tweak"];
	        this.data = source["data"];
	        this.alphabet = source["alphabet"];
	        this.cipher = source["cipher"];
	        this.mode = source["mode"];
	    }
	}
	export class RC4Request {
	    key: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new RC4Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.data = source["data"];
	    }
	}
	export class SIVRequest {
	    mode: string;
	    key: string;
	    nonce: string;
	    aad: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new SIVRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.key = source["key"];
	        this.nonce = source["nonce"];
	        this.aad = source["aad"];
	        this.data = source["data"];
	    }
	}

}

export namespace utils {
	
	export class ASN1Request {
	    data: string;
	    format: string;
	
	    static createFrom(source: any = {}) {
	        return new ASN1Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = source["data"];
	        this.format = source["format"];
	    }
	}
	export class Base32Request {
	    data: string;
	    isHex: boolean;
	    noPadding: boolean;
	    variant: string;
	
	    static createFrom(source: any = {}) {
	        return new Base32Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = source["data"];
	        this.isHex = source["isHex"];
	        this.noPadding = source["noPadding"];
	        this.variant = source["variant"];
	    }
	}
	export class Base58Request {
	    data: string;
	    isHex: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Base58Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = source["data"];
	        this.isHex = source["isHex"];
	    }
	}
	export class Base64Request {
	    data: string;
	    format: string;
	    isHex: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Base64Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = source["data"];
	        this.format = source["format"];
	        this.isHex = source["isHex"];
	    }
	}
	export class BaseConvertRequest {
	    value: string;
	    from: number;
	    to: number;
	
	    static createFrom(source: any = {}) {
	        return new BaseConvertRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.value = source["value"];
	        this.from = source["from"];
	        this.to = source["to"];
	    }
	}
	export class Bech32DecodeResult {
	    success: boolean;
	    hrp: string;
	    data: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new Bech32DecodeResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.hrp = source["hrp"];
	        this.data = source["data"];
	        this.error = source["error"];
	    }
	}
	export class Bech32EncodeRequest {
	    hrp: string;
	    data: string;
	    isHex: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Bech32EncodeRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hrp = source["hrp"];
	        this.data = source["data"];
	        this.isHex = source["isHex"];
	    }
	}
	export class BigIntRequest {
	    a: string;
	    b: string;
	    n: string;
	    op: string;
	    baseFrom: number;
	    baseTo: number;
	
	    static createFrom(source: any = {}) {
	        return new BigIntRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.a = source["a"];
	        this.b = source["b"];
	        this.n = source["n"];
	        this.op = source["op"];
	        this.baseFrom = source["baseFrom"];
	        this.baseTo = source["baseTo"];
	    }
	}
	export class CSRRequest {
	    cn: string;
	    o: string;
	    c: string;
	    l: string;
	    st: string;
	    ou: string;
	    algo: string;
	    type: string;
	
	    static createFrom(source: any = {}) {
	        return new CSRRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.cn = source["cn"];
	        this.o = source["o"];
	        this.c = source["c"];
	        this.l = source["l"];
	        this.st = source["st"];
	        this.ou = source["ou"];
	        this.algo = source["algo"];
	        this.type = source["type"];
	    }
	}
	export class CertChainRequest {
	    leaf: string;
	    intermediates: string;
	    roots: string;
	
	    static createFrom(source: any = {}) {
	        return new CertChainRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.leaf = source["leaf"];
	        this.intermediates = source["intermediates"];
	        this.roots = source["roots"];
	    }
	}
	export class CertChainResult {
	    success: boolean;
	    valid: boolean;
	    data: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new CertChainResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.valid = source["valid"];
	        this.data = source["data"];
	        this.error = source["error"];
	    }
	}
	export class CertGenRequest {
	    csr: string;
	    days: number;
	    type: string;
	    algo: string;
	    san: string[];
	    isCA: boolean;
	    pathLen: number;
	    keyUsage: string[];
	    extKeyUsage: string[];
	    crlPoints: string[];
	    ocspUrls: string[];
	    policies: string[];
	
	    static createFrom(source: any = {}) {
	        return new CertGenRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.csr = source["csr"];
	        this.days = source["days"];
	        this.type = source["type"];
	        this.algo = source["algo"];
	        this.san = source["san"];
	        this.isCA = source["isCA"];
	        this.pathLen = source["pathLen"];
	        this.keyUsage = source["keyUsage"];
	        this.extKeyUsage = source["extKeyUsage"];
	        this.crlPoints = source["crlPoints"];
	        this.ocspUrls = source["ocspUrls"];
	        this.policies = source["policies"];
	    }
	}
	export class DualCertResult {
	    success: boolean;
	    signCert: string;
	    signKey: string;
	    encryptCert: string;
	    enwrappedKey: string;
	    rootCert: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new DualCertResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.signCert = source["signCert"];
	        this.signKey = source["signKey"];
	        this.encryptCert = source["encryptCert"];
	        this.enwrappedKey = source["enwrappedKey"];
	        this.rootCert = source["rootCert"];
	        this.error = source["error"];
	    }
	}
	export class FileDecryptRequest {
	    inputPath: string;
	    outputPath: string;
	    key: string;
	    algorithm: string;
	
	    static createFrom(source: any = {}) {
	        return new FileDecryptRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.inputPath = source["inputPath"];
	        this.outputPath = source["outputPath"];
	        this.key = source["key"];
	        this.algorithm = source["algorithm"];
	    }
	}
	export class FileEncryptRequest {
	    inputPath: string;
	    outputPath: string;
	    key: string;
	    algorithm: string;
	
	    static createFrom(source: any = {}) {
	        return new FileEncryptRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.inputPath = source["inputPath"];
	        this.outputPath = source["outputPath"];
	        this.key = source["key"];
	        this.algorithm = source["algorithm"];
	    }
	}
	export class FileHashRequest {
	    filePath: string;
	    algorithm: string;
	
	    static createFrom(source: any = {}) {
	        return new FileHashRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filePath = source["filePath"];
	        this.algorithm = source["algorithm"];
	    }
	}
	export class InternalCAResult {
	    success: boolean;
	    cert: string;
	    key: string;
	    csr: string;
	    root: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new InternalCAResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.cert = source["cert"];
	        this.key = source["key"];
	        this.csr = source["csr"];
	        this.root = source["root"];
	        this.error = source["error"];
	    }
	}
	export class JWTRequest {
	    token: string;
	    key: string;
	    keyFormat: string;
	    alg: string;
	    verify: boolean;
	
	    static createFrom(source: any = {}) {
	        return new JWTRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.token = source["token"];
	        this.key = source["key"];
	        this.keyFormat = source["keyFormat"];
	        this.alg = source["alg"];
	        this.verify = source["verify"];
	    }
	}
	export class JWTResult {
	    success: boolean;
	    header: string;
	    payload: string;
	    valid: boolean;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new JWTResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.header = source["header"];
	        this.payload = source["payload"];
	        this.valid = source["valid"];
	        this.error = source["error"];
	    }
	}
	export class KeyConvertRequest {
	    data: string;
	    format: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyConvertRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = source["data"];
	        this.format = source["format"];
	    }
	}
	export class KeyConvertResult {
	    success: boolean;
	    keyType: string;
	    pkcs1Pem: string;
	    pkcs8Pem: string;
	    publicPem: string;
	    derHex: string;
	    derBase64: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyConvertResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.keyType = source["keyType"];
	        this.pkcs1Pem = source["pkcs1Pem"];
	        this.pkcs8Pem = source["pkcs8Pem"];
	        this.publicPem = source["publicPem"];
	        this.derHex = source["derHex"];
	        this.derBase64 = source["derBase64"];
	        this.error = source["error"];
	    }
	}
	export class PKCS12Request {
	    data: string;
	    format: string;
	    password: string;
	
	    static createFrom(source: any = {}) {
	        return new PKCS12Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = source["data"];
	        this.format = source["format"];
	        this.password = source["password"];
	    }
	}
	export class PKCS12Result {
	    success: boolean;
	    keyPem: string;
	    certPem: string;
	    caPem: string;
	    error: string;
	    certInfo: string;
	
	    static createFrom(source: any = {}) {
	        return new PKCS12Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.keyPem = source["keyPem"];
	        this.certPem = source["certPem"];
	        this.caPem = source["caPem"];
	        this.error = source["error"];
	        this.certInfo = source["certInfo"];
	    }
	}
	export class PaddingRequest {
	    data: string;
	    mode: string;
	    blockSize: number;
	
	    static createFrom(source: any = {}) {
	        return new PaddingRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data = source["data"];
	        this.mode = source["mode"];
	        this.blockSize = source["blockSize"];
	    }
	}
	export class RandomRequest {
	    length: number;
	    format: string;
	
	    static createFrom(source: any = {}) {
	        return new RandomRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.length = source["length"];
	        this.format = source["format"];
	    }
	}
	export class SelfSignedCertRequest {
	    cn: string;
	    o: string;
	    c: string;
	    l: string;
	    st: string;
	    ou: string;
	    days: number;
	    algo: string;
	    isCA: boolean;
	    pathLen: number;
	    keyUsage: string[];
	    extKeyUsage: string[];
	    san: string[];
	    crlPoints: string[];
	    ocspUrls: string[];
	    policies: string[];
	
	    static createFrom(source: any = {}) {
	        return new SelfSignedCertRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.cn = source["cn"];
	        this.o = source["o"];
	        this.c = source["c"];
	        this.l = source["l"];
	        this.st = source["st"];
	        this.ou = source["ou"];
	        this.days = source["days"];
	        this.algo = source["algo"];
	        this.isCA = source["isCA"];
	        this.pathLen = source["pathLen"];
	        this.keyUsage = source["keyUsage"];
	        this.extKeyUsage = source["extKeyUsage"];
	        this.san = source["san"];
	        this.crlPoints = source["crlPoints"];
	        this.ocspUrls = source["ocspUrls"];
	        this.policies = source["policies"];
	    }
	}
	export class SelfSignedCertResult {
	    success: boolean;
	    cert: string;
	    key: string;
	    csr: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new SelfSignedCertResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.cert = source["cert"];
	        this.key = source["key"];
	        this.csr = source["csr"];
	        this.error = source["error"];
	    }
	}
	export class TimestampRequest {
	    value: string;
	    from: string;
	    to: string;
	    timezone: string;
	
	    static createFrom(source: any = {}) {
	        return new TimestampRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.value = source["value"];
	        this.from = source["from"];
	        this.to = source["to"];
	        this.timezone = source["timezone"];
	    }
	}
	export class ToolResult {
	    success: boolean;
	    data: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new ToolResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.data = source["data"];
	        this.error = source["error"];
	    }
	}
	export class XORRequest {
	    a: string;
	    b: string;
	
	    static createFrom(source: any = {}) {
	        return new XORRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.a = source["a"];
	        this.b = source["b"];
	    }
	}

}

