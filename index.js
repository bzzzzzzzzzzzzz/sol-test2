import * as umbral from "@nucypher/umbral-pre";
import { capsule_fromBytes, reencryptionevidence_e, reencryptionevidence_new } from "@nucypher/umbral-pre/pkg-bundler/umbral_pre_wasm_bg.wasm";
const publicKeyToAddress = require('ethereum-public-key-to-address')
import Web3 from "web3";

let enc = new TextEncoder();
let dec = new TextDecoder("utf-8");

var listingFactoryContractAddress = "0xaeC48BFD0cabb91E7505EAA9887eb076d11696D7" // grab this from ganache

// ALICE Key Generation
var alice_sk;
var alice_pk;
var signing_sk;
var signer;
var verifying_pk;

function generateAliceKeys() {
    alice_sk = umbral.SecretKey.random();
    alice_pk = alice_sk.publicKey();
    signing_sk = umbral.SecretKey.random();
    signer = new umbral.Signer(signing_sk);
    verifying_pk = signing_sk.publicKey();
     
    document.getElementById("var1").value = alice_sk.toBEBytes();
    document.getElementById("var2").value = alice_pk.toCompressedBytes();
    document.getElementById("var3").value = signing_sk.toBEBytes();
    document.getElementById("var4").value = verifying_pk.toCompressedBytes();   
}

const generateAliceKeysButton = document.getElementById("generateAliceKeys");
generateAliceKeysButton.addEventListener("click", generateAliceKeys)




// ALICE creates listing
function createListing() {
    // grab values from html
    var ipfsCID = document.getElementById("IPFS_CID").value;
    var aesKey = document.getElementById("AES_Key").value;
    var dkeyPrice = document.getElementById("DKEY_Price").value;
    var alicePublicKeyBytes = document.getElementById("Alice_PublicKey").value;
    var howManyCFragsForSale = document.getElementById("Number_of_CFrags").value;
    
    // encode AES decryption key into bytes
    var plaintext_bytes = enc.encode(aesKey);
    
    // use alice pub key to encrypt the aesKey bytes, making capsule + ciphertext
    alicePublicKeyBytes = alicePublicKeyBytes.split(",").map(function (item) {return +item;});
    var alicePublicKey = umbral.PublicKey.fromCompressedBytes(Uint8Array.from(alicePublicKeyBytes))
    var [capsule, ciphertext] = umbral.encrypt(alicePublicKey, plaintext_bytes);

    // make web3 object
    const web3 = new Web3(window.ethereum)
    
    // convert aliceCreatesListing args using web3.utils to make them solidity friendly
    ipfsCID = web3.utils.asciiToHex(ipfsCID);
    var capsuleHex = web3.utils.bytesToHex(capsule.toBytes());
    var capsuleSimpleHex = web3.utils.bytesToHex(capsule.toBytesSimple());
    ciphertext = web3.utils.bytesToHex(ciphertext);
    howManyCFragsForSale = web3.utils.toWei(howManyCFragsForSale, 'wei'); 
    dkeyPrice = web3.utils.toWei(dkeyPrice.toString(), 'kwei');
    var alicePublicKeyHexBytes = web3.utils.bytesToHex(alicePublicKeyBytes);
    
    // call ListingFactory.sol's aliceCreatesListing() func
    var contractJSON = require("./build/contracts/Test.json");
    var abi = contractJSON.abi;
    var contractAddress = listingFactoryContractAddress //contractJSON.networks[5777].address;
    var contract = new web3.eth.Contract(abi, contractAddress);

    // hardcoded Alice's "from" address (just an address from the ganache network), to be reused later
    contract.methods.aliceCreatesListing(ipfsCID, howManyCFragsForSale, dkeyPrice, alicePublicKeyHexBytes, capsuleHex, capsuleSimpleHex, ciphertext).send({ from: "0x24608b352C4f6BCDa85c303d3b450a96F455e8bE" });
}
const triggerPolicyCreation = document.getElementById("Trigger_Policy_Creation");
triggerPolicyCreation.addEventListener("click", createListing)




function checkListing() {
    const web3 = new Web3(window.ethereum)
    var contractJSON = require("./build/contracts/Test.json");
    var abi = contractJSON.abi;
    var contractAddress = listingFactoryContractAddress //contractJSON.networks[5777].address;
    var contract = new web3.eth.Contract(abi, contractAddress);

    var ipfsCID = document.getElementById("IPFS_CID").value;
    ipfsCID = web3.utils.asciiToHex(ipfsCID);

    contract.methods.getCapsule(ipfsCID).call().then(function(result){
        console.log(result[0]);
    });
}
const triggerCheckListing = document.getElementById("Check_Listing");
triggerCheckListing.addEventListener("click", checkListing)




// BOB generates keys... 
function bobGeneratesKeys() {
    var bob_sk = umbral.SecretKey.random();
    var bob_pk = bob_sk.publicKey();
     
    document.getElementById("var10").value = bob_sk.toBEBytes();
    document.getElementById("var11").value = bob_pk.toCompressedBytes();
}
const triggerBobGeneratesKeys = document.getElementById("generateBobKeys");
triggerBobGeneratesKeys.addEventListener("click", bobGeneratesKeys)




// BOB pays ALICE's specified amount to smart contract... 
function bobMakesPayment() {
   // grab html values
   var ipfsCID = document.getElementById("IPFS_CID_Bob").value;
   var dkeyPrice = document.getElementById("DKEY_Price_Bob").value;
   var bobPublicKeyBytes = document.getElementById("Bob_DecryptingPublicKey").value;

   // make Web3 instance
   const web3 = new Web3(window.ethereum)

   //format values
   bobPublicKeyBytes = bobPublicKeyBytes.split(",").map(function (item) {return +item;});
   var bobDecryptingPubKey = web3.utils.bytesToHex(bobPublicKeyBytes);
   ipfsCID = web3.utils.asciiToHex(ipfsCID);

    // call ListingFactory.sol's bobSendsPaymentToListing() func
    var contractJSON = require("./build/contracts/Test.json");
    var abi = contractJSON.abi;
    var contractAddress = listingFactoryContractAddress //should be contractJSON.networks[5777].address;
    var contract = new web3.eth.Contract(abi, contractAddress);

    const value = web3.utils.toWei(dkeyPrice, 'ether'); 
    const options = {
        from: '0x24608b352C4f6BCDa85c303d3b450a96F455e8bE', // hardcoded Bob's "from" address (just an address from the ganache network), to be reused later
        value: value
    };
    
    contract.methods.bobSendsPaymentToListing(ipfsCID, bobDecryptingPubKey).send(options);
}
const triggerBobMakesPayment = document.getElementById("Bob_Makes_Payment");
triggerBobMakesPayment.addEventListener("click", bobMakesPayment)




// ALICE checks the smart contract events to see if any BOBs have paid
function checkIfPaymentReceived() {
    // instantiate web3 obj
    const web3 = new Web3(window.ethereum)
    
    // grab ipfsCID from html, and format it
    var ipfsCID = document.getElementById("IPFS_CID2").value;
    ipfsCID = web3.utils.asciiToHex(ipfsCID);

    // make contract obj    
    var contractJSON = require("./build/contracts/Test.json");
    var abi = contractJSON.abi;
    var contractAddress = listingFactoryContractAddress //contractJSON.networks[5777].address;
    var contract = new web3.eth.Contract(abi, contractAddress);

    // read from past events (filtered by ipfsCid), and save values
    contract.getPastEvents('PaymentReceived', {
        fromBlock: 0
    }, function(error, events){ 
        document.getElementById("var5").value = events.length
    }).then(function(events){
        events.forEach(function(event){
            // document.getElementById("var20").value = web3.utils.hexToString(event.returnValues[0])
            document.getElementById("var6").value = web3.utils.hexToBytes(event.returnValues[1])
            document.getElementById("var7").value = web3.utils.hexToBytes(event.returnValues[3])
        
        });
    });
}
const triggerPaymentReceivedCheck = document.getElementById("checkIfPaymentReceived");
triggerPaymentReceivedCheck.addEventListener("click", checkIfPaymentReceived)




// ALICE responds to BOB's payment, by creating and sending a cfrag she's reencrypted for BOB
function aliceCreatesCFrag() {
    // grab values from html
    var ipfsCID = document.getElementById("IPFS_CID3").value;
    var alicePublicKeyBytes = document.getElementById("Alice_PublicKey").value;
    var aliceSecretKeyBytes = document.getElementById("Alice_SecretKey").value;
    var aliceVerifyingPublicKeyBytes = document.getElementById("Alice_VerifyingPublicKey").value;
    var aliceSigningSecretKeyBytes = document.getElementById("Alice_SigningSecretKey").value;
    var bobPublicKeyBytes = document.getElementById("Bob_PublicKey").value;
    var capsuleBytes = document.getElementById("Capsule_Bytes").value;

    // format values
    alicePublicKeyBytes = alicePublicKeyBytes.split(",").map(function (item) {return +item;});
    var alicePublicKey = umbral.PublicKey.fromCompressedBytes(Uint8Array.from(alicePublicKeyBytes))
    
    aliceSecretKeyBytes = aliceSecretKeyBytes.split(",").map(function (item) {return +item;});
    var aliceSecretKey = umbral.SecretKey.fromBEBytes(Uint8Array.from(aliceSecretKeyBytes))
    
    aliceVerifyingPublicKeyBytes = aliceVerifyingPublicKeyBytes.split(",").map(function (item) {return +item;});
    var aliceVerifyingPublicKey = umbral.PublicKey.fromCompressedBytes(Uint8Array.from(aliceVerifyingPublicKeyBytes))

    aliceSigningSecretKeyBytes = aliceSigningSecretKeyBytes.split(",").map(function (item) {return +item;});
    var aliceSigningSecretKey = umbral.SecretKey.fromBEBytes(Uint8Array.from(aliceSigningSecretKeyBytes))
    signer = new umbral.Signer(aliceSigningSecretKey);

    bobPublicKeyBytes = bobPublicKeyBytes.split(",").map(function (item) {return +item;});
    var bobPublicKey = umbral.PublicKey.fromCompressedBytes(Uint8Array.from(bobPublicKeyBytes))
    
    capsuleBytes = capsuleBytes.split(",").map(function (item) {return +item;});
    var capsule = umbral.Capsule.fromBytes(Uint8Array.from(capsuleBytes))
    
    const fromHexString = (hexString) => 
        Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
    
    var alice_address_str = publicKeyToAddress(Buffer.from(alicePublicKey.toCompressedBytes())).slice(2)
    var alice_address = fromHexString(alice_address_str)

    // create kfrag
    let shares = 2; // how many fragments to create
    let threshold = 1; // how many should be enough to decrypt
    let kfrags = umbral.generateKFrags(
        aliceSecretKey, bobPublicKey, signer, threshold, shares,
        true, // add the delegating key (alice_pk) to the signature
        true, // add the receiving key (bob_pk) to the signature
    );
    let kfrag0 = umbral.KeyFrag.fromBytes(kfrags[0].toBytes())
    let verifiedKFrag0 = kfrag0.verify(aliceVerifyingPublicKey, alicePublicKey, bobPublicKey)

    // create cfrag
    let cfrag0 = umbral.reencrypt(capsule, verifiedKFrag0);
    
    // create reencryption evidence
    let evidence = new umbral.ReencryptionEvidence(capsule, cfrag0, aliceVerifyingPublicKey, alicePublicKey, bobPublicKey)

    let pointEyCoord = evidence.e.coordinates()[1]
    let pointEZxCoord = evidence.ez.coordinates()[0]
    let pointEZyCoord = evidence.ez.coordinates()[1]
    let pointE1yCoord = evidence.e1.coordinates()[1]
    let pointE1HxCoord = evidence.e1h.coordinates()[0]
    let pointE1HyCoord = evidence.e1h.coordinates()[1]
    let pointE2yCoord = evidence.e2.coordinates()[1]
    let pointVyCoord = evidence.v.coordinates()[1]
    let pointVZxCoord = evidence.vz.coordinates()[0]
    let pointVZyCoord = evidence.vz.coordinates()[1]
    let pointV1yCoord = evidence.v1.coordinates()[1]
    let pointV1HxCoord = evidence.v1h.coordinates()[0]
    let pointV1HyCoord = evidence.v1h.coordinates()[1]
    let pointV2yCoord = evidence.v2.coordinates()[1]
    let pointUZxCoord = evidence.uz.coordinates()[0]
    let pointUZyCoord = evidence.uz.coordinates()[1]
    let pointU1yCoord = evidence.u1.coordinates()[1]
    let pointU1HxCoord = evidence.u1h.coordinates()[0]
    let pointU1HyCoord = evidence.u1h.coordinates()[1]
    let pointU2yCoord = evidence.u2.coordinates()[1]
    let hashedKFragValidityMessage = evidence.kfragValidityMessageHash
    let alicesKeyAsAddress = alice_address
    let lostBytesBool = evidence.kfragSignatureV

    if (lostBytesBool == false) {
        var lostBytes = new Uint8Array([0x00])
    } else {
        var lostBytes = new Uint8Array([0x01])
    }

    let eval_args = new Uint8Array([
        ...pointEyCoord,
        ...pointEZxCoord,
        ...pointEZyCoord,
        ...pointE1yCoord,
        ...pointE1HxCoord,
        ...pointE1HyCoord,
        ...pointE2yCoord,
        ...pointVyCoord,
        ...pointVZxCoord,
        ...pointVZyCoord,
        ...pointV1yCoord,
        ...pointV1HxCoord,
        ...pointV1HyCoord,
        ...pointV2yCoord,
        ...pointUZxCoord,
        ...pointUZyCoord,
        ...pointU1yCoord,
        ...pointU1HxCoord,
        ...pointU1HyCoord,
        ...pointU2yCoord,
        ...hashedKFragValidityMessage,
        ...alicesKeyAsAddress,
        ...lostBytes,                       
        ...lostBytes,
        ...lostBytes,
        ...lostBytes,
        ...lostBytes,
    ])

    capsule = capsule.toBytesSimple()
    let unverified_cfrag0 = cfrag0.unverify()
    let unverified_cfrag0_bytes = unverified_cfrag0.toBytesSimple()


    // connect to the local network, create a contract object
    const web3 = new Web3(window.ethereum)
    var contractJSON = require("./build/contracts/Test.json");
    var abi = contractJSON.abi;
    var contractAddress = listingFactoryContractAddress //contractJSON.networks[5777].address;
    var contract = new web3.eth.Contract(abi, contractAddress);

    // convert uint8 array into hex str
    var bobDecryptingPubKey = web3.utils.bytesToHex(bobPublicKeyBytes);
    ipfsCID = web3.utils.asciiToHex(ipfsCID);
    capsule = web3.utils.bytesToHex(capsule);
    cfrag0 = web3.utils.bytesToHex(unverified_cfrag0_bytes);
    eval_args = web3.utils.bytesToHex(eval_args);

    contract.methods.aliceSendsCFrag(bobDecryptingPubKey, ipfsCID, cfrag0, eval_args, capsule).send({ from: "0x24608b352C4f6BCDa85c303d3b450a96F455e8bE" }).then(function(result){
        console.log(result);
    });
}

const triggerCFragCreation = document.getElementById("Trigger_CFrag_Creation");
triggerCFragCreation.addEventListener("click", aliceCreatesCFrag)




// bob grabs ReencryptedKeyProvided event data and decrypts file in-browser...