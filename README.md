# Secure P2P Messaging without a Central Server

## Description

[WhatsApp](https://www.whatsapp.com/), [Signal](https://signal.org/), [Telegram](https://telegram.org/), .. all use a central server that you must trust.  
[Threema](https://threema.ch/) is most likely the most secure messaging app.

How to build a messaging app that does not use a Central Server?

## Smart Contract
A PoC using a smart contract where encrypted messages are placed and retrieved using
public key encryption.

```solidity
//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.4;

import "hardhat/console.sol";

contract SecMsgI {
    mapping(string => address) _pseudos; // pseudo to address, optional
    mapping(address => string) _pubKeys; // address to public key, optional

    struct EM {
        address from;
        string message;
    }

    mapping(bytes32 => EM[]) _messages; // List of messages

    constructor() {
    }

    // Gets the public key associated with this pseudo
    function getPubKey(string memory pseudo) public view returns(string memory) {
        string memory pk =  _pubKeys[_pseudos[pseudo]];
         console.log("getPubKey/pk", pk);
        return pk;
    }

    // Registers a pseudo and public key 
    function registerPseudoPubKey(string memory pseudo, string memory pubKey) public {
        require(_pseudos[pseudo] != msg.sender, "Pseudo already taken");

        _pseudos[pseudo] = msg.sender;
        _pubKeys[msg.sender] = pubKey;

        console.log("registerPseudoPubKey/pubKey", pubKey);
    }

    function deleteAccount(string memory pseudo) public {
        address pseudo_address = _pseudos[pseudo];
        require(msg.sender == pseudo_address, "Can only delete your own account");
        delete _pseudos[pseudo];
        delete _pubKeys[msg.sender];
    }

    // Register an encrypted message for a user
    function registerMsgByPseudo(string memory pseudo, string memory what) public {
        address pseudo_address = _pseudos[pseudo];
        console.log("pseudo_address", pseudo_address);
        console.log("what", what);
        string memory pubKey = _pubKeys[pseudo_address];
        bytes32 pubKeyHash = sha256(bytes(pubKey));
        registerMsgByPubKey(pubKeyHash, what);
    }

    function registerMsgByPubKey(bytes32 pubKeyHash, string memory what) public {
        EM memory em = EM(msg.sender, what);
        _messages[pubKeyHash].push(em);
    }

    function numberOfMessages() public view returns (uint256) {
        string memory pubKey = _pubKeys[msg.sender];
        bytes32 pubKeyHash = sha256(bytes(pubKey));
        EM[] memory messages = _messages[pubKeyHash];
        return messages.length;
    }

    function getMessageById(uint256 index) public view returns (address, string memory) {
        string memory pubKey = _pubKeys[msg.sender];
        bytes32 pubKeyHash = sha256(bytes(pubKey));
        EM[] memory messages = _messages[pubKeyHash];
        EM memory em = messages[index];
        return (em.from, em.message);
    }

    function deleteMsgById(uint256 index) public {
        // TODO
    }

    function deleteAllMessages() public {
        string memory pubKey = _pubKeys[msg.sender];
        bytes32 pubKeyHash = sha256(bytes(pubKey));
        delete _messages[pubKeyHash];
    }
 }
```

A simple test:

```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");
const NodeRSA = require('node-rsa');

describe("Secure Messaging Test", function () {
  // https://www.npmjs.com/package/node-rsa
  const tj_key_pair = new NodeRSA({b: 512});

  let _sec_msg_contract;

  before(async () => {
    const SecMsgI = await ethers.getContractFactory("SecMsgI");
    _sec_msg_contract = await SecMsgI.deploy();
    await _sec_msg_contract.deployed();
  });

  it ("Test Register Public Key", async function () {
    const pub_key = tj_key_pair.exportKey("pkcs1-public");
    console.log(pub_key);

    // Registration of public key
    await _sec_msg_contract.registerPseudoPubKey("tj", pub_key);
  });

  it ("Test Get Key Back", async function () {
    const pub_key = await _sec_msg_contract.getPubKey("tj");
    console.log(pub_key);
  });

  it ("Register Message for Pseudo", async function () {
    const pub_key = await _sec_msg_contract.getPubKey("tj");
    console.log("pub_key: ", pub_key);

    // Encryption test
    const rsa = new NodeRSA();
    rsa.importKey(pub_key);
    const enc_msg = rsa.encrypt("Hello. You here?", "base64");
    console.log("encrypted msg: ", enc_msg);

    await _sec_msg_contract.registerMsgByPseudo("tj", enc_msg);

    const clear_msg = tj_key_pair.decrypt(enc_msg);
    console.log("clear_msg: ", clear_msg.toString());
  });

  it ("Number of messages", async function () {
    const nb_msgs = await _sec_msg_contract.numberOfMessages();
    console.log("nb_msgs: ", nb_msgs);
  });

  it ("Get Message By Id", async function () {
    const enc_msg = await _sec_msg_contract.getMessageById(0);
    const em = enc_msg[1];
    console.log("enc_msg: ", enc_msg[1]);

    const clear_msg = tj_key_pair.decrypt(em);
    console.log("clear_msg: ", clear_msg.toString());
  });
});
```

## Why this will never see the light of day?

Because once messages are posted on-chain, even though encrypted, in the future, they might be decrypted (quantum, weak key generation, ...)
