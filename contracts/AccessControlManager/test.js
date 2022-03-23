const web3 = require("web3")
const ethSigUtil = require("eth-sig-util");

console.log(web3)

function checkSignature(nonce, signature) {
    const msgParams = {
        data: nonce,
        sig: signature
    };
    return ethSigUtil.recoverPersonalSignature(msgParams);
}
var x= checkSignature("0xnycu","0x5cb95ba06317a72a99d876fb83d6c5ad30250aec1f734e6729c77321d36db4707089b1e1e928befd4bd4354f142e88894d2c2b5a8f54eec80674625fc470c62e1b");
console.log(x)
//let r = web3.eth.personal.recover("0xnycu", "0x5cb95ba06317a72a99d876fb83d6c5ad30250aec1f734e6729c77321d36db4707089b1e1e928befd4bd4354f142e88894d2c2b5a8f54eec80674625fc470c62e1b").toUpperCase();
//console.log(r)