const CryptoJS = require("crypto-js");

// UTF-8 エンコード
function encodeUTF8(str) {
    return new TextEncoder().encode(str);
}

// ArrayBuffer を MD5 に変換
function getMD5HexFromBuffer(buffer) {
    const wordArray = CryptoJS.lib.WordArray.create(buffer);
    return CryptoJS.MD5(wordArray).toString(CryptoJS.enc.Hex);
}

// JSON を安定化して文字列化
function stableJSONStringify(obj) {
    return JSON.stringify(obj, Object.keys(obj).sort());
}

// JSON を UTF-8 ArrayBuffer に変換して MD5 計算
function getMD5Hex(input) {
    const jsonStr = stableJSONStringify(input);
    const utf8Buffer = encodeUTF8(jsonStr);
    return getMD5HexFromBuffer(utf8Buffer);
}

// データ例
const n = {
    data: {
        keys: [
            {
                kty: "oct",
                k: "20jjJlzTR6KTUh-t1TeBrA",
                kid: "uIFdYNVYShGCkN8ufLd0mA",
                alg: "A128KW",
            }
        ],
        type: "temporary",
    },
};

// ハッシュを計算
console.log(getMD5Hex(n.data));
