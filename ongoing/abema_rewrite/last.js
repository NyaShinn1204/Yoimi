const CryptoJS = require("crypto-js");
const key = CryptoJS.lib.WordArray.create([
    -1371776855,
    833737578,
    1953869114,
    1642737802
]);
const iv = CryptoJS.lib.WordArray.create([
    1251856971,
    1504162131,
    144834118,
    -484671576
]);
const ciphertext = CryptoJS.lib.WordArray.create([
    -495268593,
    -1914933604,
    1238500604,
    507301613,
    -174559424,
    -699451963,
    778833758,
    -1691233475
]);
const decrypted = CryptoJS.AES.decrypt(
    { ciphertext: ciphertext },
    key,
    { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
);
console.log(decrypted.toString(CryptoJS.enc.Utf8));