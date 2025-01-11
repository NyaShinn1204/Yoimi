var fingerprint2 = require('fingerprintjs2');

let options = {excludes: {userAgent: true, enumerateDevices: true, pixelRatio: true, doNotTrack: true, fontsFlash: true}};
fingerprint2.getV18( options, (result)=>{
    console.log(result)
    // 取得後にlogin前処理呼出し
    this.beforeLogin(info);
});

console.log(result);