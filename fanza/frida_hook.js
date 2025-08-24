Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload('int','java.security.Key','java.security.spec.AlgorithmParameterSpec').implementation = function(mode, key, params) {
        // Key の取得
        var key_bytes = key.getEncoded();
        var key_array = [];
        for (var i = 0; i < key_bytes.length; i++) {
            key_array.push(key_bytes[i]);
        }

        // params は IvParameterSpec かもしれないが安全に byte[] として取得
        var iv_array = [];
        try {
            if (params && params.getIV) { // メソッドが存在するかチェック
                var iv_bytes = params.getIV();
                for (var i = 0; i < iv_bytes.length; i++) {
                    iv_array.push(iv_bytes[i]);
                }
            }
        } catch(err) {
            console.log("[Cipher.init] IV の取得に失敗しました: " + err);
        }

        console.log("[Cipher.init] mode: " + mode);
        console.log("[Cipher.init] key_bytes: " + key_array);
        console.log("[Cipher.init] iv_bytes: " + iv_array);

        // 元の init を呼ぶ
        return this.init(mode, key, params);
    };
});
