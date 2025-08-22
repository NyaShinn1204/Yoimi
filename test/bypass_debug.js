// Bypass jp.ne.wowow.vod.androidtv
Java.perform(function () {
    var SettingsSecure = Java.use("android.provider.Settings$Secure");

    SettingsSecure.getInt.overload(
        "android.content.ContentResolver",
        "java.lang.String",
        "int"
    ).implementation = function (cr, name, def) {
        if (name === "adb_enabled") {
            console.log("[*] Bypassing adb_enabled check");
            return 0;
        }
        return this.getInt(cr, name, def);
    };
});

// Bypass jp.wowow.wod
Java.perform(function () {
    var Cls = Java.use('jp.wowow.wod.feature.parts.checker.WowowServiceVerifier$verify$5');
    var C7495b = Java.use('jp.wowow.wod.feature.parts.checker.b');

    Cls.invokeSuspend.implementation = function (param) {
        console.log('[Bypass] invokeSuspend called, skipping all ADB checks');

        try {
            // this.L$0 が C7495b ならそのまま返す
            if (this.L$0 && Java.cast(this.L$0, C7495b)) {
                console.log('Returning existing L$0');
                return this.L$0;
            }
        } catch (e) {
            console.log('L$0 cast failed:', e);
        }

        try {
            // param が C7495b なら返す
            if (param && Java.cast(param, C7495b)) {
                console.log('Returning param');
                return param;
            }
        } catch (e) {
            console.log('Param cast failed:', e);
        }

        // ダミーの C7495b を作って返す
        console.log('Creating dummy C7495b');
        var dummy = C7495b.$new(); // デフォルトコンストラクタ
        return dummy;
    };
});
