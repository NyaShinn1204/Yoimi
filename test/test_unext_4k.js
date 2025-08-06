Java.perform(function () {
    console.log("[*] U-Next Bypass 4k Check");

    // 1. DisplayCompat.getMode() を偽装（解像度: 3840x2160）
    try {
        var DisplayCompat = Java.use("androidx.core.view.DisplayCompat");
        var ModeCompat = Java.use("androidx.core.view.DisplayCompat$ModeCompat");

        DisplayCompat.getMode.overload("android.content.Context", "android.view.Display").implementation = function (context, display) {
            console.log("[+] 偽の4K DisplayCompat.ModeCompat を返す");
            return ModeCompat.$new(true, 3840, 2160); // isNative = true
        };
    } catch (e) {
        console.error("[-] DisplayCompat フック失敗: " + e);
    }

    // 2. DisplayDetectorKt.m5760a() を常に false に
    try {
        var DisplayDetectorKt = Java.use("DisplayDetectorKt");

        DisplayDetectorKt.m5760a.implementation = function () {
            console.log("[+] m5760a() → false を強制");
            return false;  // または true にすれば逆の挙動
        };
    } catch (e) {
        console.error("[-] DisplayDetectorKt フック失敗: " + e);
    }

    // 3. SharedPreferences.getInt() の "4k_support_check_mode" を 0 に偽装
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");

        SharedPreferencesImpl.getInt.overload('java.lang.String', 'int').implementation = function (key, defValue) {
            if (key === "4k_support_check_mode") {
                console.log("[+] 4k_support_check_mode を 0 に偽装");
                return 0;
            }
            return this.getInt(key, defValue);
        };
    } catch (e) {
        console.error("[-] SharedPreferences フック失敗: " + e);
    }

    // 4. m5789b() を直接 true にする（クラス名は難読化されているかも）
    try {
        var TargetClass = Java.use("jp.unext.sdk.player.impl.PlayerFactory"); // ← ここを正しいクラス名に置き換える
        TargetClass.m5789b.implementation = function () {
            console.log("[+] m5789b() を true に強制");
            return true;
        };
    } catch (e) {
        console.warn("[-] m5789b() フックに失敗またはクラス名未設定: " + e);
    }

    console.log("[*] 全フック完了");
});
