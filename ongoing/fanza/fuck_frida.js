Java.perform(function() {
    // UnityPlayer クラスをロード
    var UnityPlayer = Java.use("com.unity3d.player.UnityPlayer");

    // UnitySendMessage メソッドを取得
    var UnitySendMessage = UnityPlayer.UnitySendMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String');

    // メソッドにフック
    UnitySendMessage.implementation = function(obj, method, message) {
        console.log("UnitySendMessage called: obj=" + obj + ", method=" + method + ", message=" + message);
        // 元のメソッドを呼び出す
        this.UnitySendMessage(obj, method, message);
    };
});