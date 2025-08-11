Java.perform(function() {
    var cls = Java.use("jp.co.rakuten.video.rakutentvapp.presentation.ui.activity.MobileWelcomeActivity");
    cls.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
        console.log("Redirecting MobileWelcomeActivity to MainActivity");
        this.onCreate.call(this, bundle); // super呼び出し
        var intent = Java.use("android.content.Intent").$new(this, Java.use("jp.co.rakuten.video.rakutentvapp.presentation.ui.activity.HomeActivity").class);
        this.startActivity(intent);
        this.finish();
    };
});
