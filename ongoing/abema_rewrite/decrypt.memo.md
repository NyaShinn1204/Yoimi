kのdecrpy方法:

Step1.
n(8416)をrun
⇒7688, 5448, 6398, 2032をrun

n(1715)をrun
⇒5448, 7803, 3393をrun

n(8080)をrun
⇒1180, 2295をrun

n(1737)をrun(お目当てのやつ)
⇒var A = function e(t, n) {を実行しているところを探す line:56374
func eのt, nを生成しているところを探す。
疑ってるのは
line: 22038の
```
                                    for (var r = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(t))), i = [], a = 0; a < r.kids.length; a++) {
                                        var o = r.kids[a]
                                          , s = e.clearkeys && e.clearkeys.hasOwnProperty(o) ? e.clearkeys[o] : null;
                                        if (!s)
                                            throw new Error("DRM: ClearKey keyID (" + o + ") is not known!");
                                        i.push(new A(o,s))
```
の部分 でもdevで見ると実行されてなかった
なおこのコードは1737の中にある模様

Step2.
まだ暗号化されているのでどっかにあるコードを探す




番外:
initdataの取得:
requestKeySystemAccessのthen->x
↓
x->k->U->createKeySession
x:55957
k:55966
U:55979