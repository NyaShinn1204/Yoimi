var o = {
    AY: 403,
    Bl: 422,
    DE: 201,
    Jc: 307,
    OK: 200,
    Pf: 413,
    S: 415,
    Wm: 429,
    dr: 402,
    eV: 498,
    hB: 401,
    iq: 204,
    j7: 412,
    n: 500,
    p2: 404,
    p9: 409,
    qH: 400,
    wh: 202
}
var a = ["Y2hhckF0", "T3RPTWk=", "X19BQk1fTElDRU5TRV9QUk9YWV9f", "QlFWdXo=", "T1ptZUQ=", "aGlnaE9yZGVy", "cHVzaA==", "bGVuZ3Ro", "Q3dBUXI=", "bG93T3JkZXI=", "VEF0QUM=", "R0tLUkI=", "Ym1KZEo=", "T29XRlM=", "cURwQk4=", "UXRWRE4=", "a3JJRGs=", "ak5lYXY=", "UHBrZWs=", "Z3FicHY=", "Y0VnSWs=", "dXNo", "U2RvV3k=", "Z3NLS3I=", "Y2hhckNvZGVBdA==", "cG93", "RHVheUc=", "MDAwMDAwMDAwMDAwMDAwMA==", "UUpsZ3M=", "cmlnaHQ=", "VnhPRE8=", "bGVmdA==", "alhvZG4=", "c3BsaXQ=", "bWFw", "a1VlbWI=", "ZFpxZ3g=", "Zk1xTnM=", "andhRUU=", "SHJ6dEo=", "RnNTbXI=", "Z0JSV1g=", "QWxoY0c=", "TlpMVEU="];
var i = 181;
var auidwiaud = (function(r) {
    for (; --r; ) {
        a.push(a.shift());  // 配列aを回転
    }
    return a;  // 回転後の配列を返す
})(++i);
console.log(auidwiaud);  // 回転後の配列を表示
var c, f, h = function(r, n) {
    var e = a[r -= 0];
    void 0 === h.dQYSYC && (!function() {
        var r;
        try {
            r = Function('return (function() {}.constructor("return this")( ));')()
        } catch (n) {
            r = window
        }
        r.atob || (r.atob = function(r) {
            for (var n, e, t = String(r).replace(/=+$/, ""), i = 0, o = 0, u = ""; e = t.charAt(o++); ~e && (n = i % 4 ? 64 * n + e : e,
            i++ % 4) ? u += String.fromCharCode(255 & n >> (-2 * i & 6)) : 0)
                e = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(e);
            return u
        }
        )
    }(),
    h.dqEXRM = function(r) {
        for (var n = atob(r), e = [], t = 0, i = n.length; t < i; t++)
            e += "%" + ("00" + n.charCodeAt(t).toString(16)).slice(-2);
        return decodeURIComponent(e)
    }
    ,
    h.UnRRuZ = {},
    h.dQYSYC = !0);
    var t = h.UnRRuZ[r];
    return void 0 === t ? (e = h.dqEXRM(e),
    h.UnRRuZ[r] = e) : e = t,
    e
}, d = function(r, n) {
    this[h("0x0")] = r,
    this.lowOrder = n
}, l = function(r, n, e) {
    var t, i, o, u, s, a, c, f = [];
    for (f = n || [0],
    o = (e = e || 0) >>> 3,
    i = 0; i < r.length; i += 1)
        t = r.charCodeAt(i),
        u = (s = i + o) >>> 2,
        f.length <= u && f[h("0x1")](0),
        f[u] |= t << 8 * (3 - s % 4);
    return {
        value: f,
        binLen: (a = 8,
        c = r[h("0x2")],
        a * c + e)
    }
}, w = function(r) {
    var n, e, t = "", i = 4 * r.length;
    for (n = 0; n < i; n += 1)
        e = r[n >>> 2] >>> 8 * (3 - n % 4) & 255,
        t += String.fromCharCode(e);
    return t
}, v = function() {
    return l
}, p = function(r, n) {
    return r << n | r >>> 32 - n
}, g = function(r, n) {
    return r >>> n | r << 32 - n
}
function br(r) {
    for (var n = function(r, n) { return r < n }, e = function(r, n) { return r / n }, t = function(r, n) { return r - n }, i = function(r, n) { return r >= n }, o = function(r, n) { return r * n }, u = function(r, n) { return r & n }, s = {}, a = r[h("0x2")], c = r.charAt(0), f = 0; n(f, r.length); f++)
        decode_method = h("0x27")
        //console.log(decode_method)
        s[r[decode_method](f)] = f;
    return {
        e: function (o) {
            if (o[h("0x2")] === 0) return "";  // ここでも `h("0x2")` を使ってインデックスを取得

            var u = [0];
            for (var s = 0; n(s, o.length); ++s) {
                var c = 0,
                    f = o[s];

                for (c = 0; c < u.length; ++c) {
                    f += u[c] << 8;
                    u[c] = f % a;
                    f = (f / a) | 0;
                }

                while (f > 0) {
                    u.push(f % a);
                    f = 0 | e(f, a);
                }
            }

            var d = "";
            for (var l = 0; 0 === o[l] && n(l, t(o.length, 1)); ++l)
                d += r[0];

            for (var w = u.length - 1; i(w, 0); --w)
                d += r[u[w]];

            return d;
        },

        d: function (r) {
            if (r.length === 0) return [];

            var n = [0];

            for (var e = 0; e < r[h("0x2")]; e++) {  // ここでも `h("0x2")` を使ってインデックスを取得
                var t = s[r[e]];
                if (t === undefined) throw new Error("b" + a + "c");

                var i = 0,
                    f = t;
                for (i = 0; i < n.length; ++i) {
                    f += o(n[i], a);
                    n[i] = u(255, f);
                    f >>= 8;
                }

                while (f > 0) {
                    n.push(255 & f);
                    f >>= 8;
                }
            }

            for (var d = 0; r[d] === c && d < r.length - 1; ++d)
                n.push(0);

            return n.reverse();
        }
    };
}

function Cr(r, n, e) {
    var t, i, o, u, s, a, c, f, d, l, w, v, p = {
        RPJda: function(r, n, e) {
            return r(n, e)
        },
        pNEvf: function(r, n, e, t) {
            return r(n, e, t)
        },
        BQVuz: function(r, n) {
            return r(n)
        },
        OZmeD: function(r, n) {
            return r(n)
        }
    }, g = e[h("0x27")](e.length - 1), O = e.substring(0, e.length - 1);
    return J("5" === g ? (t = r,
    i = n,
    o = O,
    u = function(r, n) {
        return r(n)
    }
    ,
    s = function(r, n, e) {
        return r(n, e)
    }
    ,
    a = Dr(4),
    c = F(_r, a, t + i),
    f = F(_r, c, i),
    d = F(_r, c, t),
    l = mr(u(Rr, 5), $(f)),
    w = s(mr, Rr(5), u($, d)),
    v = Pr.d(o),
    v = mr(w, v),
    ir.d(v, l)) : "4" === g ? function(r, n, e) {
        var t = F(_r, Dr(3), p.RPJda(Ir, Dr(2), r))
          , i = F(_r, t, Ir(n, r))
          , o = p.pNEvf(F, _r, t, Ir(Dr(2), n))
          , u = Pr.d(e)
          , s = yr($(o), u);
        return ir.d(s, $(i))
    }(r, n, O) : function(r, n, e) {
        var t = F(_r, Dr(1), Ir(r, p[h("0x2a")](Dr, 0)))
          , i = F(_r, t, p.RPJda(Ir, r, n))
          , o = F(_r, t, Ir(n, Dr(0)))
          , u = Pr.d(e)
          , s = ir.d(u, p.BQVuz($, i));
        return yr(p[h("0x2b")]($, o), s)
    }(r, n, O))
}

function wn(r, n, e) {
    var t, i, o, u, s, a
    var c = function (r, n) {
        return r(n)
    }
    var f = function (r, n) {
        return r + n
    }
    var J = function (r) {
        return new Uint8Array(r)
    }

    var Fr = br("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    //付けたし
    var H = "Window" // ブラウザ定義
    var Ur = "String"
    var Nr = "fromCharCode"
    var jr = "apply" 
    var Mr = "parse"
    var Br = "JSON"
    var qr = "keys"
    var Jr = "kid"
    var Qr = "k"
    var Hr = "slice"
    var Wr = "indexOf"
    var Kr = "."
    var Xr = "stringify"

    var h = (t = (a = n, H[Ur][Nr][jr](null, J(a))), H[Br][Mr](t))
    var d = h[qr][0]
    var l = d[Jr]
    var w = d[Qr]
    var v = w[Hr](0, w[Wr](Kr))
    var p = w[Hr](w[Wr](Kr) + 1)
    var g = p[Hr](0, p[Wr](Kr))
    var O = p[Hr](f(p[Wr](Kr), 1))
    var x = (s = v, c(J, Fr.d(s)))

    //付けたし
    var $r = "lib"
    var rn = "WordArray"
    var nn = "create"

    var y = (o = r, u = Cr(l, e, g), o[$r][rn][nn](u));
    return d.k = function (r, n, e, t) {
        var i = {};
        i[hn] = r[$r][rn][nn](n);
        var o, u, s, a, c, f = {};
        //付けたし
        var en = "create"
        var sn = "CBC"
        var tn = "iv"
        var un = "enc"
        var an = "Hex"
        var Mr = "parse"
        var on = "padding"
        var cn = "pad"
        var fn = "Pkcs7"
        var zr = "AES"
        var ln = "decrypt"
        var Yr = "toString"
        var dn = "Utf8"

        return f[en] = r[en][sn],
            f[tn] = (c = t,
            r[un][an][Mr](c)),
            f[on] = r[cn][fn],
            (o = r, u = i, s = e, a = f, o[zr][ln](u, s, a))[Yr](r[un][dn])
    }(r, x, y, O),
        function (r) {
            var Gr = "length"
            var Zr = "charCodeAt"
            var Vr = "buffer"
            for (var n = r[Gr], e = J(n), t = 0; t < n; ++t)
                e[t] = r[Zr](t);
            return e[Vr]
        }((i = h,H[Br][Xr](i)))
}

function vn(r) {
    //付けたし
    var Tr = "abm_userId"
    var Ar = "localStorage"
    var Lr = "getItem"
    //var n, e = (n = Tr,
    //Ar[Lr](n));
    var n, e = (n=Tr, e="EX4EKv39PYnRJF")
    return function(n) {
        return wn(r, n, e)
    }
}
const On = {}; // WeakMap の代わりに普通のオブジェクトを使用

function yn(r) {
    const encryptionObject = {
        AES: { encrypt: () => {}, decrypt: () => {} },
        Blowfish: { encrypt: () => {}, decrypt: () => {} },
        DES: { encrypt: () => {}, decrypt: () => {} },
        HmacSHA256: (t, n) => "hmac_sha256_result",
        SHA256: (t, n) => "sha256_result",
        enc: {
            Utf8: { parse: () => {}, stringify: () => {} }
        },
        mode: { CBC: { processBlock: () => {} } },
        pad: { Pkcs7: { pad: () => {}, unpad: () => {} } }
    };
    On[r] = vn(encryptionObject); // オブジェクトのキーに r をセット

    var n = {
        data: {
            keys: [
                {
                    k: "GF5kEzJ57JMwj4ANiVjXK96YmupfqKJEGoRxcEr5D2xc.DyE8UXxDHTRoHqSFv8MnVv5.4a9dd24b59a7b15308a1fe46e31c7fa8",
                    kid: "uIFdYNVYShGCkN8ufLd0mA",
                    kty: "oct"
                }
            ],
            type: "temporary"
        }, 
        headers: {
            "content-length": "182",
            "content-type": "application/json"
        },
        url: "https://license.p-c3-e.abema-tv.com/abematv-dash?" +
             "t=6sJtxaJyf4tSDqoGNAmSqTScKrBUAxNZFXXur5XRWfKbw46V928K3nAeLZttpJUHsJEHSFhgubHG5QFJCXY9Kn2DgEE7XNucaYMt3Ppsgs6T1E2WCj6unr" +
             "&cid=25-147_s1_p1&ct=program"
    };

    if (n.url.includes("https://license.p-c3-e.abema-tv.com/abematv-dash") && n.headers["content-type"] === "application/json") {
        const e = On[r]; // get に相当する処理
        if (e === undefined)
            throw new Error("Unexpected Error: Decoder is missing.");

        const t = e(function(r) {
            const n = JSON.stringify(r);
            const e = new TextEncoder();
            return e.encode(n).buffer;
        }(n.data));

        n.data = function(r) {
            const n = new TextDecoder();
            const e = new Uint8Array(r);
            const t = n.decode(e);
            return JSON.parse(t);
        }(t);
    }

    return Promise.resolve();
}

yn(undefined);