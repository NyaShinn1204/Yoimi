var l = function(r, n, e) {
    var t, i, o, u, s, a, c, f = [];
    for (f = n || [0],
    o = (e = e || 0) >>> 3,
    i = 0; i < r.length; i += 1)
        t = r.charCodeAt(i),
        u = (s = i + o) >>> 2,
        f.length <= u && f.push(0),
        f[u] |= t << 8 * (3 - s % 4);
    return {
        value: f,
        binLen: (a = 8,
        c = r.length,
        a * c + e)
    }
}
var d = function(r, n) {
    this.highOrder = r,
    this.lowOrder = n
}
var g = function(r, n) {
    return r >>> n | r << 32 - n
}
var v = function() {
    return l
}
var w = function(r) {
    var n, e, t = "", i = 4 * r.length;
    for (n = 0; n < i; n += 1)
        e = r[n >>> 2] >>> 8 * (3 - n % 4) & 255,
        t += String.fromCharCode(e);
    return t
}
var Z = function(r) {
    var n, e, t;
    if (1 === r)
        n = [1732584193, 4023233417, 2562383102, 271733878, 3285377520];
    else
        switch (e = [3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428],
        t = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225],
        r) {
        case 224:
            n = e;
            break;
        case 256:
            n = t;
            break;
        case 384:
            n = [new d(3418070365,e[0]), new d(1654270250,e[1]), new d(2438529370,e[2]), new d(355462360,e[3]), new d(1731405415,e[4]), new d(41048885895,e[5]), new d(3675008525,e[6]), new d(1203062813,e[7])];
            break;
        case 512:
            n = [new d(t[0],4089235720), new d(t[1],2227873595), new d(t[2],4271175723), new d(t[3],1595750129), new d(t[4],2917565137), new d(t[5],725511199), new d(t[6],4215389547), new d(t[7],327033209)];
            break;
        default:
            throw new Error("variant")
        }
    return n
}
var A = function(r, n) {
    var e = {
        KSWbw: function(r, n) {
            return r + n
        },
        qDpBN: function(r, n) {
            return r | n
        },
        YQnAZ: function(r, n) {
            return r + n
        },
        QtVDN: function(r, n) {
            return r >>> n
        },
        BRDLZ: function(r, n) {
            return r & n
        }
    }
      , t = e.KSWbw(65535 & r, 65535 & n);
    return e.qDpBN((65535 & e.YQnAZ((r >>> 16) + (n >>> 16), e.QtVDN(t, 16))) << 16, e.BRDLZ(65535, t))
}, j = function(r, n, e, t) {
    var i = {
        gXRMN: function(r, n) {
            return r | n
        },
        ASQcV: function(r, n) {
            return r << n
        },
        krIDk: function(r, n) {
            return r + n
        },
        OGiIK: function(r, n) {
            return r + n
        },
        nSUEx: function(r, n) {
            return r >>> n
        }
    }
      , o = (65535 & r) + (65535 & n) + (65535 & e) + (65535 & t);
    return i.gXRMN(i.ASQcV(65535 & i.krIDk(i.OGiIK(i.nSUEx(r, 16) + (n >>> 16), e >>> 16), t >>> 16) + (o >>> 16), 16), 65535 & o)
}, N = function(r, n, e, t, i) {
    var o = function(r, n) {
        return r >>> n
    }
      , u = function(r, n) {
        return r & n
    }
      , s = function(r, n) {
        return r & n
    }(65535, r) + (65535 & n) + (65535 & e) + (65535 & t) + (65535 & i);
    return (65535 & (r >>> 16) + o(n, 16) + (e >>> 16) + (t >>> 16) + (i >>> 16) + (s >>> 16)) << 16 | u(65535, s)
}, C = function(r) {
    var n, e;
    return n = g(r, 7),
    e = g(r, 18),
    n ^ e ^ x(r, 3)
}, R = function(r) {
    return {
        bmJdJ: function(r, n) {
            return r ^ n
        }
    }["bmJdJ"](g(r, 6) ^ g(r, 11), g(r, 25))
}, S = function(r) {
    return g(r, 17) ^ g(r, 19) ^ x(r, 10)
}, E = function(r) {
    var n = {
        GKKRB: function(r, n) {
            return r ^ n
        },
        mEaKH: function(r, n) {
            return r ^ n
        },
        Vkxnt: function(r, n, e) {
            return r(n, e)
        }
    };
    return n.GKKRB(n.mEaKH(n.Vkxnt(g, r, 2), n.Vkxnt(g, r, 13)), g(r, 22))
}, _ = function(r, n, e) {
    return function(r, n) {
        return r ^ n
    }(function(r, n) {
        return r & n
    }(r, n), r & e) ^ n & e
},  m = function(r, n, e) {
    return r & n ^ ~r & e
}, x = function(r, n) {
    return r >>> n
}
f = [new d((c = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298])[0],3609767458), new d(c[1],602891725), new d(c[2],3964484399), new d(c[3],2173295548), new d(c[4],4081628472), new d(c[5],3053834265), new d(c[6],2937671579), new d(c[7],3664609560), new d(c[8],2734883394), new d(c[9],1164996542), new d(c[10],1323610764), new d(c[11],3590304994), new d(c[12],4068182383), new d(c[13],991336113), new d(c[14],633803317), new d(c[15],3479774868), new d(c[16],2666613458), new d(c[17],944711139), new d(c[18],2341262773), new d(c[19],2007800933), new d(c[20],1495990901), new d(c[21],1856431235), new d(c[22],3175218132), new d(c[23],2198950837), new d(c[24],3999719339), new d(c[25],766784016), new d(c[26],2566594879), new d(c[27],3203337956), new d(c[28],1034457026), new d(c[29],2466948901), new d(c[30],3758326383), new d(c[31],168717936), new d(c[32],1188179964), new d(c[33],1546045734), new d(c[34],1522805485), new d(c[35],2643833823), new d(c[36],2343527390), new d(c[37],1014477480), new d(c[38],1206759142), new d(c[39],344077627), new d(c[40],1290863460), new d(c[41],3158454273), new d(c[42],3505952657), new d(c[43],106217008), new d(c[44],3606008344), new d(c[45],1432725776), new d(c[46],1467031594), new d(c[47],851169720), new d(c[48],3100823752), new d(c[49],1363258195), new d(c[50],3750685593), new d(c[51],3785050280), new d(c[52],3318307427), new d(c[53],3812723403), new d(c[54],2003034995), new d(c[55],3602036899), new d(c[56],1575990012), new d(c[57],1125592928), new d(c[58],2716904306), new d(c[59],442776044), new d(c[60],593698344), new d(c[61],3733110249), new d(c[62],2999351573), new d(c[63],3815920427), new d(3391569614,3928383900), new d(3515267271,566280711), new d(3940187606,3454069534), new d(4118630271,4000239992), new d(116418474,1914138554), new d(174292421,2731055270), new d(289380356,3203993006), new d(460393269,320620315), new d(685471733,587496836), new d(852142971,1086792851), new d(1017036298,365543100), new d(1126000580,2618297676), new d(1288033470,3409855158), new d(1501505948,4234509866), new d(1607167915,987167468), new d(1816402316,1246189591)];
var X = function(r, n, e) {
    var t, i, o, u, s, a, h, l, w, v, p, g, O, x, y, b, Z, B, M, X, F, H, Y, W, K, q, J, Q = function(r, n) {
        return r + n
    }, z = function(r, n, e, t) {
        return r(n, e, t)
    }, $ = function(r, n, e) {
        return r(n, e)
    }, rr = function(r, n, e) {
        return r(n, e)
    }, nr = [];
    if (function(r, n) {
        return r === n
    }(224, e) || 256 === e)
        p = 64,
        O = 1,
        Y = Number,
        x = A,
        y = j,
        b = N,
        Z = C,
        B = S,
        M = E,
        X = R,
        H = _,
        F = m,
        J = c;
    else {
        if (384 !== e && 512 !== e)
            throw new Error("ush");
        p = 80,
        O = 2,
        Y = d,
        x = U,
        y = V,
        b = G,
        Z = T,
        B = L,
        M = D,
        X = I,
        H = k,
        F = P,
        J = f
    }
    for (t = n[0],
    i = n[1],
    o = n[2],
    u = n[3],
    s = n[4],
    a = n[5],
    h = n[6],
    l = n[7],
    g = 0; g < p; g += 1)
        g < 16 ? (q = g * O,
        W = r.length <= q ? 0 : r[q],
        K = r.length <= Q(q, 1) ? 0 : r[q + 1],
        nr[g] = new Y(W,K)) : nr[g] = y(B(nr[g - 2]), nr[g - 7], Z(nr[g - 15]), nr[g - 16]),
        w = b(l, X(s), z(F, s, a, h), J[g], nr[g]),
        v = $(x, M(t), H(t, i, o)),
        l = h,
        h = a,
        a = s,
        s = x(u, w),
        u = o,
        o = i,
        i = t,
        t = x(w, v);
    return n[0] = x(t, n[0]),
    n[1] = $(x, i, n[1]),
    n[2] = x(o, n[2]),
    n[3] = x(u, n[3]),
    n[4] = x(s, n[4]),
    n[5] = x(a, n[5]),
    n[6] = x(h, n[6]),
    n[7] = rr(x, l, n[7]),
    n
}
var F = function (r, n, e) {
    var t, i, o, u, s, a, c = {
        qYOuo: function (r, n) {
            return r >>> n
        },
        yNpCr: function (r, n) {
            return r < n
        },
        GSshx: function (r, n) {
            return r > n
        },
        guLsE: function (r, n) {
            return r ^ n
        },
        BeAPN: function (r, n, e) {
            return r(n, e)
        },
        gsKKr: function (r, n) {
            return r + n
        },
        XfVGi: function (r, n, e, t, i) {
            return r(n, e, t, i)
        }
    }, f = 0, d = [], l = 0, p = r, g = !1, O = !1, x = [], y = [];
    if (i = v(),
        1 === p)
        u = 512,
            s = B,
            a = M,
            o = 160;
    else if (s = function (r, n) {
        return X(r, n, p)
    }
        ,
        a = function (r, n, e, t) {
            var i = {
                GGktb: function (r, n) {
                    return r <= n
                },
                SdoWy: function (r, n) {
                    return r + n
                }
            };
            return function (r, n, e, t, o) {
                for (var u = "0|4|3|1|2|5".split("|"), s = 0; ;) {
                    switch (u[s++]) {
                        case "0":
                            var a, c, f, d, l;
                            continue;
                        case "1":
                            for (r[n >>> 5] |= 128 << 24 - n % 32,
                                r[f] = n + e,
                                c = r.length,
                                a = 0; a < c; a += l)
                                t = X(r.slice(a, a + l), t, o);
                            continue;
                        case "2":
                            if (224 === o)
                                d = [t[0], t[1], t[2], t[3], t[4], t[5], t[6]];
                            else if (256 === o)
                                d = t;
                            else if (384 === o)
                                d = [t[0].highOrder, t[0].lowOrder, t[1].highOrder, t[1].lowOrder, t[2].highOrder, t[2].lowOrder, t[3].highOrder, t[3].lowOrder, t[4].highOrder, t[4].lowOrder, t[5].highOrder, t[5].lowOrder];
                            else {
                                if (512 !== o)
                                    throw new Error("ush");
                                d = [t[0].highOrder, t[0].lowOrder, t[1].highOrder, t[1].lowOrder, t[2].highOrder, t[2].lowOrder, t[3].highOrder, t[3].lowOrder, t[4].highOrder, t[4].lowOrder, t[5].highOrder, t[5].lowOrder, t[6].highOrder, t[6].lowOrder, t[7].highOrder, t[7].lowOrder]
                            }
                            continue;
                        case "3":
                            for (; i.GGktb(r.length, f);)
                                r.push(0);
                            continue;
                        case "4":
                            if (224 === o || 256 === o)
                                f = 15 + (i.SdoWy(n, 65) >>> 9 << 4),
                                    l = 16;
                            else {
                                if (384 !== o && 512 !== o)
                                    throw new Error("ush");
                                f = 31 + (n + 129 >>> 10 << 5),
                                    l = 32
                            }
                            continue;
                        case "5":
                            return d
                    }
                    break
                }
            }(r, n, e, t, p)
        }
        ,
        224 === p)
        u = 512,
            o = 224;
    else if (256 === p)
        u = 512,
            o = 256;
    else if (384 === p)
        u = 1024,
            o = 384;
    else {
        if (512 !== p)
            throw new Error;
        u = 1024,
            o = 512
    }
    return t = Z(p),
        function (r) {
            var n = v()(r)
                , e = n.binLen
                , i = n.value
                , o = c.qYOuo(u, 3)
                , h = o / 4 - 1;
            if (c.yNpCr(o, e / 8)) {
                for (i = a(i, e, 0, Z(p)); i.length <= h;)
                    i.push(0);
                i[h] &= 4294967040
            } else if (c.GSshx(o, e / 8)) {
                for (; i.length <= h;)
                    i.push(0);
                i[h] &= 4294967040
            }
            for (var d = 0; d <= h; d += 1)
                x[d] = c.guLsE(909522486, i[d]),
                    y[d] = 1549556828 ^ i[d];
            t = c.BeAPN(s, x, t),
                f = u,
                O = !0
        }(n),
        function () {
            var r, n, o, a, w, v = 0, p = u >>> 5;
            for (n = (r = i(e, d, l)).binLen,
                a = r.value,
                o = n >>> 5,
                w = 0; w < o; w += p)
                c.gsKKr(v, u) <= n && (t = s(a.slice(w, w + p), t),
                    v += u);
            f += v,
                d = a.slice(v >>> 5),
                l = n % u
        }(),
        function () {
            if (!1 === O)
                throw new Error("hkset");
            var r, n = w;
            return !1 === g && (r = c.XfVGi(a, d, l, f, t),
                t = s(y, Z(p)),
                t = a(r, o, u, t)),
                g = !0,
                n(t)
        }()
}

function get_f_data(a, b, c) {
    return F(a, b, c);
}

module.exports = { get_f_data };