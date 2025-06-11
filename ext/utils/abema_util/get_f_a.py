
class D:
    def __init__(self, high_order, low_order):
        self.highOrder = high_order
        self.lowOrder = low_order

def l(r, n=None, e=0):
    f = n or [0]
    o = e >> 3
    for i in range(len(r)):
        t = ord(r[i])
        s = i + o
        u = s >> 2
        if len(f) <= u:
            f.append(0)
        f[u] |= t << 8 * (3 - s % 4)
    a = 8
    c = len(r)
    return {"value": f, "binLen": a * c + e}

def g(r, n):
    return (r >> n) | (r << (32 - n))

def v():
    return l

def w(r):
    t = ""
    i = 4 * len(r)
    for n in range(i):
        e = (r[n >> 2] >> 8 * (3 - n % 4)) & 255
        t += chr(e)
    return t

def Z(r):
    if r == 1:
        n = [1732584193, 4023233417, 2562383102, 271733878, 3285377520]
    else:
        e = [3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428]
        t = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]
        if r == 224:
            n = e
        elif r == 256:
            n = t
        elif r == 384:
            n = [D(3418070365,e[0]), D(1654270250,e[1]), D(2438529370,e[2]), D(355462360,e[3]), D(1731405415,e[4]), D(41048885895,e[5]), D(3675008525,e[6]), D(1203062813,e[7])]
        elif r == 512:
            n = [D(t[0],4089235720), D(t[1],2227873595), D(t[2],4271175723), D(t[3],1595750129), D(t[4],2917565137), D(t[5],725511199), D(t[6],4215389547), D(t[7],327033209)]
        else:
            raise ValueError("variant")
    return n

def A(r, n):
    t = (65535 & r) + (65535 & n)
    return ((65535 & ((r >> 16) + (n >> 16) + (t >> 16))) << 16) | (65535 & t)

def j(r, n, e, t):
    o = (65535 & r) + (65535 & n) + (65535 & e) + (65535 & t)
    return ((65535 & ((r >> 16) + (n >> 16) + (e >> 16) + (t >> 16) + (o >> 16))) << 16) | (65535 & o)

def N(r, n, e, t, i):
    s = (65535 & r) + (65535 & n) + (65535 & e) + (65535 & t) + (65535 & i)
    return ((65535 & ((r >> 16) + (n >> 16) + (e >> 16) + (t >> 16) + (i >> 16) + (s >> 16))) << 16) | (65535 & s)

def C(r):
    n = g(r, 7)
    e = g(r, 18)
    return n ^ e ^ x(r, 3)

def R(r):
    return (g(r, 6) ^ g(r, 11)) ^ g(r, 25)

def S(r):
    return g(r, 17) ^ g(r, 19) ^ x(r, 10)

def E(r):
    return (g(r, 2) ^ g(r, 13)) ^ g(r, 22)

def _(r, n, e):
    return (r & n) ^ (r & e) ^ (n & e)

def m(r, n, e):
    return (r & n) ^ (~r & e)

def x(r, n):
    return r >> n

f = [
    D(1116352408,3609767458), D(1899447441,602891725), D(3049323471,3964484399), D(3921009573,2173295548), D(961987163,4081628472), D(1508970993,3053834265), D(2453635748,2937671579), D(2870763221,3664609560),
    D(3624381080,2734883394), D(310598401,1164996542), D(607225278,1323610764), D(1426881987,3590304994), D(1925078388,4068182383), D(2162078206,991336113), D(2614888103,633803317), D(3248222580,3479774868),
    D(3835390401,2666613458), D(4022224774,944711139), D(264347078,2341262773), D(604807628,2007800933), D(770255983,1495990901), D(1249150122,1856431235), D(1555081692,3175218132), D(1996064986,2198950837),
    D(2554220882,3999719339), D(2821834349,766784016), D(2952996808,2566594879), D(3210313671,3203337956), D(3336571891,1034457026), D(3584528711,2466948901), D(113926993,3758326383), D(338241895,168717936),
    D(666307205,1188179964), D(773529912,1546045734), D(1294757372,1522805485), D(1396182291,2643833823), D(1695183700,2343527390), D(1986661051,1014477480), D(2177026350,1206759142), D(2456956037,344077627),
    D(2730485921,1290863460), D(2820302411,3158454273), D(3259730800,3505952657), D(3345764771,106217008), D(3516065817,3606008344), D(3600352804,1432725776), D(4094571909,1467031594), D(275423344,851169720),
    D(430227734,3100823752), D(506948616,1363258195), D(659060556,3750685593), D(883997877,3785050280), D(958139571,3318307427), D(1322822218,3812723403), D(1537002063,2003034995), D(1747873779,3602036899),
    D(1955562222,1575990012), D(2024104815,1125592928), D(2227730452,2716904306), D(2361852424,442776044), D(2428436474,593698344), D(2756734187,3733110249), D(3204031479,2999351573), D(3329325298,3815920427),
    D(3391569614,3928383900), D(3515267271,566280711), D(3940187606,3454069534), D(4118630271,4000239992), D(116418474,1914138554), D(174292421,2731055270), D(289380356,3203993006), D(460393269,320620315),
    D(685471733,587496836), D(852142971,1086792851), D(1017036298,365543100), D(1126000580,2618297676), D(1288033470,3409855158), D(1501505948,4234509866), D(1607167915,987167468), D(1816402316,1246189591)
]

c = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298]


def X(r, n, e):
    if e == 224 or e == 256:
        p = 64
        O = 1
        Y = int
        x_func = A
        y_func = j
        b_func = N
        Z_func = C
        B_func = S
        M_func = E
        X_func = R
        H_func = _
        F_func = m
        J = c  # Use the global 'c' list here
    else:
        if e != 384 and e != 512:
            raise ValueError("ush")
        p = 80
        O = 2
        Y = D
        x_func = U
        y_func = V
        b_func = G
        Z_func = T
        B_func = L
        M_func = D_func
        X_func = I
        H_func = k
        F_func = P
        J = f  # Use the global 'f' list here

    t = n[0]
    i = n[1]
    o = n[2]
    u = n[3]
    s = n[4]
    a = n[5]
    h = n[6]
    l = n[7]
    nr = []

    for g_val in range(p):
        if g_val < 16:
            q = g_val * O
            W = r[q] if len(r) > q else 0
            K = r[q + 1] if len(r) > q + 1 else 0
            # The error happens here.  W and K might be D objects, so you can't directly convert them to integers
            # If e is 384 or 512, W and K are already integers.  If e is 224 or 256, we expect r to contain integers.
            if isinstance(W, D):
                W = W.highOrder  # Or W.lowOrder, depending on the desired value
            if isinstance(K, D):
                K = K.highOrder # Or K.lowOrder, depending on the desired value

            nr.append(Y(W, K))
        else:
            nr.append(y_func(B_func(nr[g_val - 2]), nr[g_val - 7], Z_func(nr[g_val - 15]), nr[g_val - 16]))

        w = b_func(l, X_func(s), F_func(s, a, h), J[g_val], nr[g_val])
        v = x_func(M_func(t), H_func(t, i, o))

        l = h
        h = a
        a = s
        s = x_func(u, w)
        u = o
        o = i
        i = t
        t = x_func(w, v)

    n[0] = x_func(t, n[0])
    n[1] = x_func(i, n[1])
    n[2] = x_func(o, n[2])
    n[3] = x_func(u, n[3])
    n[4] = x_func(s, n[4])
    n[5] = x_func(a, n[5])
    n[6] = x_func(h, n[6])
    n[7] = x_func(l, n[7])

    return n

def U(r, n):  # Example U function, implement the correct one
    # This is a placeholder, replace it with the actual U implementation
    return D(r.highOrder + n.highOrder, r.lowOrder + n.lowOrder)
def V(r, n, e, t):  # Example V function, implement the correct one
    # This is a placeholder, replace it with the actual V implementation
    return D(r.highOrder + n.highOrder + e.highOrder + t.highOrder, r.lowOrder + n.lowOrder + e.lowOrder + t.lowOrder)
def G(r, n, e, t, i):  # Example G function, implement the correct one
    # This is a placeholder, replace it with the actual G implementation
    return D(r.highOrder + n.highOrder + e.highOrder + t.highOrder + i.highOrder, r.lowOrder + n.lowOrder + e.lowOrder + t.lowOrder + i.lowOrder)
def T(r):  # Example T function, implement the correct one
    # This is a placeholder, replace it with the actual T implementation
    return D(C(r.highOrder), C(r.lowOrder))
def L(r):  # Example L function, implement the correct one
    # This is a placeholder, replace it with the actual L implementation
    return D(S(r.highOrder), S(r.lowOrder))
def D_func(r):  # Example D function, implement the correct one
    # This is a placeholder, replace it with the actual D implementation
    return D(E(r.highOrder), E(r.lowOrder))
def I(r):  # Example I function, implement the correct one
    # This is a placeholder, replace it with the actual I implementation
    return D(R(r.highOrder), R(r.lowOrder))
def k(r, n, e):  # Example k function, implement the correct one
    # This is a placeholder, replace it with the actual k implementation
    return D(_(r.highOrder, n.highOrder, e.highOrder), _(r.lowOrder, n.lowOrder, e.lowOrder))
def P(r, n, e):  # Example P function, implement the correct one
    # This is a placeholder, replace it with the actual P implementation
    return D(m(r.highOrder, n.highOrder, e.highOrder), m(r.lowOrder, n.lowOrder, e.lowOrder))

def F(p, n, e):
    if p == 1:
        u = 512
        s = lambda r, n: X(r, n, p) #  B
        a = lambda r, n, e, t: X(r, n, p) # M
        o = 160
        J = c  # Added J here, since it's used in the lambda function 'a'
    else:
        s = lambda r, n: X(r, n, p)
        a = lambda r, n, e, t: calculate_intermediate_hash(r, n, e, t, p) # M
        J = f # Added J here

        if p == 224:
            u = 512
            o = 224
        elif p == 256:
            u = 512
            o = 256
        elif p == 384:
            u = 1024
            o = 384
        elif p == 512:
            u = 1024
            o = 512
        else:
            raise ValueError

    t = Z(p)

    def process_input(r):
        nonlocal t, u
        nonlocal p
        i_obj = v()(r)
        e_val = i_obj["binLen"]
        i_arr = i_obj["value"]
        o_val = u >> 3
        h = o_val / 4 - 1

        if o_val < e_val / 8:
            for _ in range(int(h - len(i_arr)) + 1): # Fix: iterate the correct number of times
                i_arr.append(0)
            i_arr[int(h)] &= 4294967040
        elif o_val > e_val / 8:
            for _ in range(int(h - len(i_arr)) + 1): # Fix: iterate the correct number of times
                i_arr.append(0)
            i_arr[int(h)] &= 4294967040

        x = []
        y = []
        for d in range(int(h) + 1): # Fix: use int(h) to prevent float issues
            x.append(909522486 ^ i_arr[d])
            y.append(1549556828 ^ i_arr[d])

        t = s(x, t)
        f_global[0] = u
        O_global[0] = True

    def finalize():
        nonlocal t, u, f_global, d_global, l_global, g_global, O_global
        nonlocal p, o

        if not O_global[0]:
            raise ValueError("hkset")

        r = None
        n_func = w

        if not g_global[0]:
            r = a(d_global, l_global, f_global[0], t)
            t = s(y_global, Z(p))
            t = a(r, o, u, t)

        g_global[0] = True
        return n_func(t)

    e_global = [e]
    d_global = []
    l_global = 0
    f_global = [0]
    g_global = [False]
    O_global = [False]
    x_global = []
    y_global = []


    def update_hash(e_val, d_val, l_val):
        nonlocal t, u
        v_val = 0
        p_val = u >> 5
        n_val = l(e_val, d_val, l_val)["binLen"]
        a_val = l(e_val, d_val, l_val)["value"]
        o_val = n_val >> 5

        for w_val in range(0, o_val, p_val):
            if v_val + u <= n_val:
                t = s(a_val[w_val:w_val + p_val], t)
                v_val += u

        f_global[0] += v_val
        d_global[:] = a_val[v_val >> 5:]
        l_global = n_val % u

    def calculate_intermediate_hash(d_val, l_val, f_val, t_val, p_val):
        # This function replicates the logic within the 'a' function in the original JS code.
        i_val = l(e_global[0], d_val, l_val)["binLen"]
        n_val = e_global[0]
        t_val = t_val
        o_val = p_val

        d = []
        if o_val == 224:
            d = [t_val[0], t_val[1], t_val[2], t_val[3], t_val[4], t_val[5], t_val[6]]
        elif o_val == 256:
            d = t_val
        elif o_val == 384:
            d = [t_val[0].highOrder, t_val[0].lowOrder, t_val[1].highOrder, t_val[1].lowOrder, t_val[2].highOrder, t_val[2].lowOrder, t_val[3].highOrder, t_val[3].lowOrder, t_val[4].highOrder, t_val[4].lowOrder, t_val[5].highOrder, t_val[5].lowOrder]
        elif o_val == 512:
           d = [t_val[0].highOrder, t_val[0].lowOrder, t_val[1].highOrder, t_val[1].lowOrder, t_val[2].highOrder, t_val[2].lowOrder, t_val[3].highOrder, t_val[3].lowOrder, t_val[4].highOrder, t_val[4].lowOrder, t_val[5].highOrder, t_val[5].lowOrder, t_val[6].highOrder, t_val[6].lowOrder, t_val[7].highOrder, t_val[7].lowOrder]
        else:
            raise ValueError("Invalid value for o_val")

        return d

    process_input(n)
    update_hash(e_global[0], d_global, l_global)
    result = finalize()
    return result

def get_f_data(a, b, c):
    return F(a, b, c)