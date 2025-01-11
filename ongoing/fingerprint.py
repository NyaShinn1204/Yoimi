import random
from datetime import datetime, timezone

def map_values(func, arr):
    return [func(item) for item in arr]

def x64multiply(a, b):
    a0, a1 = a
    b0, b1 = b
    lo = (a0 * b0) & 0xFFFFFFFF
    hi = (a1 * b1) & 0xFFFFFFFF
    return lo, hi

def x64rotl(val, shift):
    lo, hi = val
    shift = shift % 64
    if shift == 32:
        return hi, lo
    elif shift > 32:
        shift = shift - 32
        lo = ((lo << shift) | (hi >> (32 - shift))) & 0xFFFFFFFF
        hi = (hi << shift) & 0xFFFFFFFF
    else:
        lo = ((lo << shift) | (hi >> (32 - shift))) & 0xFFFFFFFF
        hi = (hi << shift) & 0xFFFFFFFF
    return lo, hi

def x64xor(a, b):
    return (a[0] ^ b[0]) & 0xFFFFFFFF, (a[1] ^ b[1]) & 0xFFFFFFFF

def x64add(a, b):
    lo = (a[0] + b[0]) & 0xFFFFFFFF
    hi = (a[1] + b[1]) & 0xFFFFFFFF
    return lo, hi

def x64leftshift(a, shift):
    lo, hi = a
    lo = (lo << shift) & 0xFFFFFFFF
    hi = (hi << shift) & 0xFFFFFFFF
    return lo, hi

def x64fmix(val):
    lo, hi = val
    lo = (lo ^ (lo >> 33)) * 0xff51afd7ed558ccd
    lo = (lo ^ (lo >> 33)) * 0xc4ceb9fe1a85ec53
    lo = lo ^ (lo >> 33)
    hi = (hi ^ (hi >> 33)) * 0xff51afd7ed558ccd
    hi = (hi ^ (hi >> 33)) * 0xc4ceb9fe1a85ec53
    hi = hi ^ (hi >> 33)
    return lo & 0xFFFFFFFF, hi & 0xFFFFFFFF

def x64hash128(key, seed=0):
    key = key or ''
    seed = seed or 0
    remainder = len(key) % 16
    bytes = len(key) - remainder
    h1 = [0, seed]
    h2 = [0, seed]
    c1 = [0x87c37b91, 0x114253d5]
    c2 = [0x4cf5ad43, 0x2745937f]

    for i in range(0, bytes, 16):
        k1 = [
            (ord(key[i+4]) & 0xff) | ((ord(key[i+5]) & 0xff) << 8) | ((ord(key[i+6]) & 0xff) << 16) | ((ord(key[i+7]) & 0xff) << 24),
            (ord(key[i]) & 0xff) | ((ord(key[i+1]) & 0xff) << 8) | ((ord(key[i+2]) & 0xff) << 16) | ((ord(key[i+3]) & 0xff) << 24)
        ]
        k2 = [
            (ord(key[i+12]) & 0xff) | ((ord(key[i+13]) & 0xff) << 8) | ((ord(key[i+14]) & 0xff) << 16) | ((ord(key[i+15]) & 0xff) << 24),
            (ord(key[i+8]) & 0xff) | ((ord(key[i+9]) & 0xff) << 8) | ((ord(key[i+10]) & 0xff) << 16) | ((ord(key[i+11]) & 0xff) << 24)
        ]
        
        k1 = x64multiply(k1, c1)
        k1 = x64rotl(k1, 31)
        k1 = x64multiply(k1, c2)
        h1 = x64xor(h1, k1)
        h1 = x64rotl(h1, 27)
        h1 = x64add(h1, h2)
        h1 = x64add(x64multiply(h1, [0, 5]), [0, 0x52dce729])

        k2 = x64multiply(k2, c2)
        k2 = x64rotl(k2, 33)
        k2 = x64multiply(k2, c1)
        h2 = x64xor(h2, k2)
        h2 = x64rotl(h2, 31)
        h2 = x64add(h2, h1)
        h2 = x64add(x64multiply(h2, [0, 5]), [0, 0x38495ab5])

    k1 = [0, 0]
    k2 = [0, 0]

    for j in range(remainder):
        k2 = x64xor(k2, x64leftshift([0, ord(key[bytes+j])], (8 * (remainder - j - 1))))

    k2 = x64multiply(k2, c2)
    k2 = x64rotl(k2, 33)
    k2 = x64multiply(k2, c1)
    h2 = x64xor(h2, k2)

    h1 = x64xor(h1, [0, len(key)])
    h2 = x64xor(h2, [0, len(key)])
    h1 = x64add(h1, h2)
    h2 = x64add(h2, h1)

    h1 = x64fmix(h1)
    h2 = x64fmix(h2)
    h1 = x64add(h1, h2)
    h2 = x64add(h2, h1)

    return f"{h1[0]:08x}{h1[1]:08x}{h2[0]:08x}{h2[1]:08x}"

def process_fingerprint(components, options=None):
    if options is None:
        options = {}

    new_components = []

    for component in components:
        if component['value'] == options.get('NOT_AVAILABLE', 'not available'):
            new_components.append({'key': component['key'], 'value': 'unknown'})
        elif component['key'] == 'plugins':
            new_components.append({
                'key': 'plugins',
                'value': ','.join([
                    f"{p[0]}::{p[1]}::{','.join([mt if isinstance(mt, str) else '~'.join(mt) for mt in p[2]])}"
                    for p in component['value']
                ])
            })
        elif component['key'] in ['canvas', 'webgl'] and isinstance(component['value'], list):
            new_components.append({'key': component['key'], 'value': '~'.join(component['value'])})
        elif component['key'] in ['sessionStorage', 'localStorage', 'indexedDb', 'addBehavior', 'openDatabase']:
            if component['value']:
                new_components.append({'key': component['key'], 'value': 1})
        else:
            if component['value']:
                new_components.append({
                    'key': component['key'],
                    'value': ';'.join(component['value']) if isinstance(component['value'], list) else component['value']
                })
            else:
                new_components.append({'key': component['key'], 'value': component['value']})

    murmur = x64hash128('~~~'.join([str(component['value']) for component in new_components]), 31)

    return murmur, new_components

def get_detect_screen_orientation():
    t = [1920, 1080]
    if True:
        t.sort(reverse=True)
    return t

def get_screen_dimensions():
    avail_width = 1920
    avail_height = 1032
    
    if avail_width and avail_height:
        t = [avail_height, avail_width]
        if True:
            t.sort(reverse=True)
        return t
    
    return "not available"

def get_timezone_offset():
    now = datetime.now(timezone.utc).astimezone()
    timezone_offset = -now.utcoffset().total_seconds() / 60
    return str(int(timezone_offset))

def get_time_zone():
    from tzlocal import get_localzone_name
    return get_localzone_name
# Get Plugins for WEB:
#R = function() {
#    return "Microsoft Internet Explorer" === navigator.appName || !("Netscape" !== navigator.appName || !/Trident/.test(navigator.userAgent))
#}
#o = function() {
#    var e = [];
#    if (Object.getOwnPropertyDescriptor && Object.getOwnPropertyDescriptor(window, "ActiveXObject") || "ActiveXObject"in window) {
#        e = s(["AcroPDF.PDF", "Adodb.Stream", "AgControl.AgControl", "DevalVRXCtrl.DevalVRXCtrl.1", "MacromediaFlashPaper.MacromediaFlashPaper", "Msxml2.DOMDocument", "Msxml2.XMLHTTP", "PDF.PdfCtrl", "QuickTime.QuickTime", "QuickTimeCheckObject.QuickTimeCheck.1", "RealPlayer", "RealPlayer.RealPlayer(tm) ActiveX Control (32-bit)", "RealVideo.RealVideo(tm) ActiveX Control (32-bit)", "Scripting.Dictionary", "SWCtl.SWCtl", "Shell.UIHelper", "ShockwaveFlash.ShockwaveFlash", "Skype.Detection", "TDCCtl.TDCCtl", "WMPlayer.OCX", "rmocx.RealPlayer G2 Control", "rmocx.RealPlayer G2 Control.1"], function(e) {
#            try {
#                return new window.ActiveXObject(e),
#                e
#            } catch (e) {
#                return "error"
#            }
#        })
#    } else
#        e.push("not available");
#    return navigator.plugins && (e = e.concat(i())),
#    e
#}
#c = function(e, t) {
#    if (Array.prototype.forEach && e.forEach === Array.prototype.forEach)
#        e.forEach(t);
#    else if (e.length === +e.length)
#        for (var a = 0, n = e.length; a < n; a++)
#            t(e[a], a, e);
#    else
#        for (var r in e)
#            e.hasOwnProperty(r) && t(e[r], r, e)
#}
#u = function(e) {
#    for (var t = !1, a = 0, n = [/palemoon/i].length; a < n; a++) {
#        var r = [/palemoon/i][a];
#        if (navigator.userAgent.match(r)) {
#            t = !0;
#            break
#        }
#    }
#    return t
#}
#s = function(e, n) {
#    var r = [];
#    return null == e ? r : Array.prototype.map && e.map === Array.prototype.map ? e.map(n) : (c(e, function(e, t, a) {
#        r.push(n(e, t, a))
#    }),
#    r)
#}
#i = function(e) {
#    if (null == navigator.plugins)
#        return "not available";
#    for (var t = [], a = 0, n = navigator.plugins.length; a < n; a++)
#        navigator.plugins[a] && t.push(navigator.plugins[a]);
#    return u() && (t = t.sort(function(e, t) {
#        return e.name > t.name ? 1 : e.name < t.name ? -1 : 0
#    })),
#    s(t, function(e) {
#        var t = s(e, function(e) {
#            return [e.type, e.suffixes]
#        });
#        return [e.name, e.description, t]
#    })
#}
#excludeIE = !1
#EXCLUDED = "excluded"
#get_plugins_return = R() ? excludeIE ? EXCLUDED : o() : i()

def get_canvas_data():
    from PIL import Image, ImageDraw, ImageFont
    import io
    import base64
    
    results = []
    
    width, height = 2000, 200
    img = Image.new('RGBA', (width, height), (255, 255, 255, 0))
    draw = ImageDraw.Draw(img)
    
    draw.rectangle([0, 0, 10, 10], fill=(0, 0, 0, 255))
    draw.rectangle([2, 2, 8, 8], fill=(255, 255, 255, 255))
    results.append("canvas winding: no")

    draw.rectangle([125, 1, 187, 21], fill=(255, 102, 0))
    
    font = ImageFont.load_default()
    if not False:
        fake_font = "11pt no-real-font-123"
    else:
        fake_font = "11pt Arial"
    
    draw.text((2, 15), "Cwm fjordbank glyphs vext quiz, 😃", fill=(6, 9, 105), font=font)
    draw.text((4, 45), "Cwm fjordbank glyphs vext quiz, 😃", fill=(102, 204, 0, 51), font=font)

    draw.ellipse([0, 0, 100, 100], fill=(255, 0, 255, 255))
    draw.ellipse([50, 0, 150, 100], fill=(0, 255, 255, 255))
    draw.ellipse([25, 50, 125, 150], fill=(255, 255, 0, 255))
    
    draw.ellipse([0, 0, 150, 150], fill=(255, 0, 255, 255))
    draw.ellipse([50, 50, 100, 100], fill=(255, 255, 255, 0))

    with io.BytesIO() as output:
        img.save(output, format="PNG")
        data_url = "data:image/png;base64," + base64.b64encode(output.getvalue()).decode()
        results.append("canvas fp:" + data_url)
    
    return results

#components = [
#    {'key': 'plugins', 'value': [['plugin1', 'description1', ['mimeType1', 'mimeType2']], ['plugin2', 'description2', ['mimeType3']]]},
#    {'key': 'canvas', 'value': ['data1', 'data2']},
#    {'key': 'localStorage', 'value': True},
#    {'key': 'sessionStorage', 'value': None},
#]
components = [
    {"key": "webdriver", "value": False},
    {"key": "language", "value": "ja"},
    {"key": "colorDepth", "value": random.random(24, 32)},
    {"key": "deviceMemory", "value": random.random(0.25, 0.5, 1, 2, 4, 8)}, # 8
    {"key": "hardwareConcurrency", "value": random.randint(1, 8)}, # 5
    {"key": "screenResolution", "value": get_detect_screen_orientation()},
    {"key": "availableScreenResolution", "value": get_screen_dimensions()},
    {"key": "timezoneOffset", "value": get_timezone_offset()},
    {"key": "timezone", "value": get_time_zone()},
    {"key": "sessionStorage", "value": True}, # sessionStorageが存在していれば
    {"key": "localStorage", "value": True}, # localStorageが存在していれば
    {"key": "indexedDb", "value": True}, # indexedDBが存在していれば
    {"key": "addBehavior", "value": False}, #document.body と document.body.addBehavior の両方が存在するか
    {"key": "openDatabase", "value": False}, #openDatabaseが存在していれば
    {"key": "cpuClass", "value": "not available"}, # navigator.cpuClassがなければ
    {"key": "platform", "value": "Win32"}, # Win32, Win64, MacIntel, Linux armv71, iPhone, Android
    {"key": "plugins", "value": [["Web com.adobe.pdf Renderer","Portable Document Format",[["application/x-google-chrome-pdf","pdf"]]],["l5cWLFpU","RMOPm6laVKs9mb057dt9e2bVSRQv26GD",[["","FKN"]]],["Web Portable Document Format Display","",[["application/pdf","pdf"]]],["k9e2bVS","fy4cWLFh3EhvXTwBAAIr899Hi47lSwB",[["","w3b"]]]]}, # 元コードはline: 172から
    {"key": "canvas", "value": get_canvas_data()},
    {"key": "webgl", "value": False},
    {"key": "webdriver", "value": False},
    {"key": "webdriver", "value": False},
    {"key": "webdriver", "value": False},
    {"key": "webdriver", "value": False},
    {"key": "webdriver", "value": False},
    {"key": "webdriver", "value": False},
    {"key": "webdriver", "value": False},
    {"key": "webdriver", "value": False},
    {"key": "webdriver", "value": False},
]

options = {'NOT_AVAILABLE': 'not available'}

murmur, new_components = process_fingerprint(components, options)
print("Fingerprint:", murmur)
print("Processed Components:", new_components)
