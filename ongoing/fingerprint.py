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
                #print(component['value'])
                new_components.append({
                    'key': component['key'],
                    'value': ';'.join(str(v) for v in component['value']) if isinstance(component['value'], list) else component['value']
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
    value = get_localzone_name()
    return value
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

def get_canvas_data(): # 多分これ壊れてる。
#    from PIL import Image, ImageDraw, ImageFont
#    import io
#    import base64
#    
#    results = []
#    
#    width, height = 2000, 200
#    img = Image.new('RGBA', (width, height), (255, 255, 255, 0))
#    draw = ImageDraw.Draw(img)
#    
#    draw.rectangle([0, 0, 10, 10], fill=(0, 0, 0, 255))
#    draw.rectangle([2, 2, 8, 8], fill=(255, 255, 255, 255))
#    results.append("canvas winding: no")
#
#    draw.rectangle([125, 1, 187, 21], fill=(255, 102, 0))
#    
#    font = ImageFont.load_default()
#    if not False:
#        fake_font = "11pt no-real-font-123"
#    else:
#        fake_font = "11pt Arial"
#    
#    draw.text((2, 15), "Cwm fjordbank glyphs vext quiz, 😃", fill=(6, 9, 105), font=font)
#    draw.text((4, 45), "Cwm fjordbank glyphs vext quiz, 😃", fill=(102, 204, 0, 51), font=font)
#
#    draw.ellipse([0, 0, 100, 100], fill=(255, 0, 255, 255))
#    draw.ellipse([50, 0, 150, 100], fill=(0, 255, 255, 255))
#    draw.ellipse([25, 50, 125, 150], fill=(255, 255, 0, 255))
#    
#    draw.ellipse([0, 0, 150, 150], fill=(255, 0, 255, 255))
#    draw.ellipse([50, 50, 100, 100], fill=(255, 255, 255, 0))
#
#    with io.BytesIO() as output:
#        img.save(output, format="PNG")
#        data_url = "data:image/png;base64," + base64.b64encode(output.getvalue()).decode()
#        results.append("canvas fp:" + data_url)
#    
#    return results
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    
    # Chromiumのオプション設定
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # ヘッドレスモード（GUIなし）
    
    # WebDriverのセットアップ（Chromiumを指定）
    #service = Service()  # chromedriverのパスを指定
    driver = webdriver.Chrome(options=chrome_options)
    
    try:
        # Webページを開く
        driver.get("https://example.com")
    
        # JavaScriptコードを実行する
        script = """
y = function (e) {
  var t = []
    , a = document.createElement("canvas");
  a.width = 2e3,
    a.height = 200,
    a.style.display = "inline";
  var n = a.getContext("2d");
  return n.rect(0, 0, 10, 10),
    n.rect(2, 2, 6, 6),
    t.push("canvas winding:" + (!1 === n.isPointInPath(5, 5, "evenodd") ? "yes" : "no")),
    n.textBaseline = "alphabetic",
    n.fillStyle = "#f60",
    n.fillRect(125, 1, 62, 20),
    n.fillStyle = "#069",
    null ? n.font = "11pt Arial" : n.font = "11pt no-real-font-123",
    n.fillText("Cwm fjordbank glyphs vext quiz, \ud83d\ude03", 2, 15),
    n.fillStyle = "rgba(102, 204, 0, 0.2)",
    n.font = "18pt Arial",
    n.fillText("Cwm fjordbank glyphs vext quiz, \ud83d\ude03", 4, 45),
    n.globalCompositeOperation = "multiply",
    n.fillStyle = "rgb(255,0,255)",
    n.beginPath(),
    n.arc(50, 50, 50, 0, 2 * Math.PI, !0),
    n.closePath(),
    n.fill(),
    n.fillStyle = "rgb(0,255,255)",
    n.beginPath(),
    n.arc(100, 50, 50, 0, 2 * Math.PI, !0),
    n.closePath(),
    n.fill(),
    n.fillStyle = "rgb(255,255,0)",
    n.beginPath(),
    n.arc(75, 100, 50, 0, 2 * Math.PI, !0),
    n.closePath(),
    n.fill(),
    n.fillStyle = "rgb(255,0,255)",
    n.arc(75, 75, 75, 0, 2 * Math.PI, !0),
    n.arc(75, 75, 25, 0, 2 * Math.PI, !0),
    n.fill("evenodd"),
    a.toDataURL && t.push("canvas fp:" + a.toDataURL()),
    t
}
return y()
        """
        result = driver.execute_script(script)
    
        return result
    
    finally:
        # ブラウザを閉じる
        driver.quit()
def get_webgl_data():
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    
    # Chromiumのオプション設定
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # ヘッドレスモード（GUIなし）
    
    # WebDriverのセットアップ（Chromiumを指定）
    #service = Service()  # chromedriverのパスを指定
    driver = webdriver.Chrome(options=chrome_options)
    
    try:
        # Webページを開く
        driver.get("https://example.com")
    
        # JavaScriptコードを実行する
        script = """
function forEachPolyfill(arr, callback) {
  if (Array.prototype.forEach && arr.forEach === Array.prototype.forEach) {
    arr.forEach(callback);
  } else if (arr.length === +arr.length) { // Check if length is a number
    for (let i = 0, len = arr.length; i < len; i++) {
      callback(arr[i], i, arr);
    }
  } else {
    for (const key in arr) {
      if (arr.hasOwnProperty(key)) {
        callback(arr[key], key, arr);
      }
    }
  };
};
function getWebGLInfo() {
  const canvas = document.createElement('canvas');
  const gl = canvas.getContext('webgl');
  if (!gl) {
    return null;
  }

  const clearAndFormat = (range) => {
    gl.clearColor(0, 0, 0, 1);
    gl.enable(gl.DEPTH_TEST);
    gl.depthFunc(gl.LEQUAL);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
    return `[${range[0]}, ${range[1]}]`;
  };

  const info = [];

  const vertexBuffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, vertexBuffer);
  const vertices = new Float32Array([-.2, -.9, 0, .4, -.26, 0, 0, .732134444, 0]);
  gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
  vertexBuffer.itemSize = 3;
  vertexBuffer.numItems = 3;

  const shaderProgram = gl.createProgram();
  const vertexShader = gl.createShader(gl.VERTEX_SHADER);
  gl.shaderSource(vertexShader, 'attribute vec2 attrVertex;varying vec2 varyinTexCoordinate;uniform vec2 uniformOffset;void main(){varyinTexCoordinate=attrVertex+uniformOffset;gl_Position=vec4(attrVertex,0,1);}');
  gl.compileShader(vertexShader);

  const fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);
  gl.shaderSource(fragmentShader, 'precision mediump float;varying vec2 varyinTexCoordinate;void main() {gl_FragColor=vec4(varyinTexCoordinate,0,1);}');
  gl.compileShader(fragmentShader);

  gl.attachShader(shaderProgram, vertexShader);
  gl.attachShader(shaderProgram, fragmentShader);
  gl.linkProgram(shaderProgram);
  gl.useProgram(shaderProgram);

  shaderProgram.vertexPosAttrib = gl.getAttribLocation(shaderProgram, 'attrVertex');
  shaderProgram.offsetUniform = gl.getUniformLocation(shaderProgram, 'uniformOffset');

  gl.enableVertexAttribArray(shaderProgram.vertexPosArray);
  gl.vertexAttribPointer(shaderProgram.vertexPosAttrib, vertexBuffer.itemSize, gl.FLOAT, false, 0, 0);
  gl.uniform2f(shaderProgram.offsetUniform, 1, 1);
  gl.drawArrays(gl.TRIANGLE_STRIP, 0, vertexBuffer.numItems);

  try {
    info.push(gl.canvas.toDataURL());
  } catch (e) {}

  info.push(`extensions:${(gl.getSupportedExtensions() || []).join(';')}`);

  const getAnisotropy = (glContext) => {
    const ext = glContext.getExtension('EXT_texture_filter_anisotropic') ||
                 glContext.getExtension('WEBKIT_EXT_texture_filter_anisotropic') ||
                 glContext.getExtension('MOZ_EXT_texture_filter_anisotropic');
    if (ext) {
      let anisotropy = glContext.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT);
      return anisotropy === 0 ? 2 : anisotropy;
    }
    return null;
  };


  const addParameterInfo = (name, param) => info.push(`webgl ${name.toLowerCase().replace(/_/g, ' ')}: ${typeof param === 'function' ? param(gl) : param}`);

  addParameterInfo('ALIASED_LINE_WIDTH_RANGE', clearAndFormat(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)));
  addParameterInfo('ALIASED_POINT_SIZE_RANGE', clearAndFormat(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)));
  addParameterInfo('ALPHA_BITS', gl.getParameter(gl.ALPHA_BITS));
  addParameterInfo('ANTIALIASING', gl.getContextAttributes().antialias ? 'yes' : 'no');
  addParameterInfo('BLUE_BITS', gl.getParameter(gl.BLUE_BITS));
  addParameterInfo('DEPTH_BITS', gl.getParameter(gl.DEPTH_BITS));
  addParameterInfo('GREEN_BITS', gl.getParameter(gl.GREEN_BITS));
  addParameterInfo('MAX_ANISOTROPY', getAnisotropy);
  addParameterInfo('MAX_COMBINED_TEXTURE_IMAGE_UNITS', gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS));
  addParameterInfo('MAX_CUBE_MAP_TEXTURE_SIZE', gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE));
  addParameterInfo('MAX_FRAGMENT_UNIFORM_VECTORS', gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS));
  addParameterInfo('MAX_RENDERBUFFER_SIZE', gl.getParameter(gl.MAX_RENDERBUFFER_SIZE));
  addParameterInfo('MAX_TEXTURE_IMAGE_UNITS', gl.getParameter(gl.MAX_TEXTURE_IMAGE_UNITS));
  addParameterInfo('MAX_TEXTURE_SIZE', gl.getParameter(gl.MAX_TEXTURE_SIZE));
  addParameterInfo('MAX_VARYING_VECTORS', gl.getParameter(gl.MAX_VARYING_VECTORS));
  addParameterInfo('MAX_VERTEX_ATTRIBS', gl.getParameter(gl.MAX_VERTEX_ATTRIBS));
  addParameterInfo('MAX_VERTEX_TEXTURE_IMAGE_UNITS', gl.getParameter(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS));
  addParameterInfo('MAX_VERTEX_UNIFORM_VECTORS', gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS));
  addParameterInfo('MAX_VIEWPORT_DIMS', clearAndFormat(gl.getParameter(gl.MAX_VIEWPORT_DIMS)));
  addParameterInfo('RED_BITS', gl.getParameter(gl.RED_BITS));
  addParameterInfo('RENDERER', gl.getParameter(gl.RENDERER));
  addParameterInfo('SHADING_LANGUAGE_VERSION', gl.getParameter(gl.SHADING_LANGUAGE_VERSION));
  addParameterInfo('STENCIL_BITS', gl.getParameter(gl.STENCIL_BITS));
  addParameterInfo('VENDOR', gl.getParameter(gl.VENDOR));
  addParameterInfo('VERSION', gl.getParameter(gl.VERSION));


  try {
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (debugInfo) {
      addParameterInfo('UNMASKED_VENDOR_WEBGL', gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL));
      addParameterInfo('UNMASKED_RENDERER_WEBGL', gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
    }
  } catch (e) {
    console.error('Error getting debug info:', e);
  }

  if (gl.getShaderPrecisionFormat) {
    forEachPolyfill(['FLOAT', 'INT'], (type) => {
      forEachPolyfill(['VERTEX', 'FRAGMENT'], (shaderType) => {
        forEachPolyfill(['HIGH', 'MEDIUM', 'LOW'], (precision) => {
          forEachPolyfill(['precision', 'rangeMin', 'rangeMax'], (prop) => {
            const value = gl.getShaderPrecisionFormat(gl[shaderType + '_SHADER'], gl[precision + '_' + type])[prop];
            const propName = prop === 'precision' ? 'precision' : `precision ${prop}`;
            info.push(`webgl ${shaderType.toLowerCase()} shader ${precision.toLowerCase()} ${type.toLowerCase()} ${propName}: ${value}`);
          });
        });
      });
    });
  }

  return info;
}

return getWebGLInfo()
        """
        result = driver.execute_script(script)
    
        return result
    
    finally:
        # ブラウザを閉じる
        driver.quit()
def get_webinfo_data():
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    
    # Chromiumのオプション設定
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # ヘッドレスモード（GUIなし）
    
    # WebDriverのセットアップ（Chromiumを指定）
    #service = Service()  # chromedriverのパスを指定
    driver = webdriver.Chrome(options=chrome_options)
    
    try:
        # Webページを開く
        driver.get("https://example.com")
    
        # JavaScriptコードを実行する
        script = """
F = function () {
  var e = document.createElement("canvas")
    , t = null;
  try {
    t = e.getContext("webgl") || e.getContext("experimental-webgl")
  } catch (e) { }
  return t || (t = null),
    t
}
M = function () {
  try {
    var e = F()
      , t = e.getExtension("WEBGL_debug_renderer_info");
    return e.getParameter(t.UNMASKED_VENDOR_WEBGL) + "~" + e.getParameter(t.UNMASKED_RENDERER_WEBGL)
  } catch (e) {
    return null
  }
}
return M()
        """
        result = driver.execute_script(script)
    
        return result
    
    finally:
        # ブラウザを閉じる
        driver.quit()
def get_font_data():
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    
    # Chromiumのオプション設定
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # ヘッドレスモード（GUIなし）
    
    # WebDriverのセットアップ（Chromiumを指定）
    #service = Service()  # chromedriverのパスを指定
    driver = webdriver.Chrome(options=chrome_options)
    
    try:
        # Webページを開く
        driver.get("https://example.com")
    
        # JavaScriptコードを実行する
        script = """
var u = ["monospace", "sans-serif", "serif"]
  , d = ["Andale Mono", "Arial", "Arial Black", "Arial Hebrew", "Arial MT", "Arial Narrow", "Arial Rounded MT Bold", "Arial Unicode MS", "Bitstream Vera Sans Mono", "Book Antiqua", "Bookman Old Style", "Calibri", "Cambria", "Cambria Math", "Century", "Century Gothic", "Century Schoolbook", "Comic Sans", "Comic Sans MS", "Consolas", "Courier", "Courier New", "Geneva", "Georgia", "Helvetica", "Helvetica Neue", "Impact", "Lucida Bright", "Lucida Calligraphy", "Lucida Console", "Lucida Fax", "LUCIDA GRANDE", "Lucida Handwriting", "Lucida Sans", "Lucida Sans Typewriter", "Lucida Sans Unicode", "Microsoft Sans Serif", "Monaco", "Monotype Corsiva", "MS Gothic", "MS Outlook", "MS PGothic", "MS Reference Sans Serif", "MS Sans Serif", "MS Serif", "MYRIAD", "MYRIAD PRO", "Palatino", "Palatino Linotype", "Segoe Print", "Segoe Script", "Segoe UI", "Segoe UI Light", "Segoe UI Semibold", "Segoe UI Symbol", "Tahoma", "Times", "Times New Roman", "Times New Roman PS", "Trebuchet MS", "Verdana", "Wingdings", "Wingdings 2", "Wingdings 3"];
false && (d = d.concat(["Abadi MT Condensed Light", "Academy Engraved LET", "ADOBE CASLON PRO", "Adobe Garamond", "ADOBE GARAMOND PRO", "Agency FB", "Aharoni", "Albertus Extra Bold", "Albertus Medium", "Algerian", "Amazone BT", "American Typewriter", "American Typewriter Condensed", "AmerType Md BT", "Andalus", "Angsana New", "AngsanaUPC", "Antique Olive", "Aparajita", "Apple Chancery", "Apple Color Emoji", "Apple SD Gothic Neo", "Arabic Typesetting", "ARCHER", "ARNO PRO", "Arrus BT", "Aurora Cn BT", "AvantGarde Bk BT", "AvantGarde Md BT", "AVENIR", "Ayuthaya", "Bandy", "Bangla Sangam MN", "Bank Gothic", "BankGothic Md BT", "Baskerville", "Baskerville Old Face", "Batang", "BatangChe", "Bauer Bodoni", "Bauhaus 93", "Bazooka", "Bell MT", "Bembo", "Benguiat Bk BT", "Berlin Sans FB", "Berlin Sans FB Demi", "Bernard MT Condensed", "BernhardFashion BT", "BernhardMod BT", "Big Caslon", "BinnerD", "Blackadder ITC", "BlairMdITC TT", "Bodoni 72", "Bodoni 72 Oldstyle", "Bodoni 72 Smallcaps", "Bodoni MT", "Bodoni MT Black", "Bodoni MT Condensed", "Bodoni MT Poster Compressed", "Bookshelf Symbol 7", "Boulder", "Bradley Hand", "Bradley Hand ITC", "Bremen Bd BT", "Britannic Bold", "Broadway", "Browallia New", "BrowalliaUPC", "Brush Script MT", "Californian FB", "Calisto MT", "Calligrapher", "Candara", "CaslonOpnface BT", "Castellar", "Centaur", "Cezanne", "CG Omega", "CG Times", "Chalkboard", "Chalkboard SE", "Chalkduster", "Charlesworth", "Charter Bd BT", "Charter BT", "Chaucer", "ChelthmITC Bk BT", "Chiller", "Clarendon", "Clarendon Condensed", "CloisterBlack BT", "Cochin", "Colonna MT", "Constantia", "Cooper Black", "Copperplate", "Copperplate Gothic", "Copperplate Gothic Bold", "Copperplate Gothic Light", "CopperplGoth Bd BT", "Corbel", "Cordia New", "CordiaUPC", "Cornerstone", "Coronet", "Cuckoo", "Curlz MT", "DaunPenh", "Dauphin", "David", "DB LCD Temp", "DELICIOUS", "Denmark", "DFKai-SB", "Didot", "DilleniaUPC", "DIN", "DokChampa", "Dotum", "DotumChe", "Ebrima", "Edwardian Script ITC", "Elephant", "English 111 Vivace BT", "Engravers MT", "EngraversGothic BT", "Eras Bold ITC", "Eras Demi ITC", "Eras Light ITC", "Eras Medium ITC", "EucrosiaUPC", "Euphemia", "Euphemia UCAS", "EUROSTILE", "Exotc350 Bd BT", "FangSong", "Felix Titling", "Fixedsys", "FONTIN", "Footlight MT Light", "Forte", "FrankRuehl", "Fransiscan", "Freefrm721 Blk BT", "FreesiaUPC", "Freestyle Script", "French Script MT", "FrnkGothITC Bk BT", "Fruitger", "FRUTIGER", "Futura", "Futura Bk BT", "Futura Lt BT", "Futura Md BT", "Futura ZBlk BT", "FuturaBlack BT", "Gabriola", "Galliard BT", "Gautami", "Geeza Pro", "Geometr231 BT", "Geometr231 Hv BT", "Geometr231 Lt BT", "GeoSlab 703 Lt BT", "GeoSlab 703 XBd BT", "Gigi", "Gill Sans", "Gill Sans MT", "Gill Sans MT Condensed", "Gill Sans MT Ext Condensed Bold", "Gill Sans Ultra Bold", "Gill Sans Ultra Bold Condensed", "Gisha", "Gloucester MT Extra Condensed", "GOTHAM", "GOTHAM BOLD", "Goudy Old Style", "Goudy Stout", "GoudyHandtooled BT", "GoudyOLSt BT", "Gujarati Sangam MN", "Gulim", "GulimChe", "Gungsuh", "GungsuhChe", "Gurmukhi MN", "Haettenschweiler", "Harlow Solid Italic", "Harrington", "Heather", "Heiti SC", "Heiti TC", "HELV", "Herald", "High Tower Text", "Hiragino Kaku Gothic ProN", "Hiragino Mincho ProN", "Hoefler Text", "Humanst 521 Cn BT", "Humanst521 BT", "Humanst521 Lt BT", "Imprint MT Shadow", "Incised901 Bd BT", "Incised901 BT", "Incised901 Lt BT", "INCONSOLATA", "Informal Roman", "Informal011 BT", "INTERSTATE", "IrisUPC", "Iskoola Pota", "JasmineUPC", "Jazz LET", "Jenson", "Jester", "Jokerman", "Juice ITC", "Kabel Bk BT", "Kabel Ult BT", "Kailasa", "KaiTi", "Kalinga", "Kannada Sangam MN", "Kartika", "Kaufmann Bd BT", "Kaufmann BT", "Khmer UI", "KodchiangUPC", "Kokila", "Korinna BT", "Kristen ITC", "Krungthep", "Kunstler Script", "Lao UI", "Latha", "Leelawadee", "Letter Gothic", "Levenim MT", "LilyUPC", "Lithograph", "Lithograph Light", "Long Island", "Lydian BT", "Magneto", "Maiandra GD", "Malayalam Sangam MN", "Malgun Gothic", "Mangal", "Marigold", "Marion", "Marker Felt", "Market", "Marlett", "Matisse ITC", "Matura MT Script Capitals", "Meiryo", "Meiryo UI", "Microsoft Himalaya", "Microsoft JhengHei", "Microsoft New Tai Lue", "Microsoft PhagsPa", "Microsoft Tai Le", "Microsoft Uighur", "Microsoft YaHei", "Microsoft Yi Baiti", "MingLiU", "MingLiU_HKSCS", "MingLiU_HKSCS-ExtB", "MingLiU-ExtB", "Minion", "Minion Pro", "Miriam", "Miriam Fixed", "Mistral", "Modern", "Modern No. 20", "Mona Lisa Solid ITC TT", "Mongolian Baiti", "MONO", "MoolBoran", "Mrs Eaves", "MS LineDraw", "MS Mincho", "MS PMincho", "MS Reference Specialty", "MS UI Gothic", "MT Extra", "MUSEO", "MV Boli", "Nadeem", "Narkisim", "NEVIS", "News Gothic", "News GothicMT", "NewsGoth BT", "Niagara Engraved", "Niagara Solid", "Noteworthy", "NSimSun", "Nyala", "OCR A Extended", "Old Century", "Old English Text MT", "Onyx", "Onyx BT", "OPTIMA", "Oriya Sangam MN", "OSAKA", "OzHandicraft BT", "Palace Script MT", "Papyrus", "Parchment", "Party LET", "Pegasus", "Perpetua", "Perpetua Titling MT", "PetitaBold", "Pickwick", "Plantagenet Cherokee", "Playbill", "PMingLiU", "PMingLiU-ExtB", "Poor Richard", "Poster", "PosterBodoni BT", "PRINCETOWN LET", "Pristina", "PTBarnum BT", "Pythagoras", "Raavi", "Rage Italic", "Ravie", "Ribbon131 Bd BT", "Rockwell", "Rockwell Condensed", "Rockwell Extra Bold", "Rod", "Roman", "Sakkal Majalla", "Santa Fe LET", "Savoye LET", "Sceptre", "Script", "Script MT Bold", "SCRIPTINA", "Serifa", "Serifa BT", "Serifa Th BT", "ShelleyVolante BT", "Sherwood", "Shonar Bangla", "Showcard Gothic", "Shruti", "Signboard", "SILKSCREEN", "SimHei", "Simplified Arabic", "Simplified Arabic Fixed", "SimSun", "SimSun-ExtB", "Sinhala Sangam MN", "Sketch Rockwell", "Skia", "Small Fonts", "Snap ITC", "Snell Roundhand", "Socket", "Souvenir Lt BT", "Staccato222 BT", "Steamer", "Stencil", "Storybook", "Styllo", "Subway", "Swis721 BlkEx BT", "Swiss911 XCm BT", "Sylfaen", "Synchro LET", "System", "Tamil Sangam MN", "Technical", "Teletype", "Telugu Sangam MN", "Tempus Sans ITC", "Terminal", "Thonburi", "Traditional Arabic", "Trajan", "TRAJAN PRO", "Tristan", "Tubular", "Tunga", "Tw Cen MT", "Tw Cen MT Condensed", "Tw Cen MT Condensed Extra Bold", "TypoUpright BT", "Unicorn", "Univers", "Univers CE 55 Medium", "Univers Condensed", "Utsaah", "Vagabond", "Vani", "Vijaya", "Viner Hand ITC", "VisualUI", "Vivaldi", "Vladimir Script", "Vrinda", "Westminster", "WHITNEY", "Wide Latin", "ZapfEllipt BT", "ZapfHumnst BT", "ZapfHumnst Dm BT", "Zapfino", "Zurich BlkEx BT", "Zurich Ex BT", "ZWAdobeF"]));
d = (d = d.concat([])).filter(function(e, t) {
    return d.indexOf(e) === t
});
var a = document.getElementsByTagName("body")[0]
  , r = document.createElement("div")
  , g = document.createElement("div")
  , n = {}
  , i = {}
  , f = function() {
    var e = document.createElement("span");
    return e.style.position = "absolute",
    e.style.left = "-9999px",
    e.style.fontSize = "72px",
    e.style.fontStyle = "normal",
    e.style.fontWeight = "normal",
    e.style.letterSpacing = "normal",
    e.style.lineBreak = "auto",
    e.style.lineHeight = "normal",
    e.style.textTransform = "none",
    e.style.textAlign = "left",
    e.style.textDecoration = "none",
    e.style.textShadow = "none",
    e.style.whiteSpace = "normal",
    e.style.wordBreak = "normal",
    e.style.wordSpacing = "normal",
    e.innerHTML = "mmmmmmmmmmlli",
    e
}
  , o = function(e) {
    for (var t = !1, a = 0; a < u.length; a++)
        if (t = e[a].offsetWidth !== n[u[a]] || e[a].offsetHeight !== i[u[a]])
            return t;
    return t
}
  , l = function() {
    for (var e = [], t = 0, a = u.length; t < a; t++) {
        var n = f();
        n.style.fontFamily = u[t],
        r.appendChild(n),
        e.push(n)
    }
    return e
}();
a.appendChild(r);
for (var s = 0, c = u.length; s < c; s++)
    n[u[s]] = l[s].offsetWidth,
    i[u[s]] = l[s].offsetHeight;
var h = function() {
    for (var e, t, a, n = {}, r = 0, i = d.length; r < i; r++) {
        for (var o = [], l = 0, s = u.length; l < s; l++) {
            var c = (e = d[r],
            t = u[l],
            a = void 0,
            (a = f()).style.fontFamily = "'" + e + "'," + t,
            a);
            g.appendChild(c),
            o.push(c)
        }
        n[d[r]] = o
    }
    return n
}();
a.appendChild(g);
for (var m = [], T = 0, p = d.length; T < p; T++)
    o(h[d[T]]) && m.push(d[T]);
a.removeChild(g),
a.removeChild(r),
m
        """
        result = driver.execute_script(script)
    
        return result
    
    finally:
        # ブラウザを閉じる
        driver.quit()
#components = [
#    {'key': 'plugins', 'value': [['plugin1', 'description1', ['mimeType1', 'mimeType2']], ['plugin2', 'description2', ['mimeType3']]]},
#    {'key': 'canvas', 'value': ['data1', 'data2']},
#    {'key': 'localStorage', 'value': True},
#    {'key': 'sessionStorage', 'value': None},
#]
components = [
    {"key": "webdriver", "value": False},
    {"key": "language", "value": "ja"},
    {"key": "colorDepth", "value": str(random.choice([24, 32]))},
    {"key": "deviceMemory", "value": str(random.choice([0.25, 0.5, 1, 2, 4, 8]))}, # 8
    {"key": "hardwareConcurrency", "value": str(random.randint(1, 8))}, # 5
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
    {"key": "canvas", "value": get_canvas_data()}, # 壊れてる。
    {"key": "webgl", "value": get_webgl_data()}, # 壊れてる。
    {"key": "webglVendorAndRenderer", "value": get_webinfo_data()},
    {"key": "adBlock", "value": False}, # true or false
    {"key": "hasLiedLanguages", "value": False}, # ユーザーの優先言語(navigator.languages)とブラウザのデフォルト言語(navigator.language)の間に不一致があるかどうか
    {"key": "hasLiedResolution", "value": False}, # ほぼ同じ true or false
    {"key": "hasLiedOs", "value": False}, # ほぼ同じ true or false
    {"key": "hasLiedBrowser", "value": False},  # ほぼ同じ true or false 
    {"key": "touchSupport", "value": [0, False, False]}, # # ほぼ同じ 最初は0固定 次はTouchEventが作れたらTrue, 次はontouchstartがwindow内にあったらTrue
    {"key": "fonts", "value": get_font_data()},
    {"key": "audio", "value": None},
]

options = {'NOT_AVAILABLE': 'not available'}

murmur, new_components = process_fingerprint(components, options)
print("Fingerprint:", murmur)
print("Processed Components:", new_components)
