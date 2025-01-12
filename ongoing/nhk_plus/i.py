import pythonmonkey as pm

pm.eval("""
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
  }
}

function getWebGLContext() {
  const canvas = document.createElement("canvas");
  try {
    return canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
  } catch (e) {
    return null;
  }
}

function hasCanvas2D() {
  const canvas = document.createElement("canvas");
  return !!canvas.getContext && !!canvas.getContext("2d");
}

function hasWebGL() {
  if (!hasCanvas2D()) {
    return false;
  }
  const gl = getWebGLContext();
  return !!window.WebGLRenderingContext && !!gl;
}

function getWebGLInfo() {
  const gl = getWebGLContext();
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
  gl.shaderSource(vertexShader, "attribute vec2 attrVertex;varying vec2 varyinTexCoordinate;uniform vec2 uniformOffset;void main(){varyinTexCoordinate=attrVertex+uniformOffset;gl_Position=vec4(attrVertex,0,1);}");
  gl.compileShader(vertexShader);

  const fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);
  gl.shaderSource(fragmentShader, "precision mediump float;varying vec2 varyinTexCoordinate;void main() {gl_FragColor=vec4(varyinTexCoordinate,0,1);}");
  gl.compileShader(fragmentShader);

  gl.attachShader(shaderProgram, vertexShader);
  gl.attachShader(shaderProgram, fragmentShader);
  gl.linkProgram(shaderProgram);
  gl.useProgram(shaderProgram);

  shaderProgram.vertexPosAttrib = gl.getAttribLocation(shaderProgram, "attrVertex");
  shaderProgram.offsetUniform = gl.getUniformLocation(shaderProgram, "uniformOffset");

  gl.enableVertexAttribArray(shaderProgram.vertexPosArray);
  gl.vertexAttribPointer(shaderProgram.vertexPosAttrib, vertexBuffer.itemSize, gl.FLOAT, false, 0, 0);
  gl.uniform2f(shaderProgram.offsetUniform, 1, 1);
  gl.drawArrays(gl.TRIANGLE_STRIP, 0, vertexBuffer.numItems);

  try {
    info.push(gl.canvas.toDataURL());
  } catch (e) {}

  info.push(`extensions:${(gl.getSupportedExtensions() || []).join(";")}`);

  const getAnisotropy = (glContext) => {
    const ext = glContext.getExtension("EXT_texture_filter_anisotropic") ||
                 glContext.getExtension("WEBKIT_EXT_texture_filter_anisotropic") ||
                 glContext.getExtension("MOZ_EXT_texture_filter_anisotropic");
    if (ext) {
      let anisotropy = glContext.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT);
      return anisotropy === 0 ? 2 : anisotropy;
    }
    return null;
  };


  const addParameterInfo = (name, param) => info.push(`webgl ${name.toLowerCase().replace(/_/g, ' ')}: ${typeof param === 'function' ? param(gl) : param}`);

  addParameterInfo("ALIASED_LINE_WIDTH_RANGE", clearAndFormat(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)));
  addParameterInfo("ALIASED_POINT_SIZE_RANGE", clearAndFormat(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)));
  addParameterInfo("ALPHA_BITS", gl.getParameter(gl.ALPHA_BITS));
  addParameterInfo("ANTIALIASING", gl.getContextAttributes().antialias ? "yes" : "no");
  addParameterInfo("BLUE_BITS", gl.getParameter(gl.BLUE_BITS));
  addParameterInfo("DEPTH_BITS", gl.getParameter(gl.DEPTH_BITS));
  addParameterInfo("GREEN_BITS", gl.getParameter(gl.GREEN_BITS));
  addParameterInfo("MAX_ANISOTROPY", getAnisotropy);
  addParameterInfo("MAX_COMBINED_TEXTURE_IMAGE_UNITS", gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS));
  addParameterInfo("MAX_CUBE_MAP_TEXTURE_SIZE", gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE));
  addParameterInfo("MAX_FRAGMENT_UNIFORM_VECTORS", gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS));
  addParameterInfo("MAX_RENDERBUFFER_SIZE", gl.getParameter(gl.MAX_RENDERBUFFER_SIZE));
  addParameterInfo("MAX_TEXTURE_IMAGE_UNITS", gl.getParameter(gl.MAX_TEXTURE_IMAGE_UNITS));
  addParameterInfo("MAX_TEXTURE_SIZE", gl.getParameter(gl.MAX_TEXTURE_SIZE));
  addParameterInfo("MAX_VARYING_VECTORS", gl.getParameter(gl.MAX_VARYING_VECTORS));
  addParameterInfo("MAX_VERTEX_ATTRIBS", gl.getParameter(gl.MAX_VERTEX_ATTRIBS));
  addParameterInfo("MAX_VERTEX_TEXTURE_IMAGE_UNITS", gl.getParameter(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS));
  addParameterInfo("MAX_VERTEX_UNIFORM_VECTORS", gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS));
  addParameterInfo("MAX_VIEWPORT_DIMS", clearAndFormat(gl.getParameter(gl.MAX_VIEWPORT_DIMS)));
  addParameterInfo("RED_BITS", gl.getParameter(gl.RED_BITS));
  addParameterInfo("RENDERER", gl.getParameter(gl.RENDERER));
  addParameterInfo("SHADING_LANGUAGE_VERSION", gl.getParameter(gl.SHADING_LANGUAGE_VERSION));
  addParameterInfo("STENCIL_BITS", gl.getParameter(gl.STENCIL_BITS));
  addParameterInfo("VENDOR", gl.getParameter(gl.VENDOR));
  addParameterInfo("VERSION", gl.getParameter(gl.VERSION));


  try {
    const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
    if (debugInfo) {
      addParameterInfo("UNMASKED_VENDOR_WEBGL", gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL));
      addParameterInfo("UNMASKED_RENDERER_WEBGL", gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
    }
  } catch (e) {
    console.error("Error getting debug info:", e);
  }

  if (gl.getShaderPrecisionFormat) {
    forEachPolyfill(["FLOAT", "INT"], (type) => {
      forEachPolyfill(["VERTEX", "FRAGMENT"], (shaderType) => {
        forEachPolyfill(["HIGH", "MEDIUM", "LOW"], (precision) => {
          forEachPolyfill(["precision", "rangeMin", "rangeMax"], (prop) => {
            const value = gl.getShaderPrecisionFormat(gl[shaderType + "_SHADER"], gl[precision + "_" + type])[prop];
            const propName = prop === "precision" ? "precision" : `precision ${prop}`;
            info.push(`webgl ${shaderType.toLowerCase()} shader ${precision.toLowerCase()} ${type.toLowerCase()} ${propName}: ${value}`);
          });
        });
      });
    });
  }

  return info;
}

hasWebGL() ? getWebGLInfo() : "not available";
""")