from OpenGL.GL import *
def for_each_polyfill(arr, callback):
    if hasattr(arr, 'forEach') and arr.forEach == arr.forEach:
        arr.forEach(callback)
    elif isinstance(arr, (list, tuple)) and len(arr) == len(arr):  # Check if length is a number
        for i in range(len(arr)):
            callback(arr[i], i, arr)
    else:
        for key in arr:
            if key in arr:
                callback(arr[key], key, arr)

def get_webgl_info():  # Assuming PyOpenGL is installed
    from PIL import Image
    import numpy as np

    canvas = None  # Placeholder for canvas
    gl = glGenBuffers  # Placeholder for WebGL context

    if not gl:
        return None

    def clear_and_format(range):
        glClearColor(0, 0, 0, 1)
        glEnable(GL_DEPTH_TEST)
        glDepthFunc(GL_LEQUAL)
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        return f"[{range[0]}, {range[1]}]"

    info = []

    vertex_buffer = glGenBuffers(1)
    glBindBuffer(GL_ARRAY_BUFFER, vertex_buffer)
    vertices = np.array([-.2, -.9, 0, .4, -.26, 0, 0, .732134444, 0], dtype='float32')
    glBufferData(GL_ARRAY_BUFFER, vertices.nbytes, vertices, GL_STATIC_DRAW)
    vertex_buffer.itemSize = 3
    vertex_buffer.numItems = 3

    shader_program = glCreateProgram()
    vertex_shader = glCreateShader(GL_VERTEX_SHADER)
    glShaderSource(vertex_shader, "attribute vec2 attrVertex; varying vec2 varyinTexCoordinate; uniform vec2 uniformOffset; void main() { varyinTexCoordinate = attrVertex + uniformOffset; gl_Position = vec4(attrVertex, 0, 1); }")
    glCompileShader(vertex_shader)

    fragment_shader = glCreateShader(GL_FRAGMENT_SHADER)
    glShaderSource(fragment_shader, "precision mediump float; varying vec2 varyinTexCoordinate; void main() { gl_FragColor = vec4(varyinTexCoordinate, 0, 1); }")
    glCompileShader(fragment_shader)

    glAttachShader(shader_program, vertex_shader)
    glAttachShader(shader_program, fragment_shader)
    glLinkProgram(shader_program)
    glUseProgram(shader_program)

    shader_program.vertexPosAttrib = glGetAttribLocation(shader_program, "attrVertex")
    shader_program.offsetUniform = glGetUniformLocation(shader_program, "uniformOffset")

    glEnableVertexAttribArray(shader_program.vertexPosAttrib)
    glVertexAttribPointer(shader_program.vertexPosAttrib, vertex_buffer.itemSize, GL_FLOAT, False, 0, None)
    glUniform2f(shader_program.offsetUniform, 1, 1)
    glDrawArrays(GL_TRIANGLE_STRIP, 0, vertex_buffer.numItems)

    try:
        info.append(gl.canvas.toDataURL())
    except Exception:
        pass

    info.append(f"extensions:{';'.join(glGetSupportedExtensions())}")

    def get_anisotropy(gl_context):
        ext = glGetExtension("EXT_texture_filter_anisotropic") or glGetExtension("WEBKIT_EXT_texture_filter_anisotropic") or glGetExtension("MOZ_EXT_texture_filter_anisotropic")
        if ext:
            anisotropy = glGetParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT)
            return 2 if anisotropy == 0 else anisotropy
        return None

    def add_parameter_info(name, param):
        info.append(f"webgl {name.lower().replace('_', ' ')}: {param(gl) if callable(param) else param}")

    add_parameter_info("ALIASED_LINE_WIDTH_RANGE", clear_and_format(glGetParameter(GL_ALIASED_LINE_WIDTH_RANGE)))
    add_parameter_info("ALIASED_POINT_SIZE_RANGE", clear_and_format(glGetParameter(GL_ALIASED_POINT_SIZE_RANGE)))
    add_parameter_info("ALPHA_BITS", glGetParameter(GL_ALPHA_BITS))
    add_parameter_info("ANTIALIASING", "yes" if glGetContextAttributes().antialias else "no")
    add_parameter_info("BLUE_BITS", glGetParameter(GL_BLUE_BITS))
    add_parameter_info("DEPTH_BITS", glGetParameter(GL_DEPTH_BITS))
    add_parameter_info("GREEN_BITS", glGetParameter(GL_GREEN_BITS))
    add_parameter_info("MAX_ANISOTROPY", get_anisotropy)
    add_parameter_info("MAX_COMBINED_TEXTURE_IMAGE_UNITS", glGetParameter(GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS))
    add_parameter_info("MAX_CUBE_MAP_TEXTURE_SIZE", glGetParameter(GL_MAX_CUBE_MAP_TEXTURE_SIZE))
    add_parameter_info("MAX_FRAGMENT_UNIFORM_VECTORS", glGetParameter(GL_MAX_FRAGMENT_UNIFORM_VECTORS))
    add_parameter_info("MAX_RENDERBUFFER_SIZE", glGetParameter(GL_MAX_RENDERBUFFER_SIZE))
    add_parameter_info("MAX_TEXTURE_IMAGE_UNITS", glGetParameter(GL_MAX_TEXTURE_IMAGE_UNITS))
    add_parameter_info("MAX_TEXTURE_SIZE", glGetParameter(GL_MAX_TEXTURE_SIZE))
    add_parameter_info("MAX_VARYING_VECTORS", glGetParameter(GL_MAX_VARYING_VECTORS))
    add_parameter_info("MAX_VERTEX_ATTRIBS", glGetParameter(GL_MAX_VERTEX_ATTRIBS))
    add_parameter_info("MAX_VERTEX_TEXTURE_IMAGE_UNITS", glGetParameter(GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS))
    add_parameter_info("MAX_VERTEX_UNIFORM_VECTORS", glGetParameter(GL_MAX_VERTEX_UNIFORM_VECTORS))
    add_parameter_info("MAX_VIEWPORT_DIMS", clear_and_format(glGetParameter(GL_MAX_VIEWPORT_DIMS)))
    add_parameter_info("RED_BITS", glGetParameter(GL_RED_BITS))
    add_parameter_info("RENDERER", glGetParameter(GL_RENDERER))
    add_parameter_info("SHADING_LANGUAGE_VERSION", glGetParameter(GL_SHADING_LANGUAGE_VERSION))
    add_parameter_info("STENCIL_BITS", glGetParameter(GL_STENCIL_BITS))
    add_parameter_info("VENDOR", glGetParameter(GL_VENDOR))
    add_parameter_info("VERSION", glGetParameter(GL_VERSION))

    try:
        debug_info = glGetExtension("WEBGL_debug_renderer_info")
        if debug_info:
            add_parameter_info("UNMASKED_VENDOR_WEBGL", glGetParameter(debug_info.UNMASKED_VENDOR_WEBGL))
            add_parameter_info("UNMASKED_RENDERER_WEBGL", glGetParameter(debug_info.UNMASKED_RENDERER_WEBGL))
    except Exception as e:
        print("Error getting debug info:", e)

    if hasattr(gl, 'getShaderPrecisionFormat'):
        for_each_polyfill(["FLOAT", "INT"], lambda type: for_each_polyfill(["VERTEX", "FRAGMENT"], lambda shader_type: for_each_polyfill(["HIGH", "MEDIUM", "LOW"], lambda precision: for_each_polyfill(["precision", "rangeMin", "rangeMax"], lambda prop: info.append(f"webgl {shader_type.lower()} shader {precision.lower()} {type.lower()} {'precision' if prop == 'precision' else 'precision ' + prop}: {gl.getShaderPrecisionFormat(gl[shader_type + '_SHADER'], gl[precision + '_' + type])[prop]}")))))

    return info

get_webgl_info()