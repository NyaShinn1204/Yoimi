from OpenGL.GL import *
from OpenGL.GLUT import *
from OpenGL.GLU import *
import numpy as np

# Initialize global variables
shaderProgram = None
vertexBuffer = None
info = []

def create_shader(shader_type, source):
    shader = glCreateShader(shader_type)
    glShaderSource(shader, source)
    glCompileShader(shader)
    if not glGetShaderiv(shader, GL_COMPILE_STATUS):
        raise RuntimeError(glGetShaderInfoLog(shader))
    return shader

def get_webgl_info():
    global shaderProgram, vertexBuffer, info

    def clear_and_format(range):
        glClearColor(0, 0, 0, 1)
        glEnable(GL_DEPTH_TEST)
        glDepthFunc(GL_LEQUAL)
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        return f"[{range[0]}, {range[1]}]"

    vertexBuffer = glGenBuffers(1)
    glBindBuffer(GL_ARRAY_BUFFER, vertexBuffer)
    vertices = np.array([-.2, -.9, 0, .4, -.26, 0, 0, .732134444, 0], dtype=np.float32)
    glBufferData(GL_ARRAY_BUFFER, vertices, GL_STATIC_DRAW)

    # Check for OpenGL errors
    error = glGetError()
    if error != GL_NO_ERROR:
        print(f"OpenGL Error: {error}")

    vertex_shader_source = """
    attribute vec2 attrVertex;
    varying vec2 varyinTexCoordinate;
    uniform vec2 uniformOffset;
    void main() {
        varyinTexCoordinate = attrVertex + uniformOffset;
        gl_Position = vec4(attrVertex, 0, 1);
    }
    """
    fragment_shader_source = """
    precision mediump float;
    varying vec2 varyinTexCoordinate;
    void main() {
        gl_FragColor = vec4(varyinTexCoordinate, 0, 1);
    }
    """

    vertexShader = create_shader(GL_VERTEX_SHADER, vertex_shader_source)
    fragmentShader = create_shader(GL_FRAGMENT_SHADER, fragment_shader_source)

    shaderProgram = glCreateProgram()
    glAttachShader(shaderProgram, vertexShader)
    glAttachShader(shaderProgram, fragmentShader)
    glLinkProgram(shaderProgram)
    if not glGetProgramiv(shaderProgram, GL_LINK_STATUS):
        raise RuntimeError(glGetProgramInfoLog(shaderProgram))
    glUseProgram(shaderProgram)

    attrVertex = glGetAttribLocation(shaderProgram, "attrVertex")
    uniformOffset = glGetUniformLocation(shaderProgram, "uniformOffset")
    glEnableVertexAttribArray(attrVertex)
    glVertexAttribPointer(attrVertex, 3, GL_FLOAT, GL_FALSE, 0, None)
    glUniform2f(uniformOffset, 1, 1)
    glDrawArrays(GL_TRIANGLE_STRIP, 0, 3)

    def add_parameter_info(name, param):
        info.append(f"webgl {name.lower().replace('_', ' ')}: {param}")

    add_parameter_info("ALIASED_LINE_WIDTH_RANGE", clear_and_format(glGetFloatv(GL_ALIASED_LINE_WIDTH_RANGE)))
    add_parameter_info("ALIASED_POINT_SIZE_RANGE", clear_and_format(glGetFloatv(GL_ALIASED_POINT_SIZE_RANGE)))
    add_parameter_info("ALPHA_BITS", glGetIntegerv(GL_ALPHA_BITS))
    add_parameter_info("ANTIALIASING", "yes" if glGetBooleanv(GL_SAMPLE_BUFFERS) else "no")
    add_parameter_info("BLUE_BITS", glGetIntegerv(GL_BLUE_BITS))
    add_parameter_info("DEPTH_BITS", glGetIntegerv(GL_DEPTH_BITS))
    add_parameter_info("GREEN_BITS", glGetIntegerv(GL_GREEN_BITS))
    add_parameter_info("MAX_COMBINED_TEXTURE_IMAGE_UNITS", glGetIntegerv(GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS))
    add_parameter_info("MAX_CUBE_MAP_TEXTURE_SIZE", glGetIntegerv(GL_MAX_CUBE_MAP_TEXTURE_SIZE))
    add_parameter_info("MAX_FRAGMENT_UNIFORM_VECTORS", glGetIntegerv(GL_MAX_FRAGMENT_UNIFORM_VECTORS))
    add_parameter_info("MAX_RENDERBUFFER_SIZE", glGetIntegerv(GL_MAX_RENDERBUFFER_SIZE))
    add_parameter_info("MAX_TEXTURE_IMAGE_UNITS", glGetIntegerv(GL_MAX_TEXTURE_IMAGE_UNITS))
    add_parameter_info("MAX_TEXTURE_SIZE", glGetIntegerv(GL_MAX_TEXTURE_SIZE))
    add_parameter_info("MAX_VARYING_VECTORS", glGetIntegerv(GL_MAX_VARYING_VECTORS))
    add_parameter_info("MAX_VERTEX_ATTRIBS", glGetIntegerv(GL_MAX_VERTEX_ATTRIBS))
    add_parameter_info("MAX_VERTEX_TEXTURE_IMAGE_UNITS", glGetIntegerv(GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS))
    add_parameter_info("MAX_VERTEX_UNIFORM_VECTORS", glGetIntegerv(GL_MAX_VERTEX_UNIFORM_VECTORS))
    add_parameter_info("MAX_VIEWPORT_DIMS", clear_and_format(glGetIntegerv(GL_MAX_VIEWPORT_DIMS)))
    add_parameter_info("RED_BITS", glGetIntegerv(GL_RED_BITS))
    add_parameter_info("RENDERER", glGetString(GL_RENDERER).decode())
    add_parameter_info("SHADING_LANGUAGE_VERSION", glGetString(GL_SHADING_LANGUAGE_VERSION).decode())
    add_parameter_info("STENCIL_BITS", glGetIntegerv(GL_STENCIL_BITS))
    add_parameter_info("VENDOR", glGetString(GL_VENDOR).decode())
    add_parameter_info("VERSION", glGetString(GL_VERSION).decode())

    anisotropy_ext = glGetString(GL_EXTENSIONS)
    if anisotropy_ext and b"GL_EXT_texture_filter_anisotropic" in anisotropy_ext:
        anisotropy = glGetFloatv(0x84FF)
        add_parameter_info("MAX_ANISOTROPY", anisotropy)

    return info

def display():
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
    webgl_info = get_webgl_info()
    print(webgl_info)
    glutSwapBuffers()

def main():
    glutInit(sys.argv)
    glutInitDisplayMode(GLUT_RGB | GLUT_DOUBLE | GLUT_DEPTH)
    glutInitWindowSize(800, 600)
    glutCreateWindow(b"PyOpenGL WebGL Info")
    glutDisplayFunc(display)
    glutMainLoop()

if __name__ == "__main__":
    main()