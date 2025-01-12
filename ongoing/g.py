import numpy as np
from OpenGL.GL import *
from OpenGL.GLUT import *
from OpenGL.GLUT.freeglut import *
from PIL import Image
import base64
from io import BytesIO

def init_gl():
    glClearColor(0.0, 0.0, 0.0, 1.0)
    glEnable(GL_DEPTH_TEST)
    glDepthFunc(GL_LEQUAL)

def create_shader(shader_type, source):
    shader = glCreateShader(shader_type)
    glShaderSource(shader, source)
    glCompileShader(shader)
    if not glGetShaderiv(shader, GL_COMPILE_STATUS):
        error = glGetShaderInfoLog(shader).decode()
        raise RuntimeError(f"Shader compilation error: {error}")
    return shader

def create_program(vertex_source, fragment_source):
    vertex_shader = create_shader(GL_VERTEX_SHADER, vertex_source)
    fragment_shader = create_shader(GL_FRAGMENT_SHADER, fragment_source)
    program = glCreateProgram()
    glAttachShader(program, vertex_shader)
    glAttachShader(program, fragment_shader)
    glLinkProgram(program)
    if not glGetProgramiv(program, GL_LINK_STATUS):
        error = glGetProgramInfoLog(program).decode()
        raise RuntimeError(f"Program link error: {error}")
    return program

def capture_framebuffer(width, height):
    """Capture the current framebuffer and return it as a base64 image."""
    glPixelStorei(GL_PACK_ALIGNMENT, 1)
    data = glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE)
    image = Image.frombytes("RGBA", (width, height), data)
    image = image.transpose(Image.FLIP_TOP_BOTTOM)  # OpenGLの座標系を修正
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    base64_image = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return base64_image

def display():
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)

    vertex_data = np.array([
        -0.2, -0.9, 0.0,
         0.4, -0.26, 0.0,
         0.0,  0.732134444, 0.0
    ], dtype=np.float32)

    vbo = glGenBuffers(1)
    glBindBuffer(GL_ARRAY_BUFFER, vbo)
    glBufferData(GL_ARRAY_BUFFER, vertex_data.nbytes, vertex_data, GL_STATIC_DRAW)

    vertex_shader_src = """
    attribute vec2 attrVertex;
    varying vec2 varyinTexCoordinate;
    uniform vec2 uniformOffset;
    void main() {
        varyinTexCoordinate = attrVertex + uniformOffset;
        gl_Position = vec4(attrVertex, 0, 1);
    }
    """
    fragment_shader_src = """
    precision mediump float;
    varying vec2 varyinTexCoordinate;
    void main() {
        gl_FragColor = vec4(varyinTexCoordinate, 0, 1);
    }
    """
    program = create_program(vertex_shader_src, fragment_shader_src)
    glUseProgram(program)

    attr_loc = glGetAttribLocation(program, "attrVertex")
    offset_loc = glGetUniformLocation(program, "uniformOffset")
    glEnableVertexAttribArray(attr_loc)
    glVertexAttribPointer(attr_loc, 3, GL_FLOAT, GL_FALSE, 0, None)

    glUniform2f(offset_loc, 1.0, 1.0)
    glDrawArrays(GL_TRIANGLE_STRIP, 0, 3)

    # フレームバッファをbase64エンコードして出力
    width, height = glutGet(GLUT_WINDOW_WIDTH), glutGet(GLUT_WINDOW_HEIGHT)
    base64_image = capture_framebuffer(width, height)
    print(f"data:image/png;base64,{base64_image}")

    glutSwapBuffers()

def main():
    glutInit()
    glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGBA)
    glutInitWindowSize(800, 600)
    glutCreateWindow(b"PyOpenGL Example")
    init_gl()
    glutDisplayFunc(display)
    glutMainLoop()

if __name__ == "__main__":
    main()
