import sys
import numpy as np

from OpenGL.GL import *
from OpenGL.GLUT import *
from OpenGL.GLU import *

vertex_shader_source = """
attribute vec2 attrVertex;
varying vec2 varyinTexCoordinate;
uniform vec2 uniformOffset;

void main(){
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

def compile_shader(source, shader_type):
    shader = glCreateShader(shader_type)
    glShaderSource(shader, source)
    glCompileShader(shader)
    if not glGetShaderiv(shader, GL_COMPILE_STATUS):
        error = glGetShaderInfoLog(shader).decode()
        print(f"Shader compilation error: {error}")
        glDeleteShader(shader)
        return None
    return shader


def get_webgl_info():
    try:
        glutInit()
        glutInitDisplayMode(GLUT_SINGLE | GLUT_RGB)
        glutInitWindowSize(256, 256) # キャンバスサイズと同じサイズに設定
        window = glutCreateWindow(b"PyOpenGL Example")

        # シェーダーのコンパイルとプログラムのリンク
        vertex_shader = compile_shader(vertex_shader_source, GL_VERTEX_SHADER)
        fragment_shader = compile_shader(fragment_shader_source, GL_FRAGMENT_SHADER)
        if not vertex_shader or not fragment_shader:
            return None

        shader_program = glCreateProgram()
        glAttachShader(shader_program, vertex_shader)
        glAttachShader(shader_program, fragment_shader)
        glLinkProgram(shader_program)
        glUseProgram(shader_program)


        # ... (他の初期化処理)

        # uniformOffsetの設定
        offset_location = glGetUniformLocation(shader_program, "uniformOffset")
        glUniform2f(offset_location, 1.0, 1.0)


        # 頂点データ
        vertices = np.array([-.2, -.9, 0, .4, -.26, 0, 0, .732134444, 0], dtype=np.float32)

        vbo = glGenBuffers(1)
        glBindBuffer(GL_ARRAY_BUFFER, vbo)
        glBufferData(GL_ARRAY_BUFFER, vertices.nbytes, vertices, GL_STATIC_DRAW)

        vertex_location = glGetAttribLocation(shader_program, "attrVertex")
        glEnableVertexAttribArray(vertex_location)
        glVertexAttribPointer(vertex_location, 2, GL_FLOAT, GL_FALSE, 0, None) # 2要素ずつ


        glClearColor(0.0, 0.0, 0.0, 1.0)  # 背景色を黒に設定
        glClear(GL_COLOR_BUFFER_BIT)

        glViewport(0, 0, 256, 256) # ビューポートの設定


        glDrawArrays(GL_TRIANGLES, 0, 3) # GL_TRIANGLE_STRIP から GL_TRIANGLES に変更
        glFlush()


        # ... (情報取得処理)

        glutDestroyWindow(window)
        return info

    except Exception as e:
        print(f"Error initializing OpenGL context: {e}")
        return None


if __name__ == "__main__":
    info = get_webgl_info()
    if info:
        for item in info:
            print(item)
    else:
        print("OpenGL information not available.")
    glutMainLoop() # glutMainLoop() を追加