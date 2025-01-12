from OpenGL.GL import *
from OpenGL.GLUT import *
from OpenGL.GLU import *
import sys
import numpy as np
from PIL import Image
import base64
import io

GL_MAX_TEXTURE_MAX_ANISOTROPY_EXT = 0x84FF  # Known value for this constant

def get_webgl_info():
    try:
        glutInit(sys.argv)
        glutInitDisplayMode(GLUT_RGBA | GLUT_DOUBLE | GLUT_DEPTH)
        width = 256
        height = 256
        glutInitWindowSize(width, height)
        glutCreateWindow(b"PyOpenGL Test")

        info_list = []

        glClearColor(0, 0, 0, 1)
        glEnable(GL_DEPTH_TEST)
        glDepthFunc(GL_LEQUAL)
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)

        glDisable(GL_FRAMEBUFFER_SRGB)

        def format_parameter(param):
          return f"[{param[0]}, {param[1]}]"

        # Create a buffer
        # 例: バッファデータのセット前後にログを追加
        print("Creating buffer...")
        buffer = glGenBuffers(1)
        glBindBuffer(GL_ARRAY_BUFFER, buffer)
        print(f"Buffer created: ID={buffer}")
        
        print("Uploading vertex data to buffer...")
        a = (-0.2, -0.9, 0.0, 0.4, -0.26, 0.0, 0.0, 0.732134444, 0)
        float_array = (GLfloat * len(a))(*a)
        print(f"Vertex data: {list(float_array)}")
        glBufferData(GL_ARRAY_BUFFER, float_array, GL_STATIC_DRAW)
        print("Vertex data uploaded.")

        item_size = 3
        num_items = 3

        # Create and compile shaders
        vertex_shader = glCreateShader(GL_VERTEX_SHADER)
        glShaderSource(vertex_shader, ["#version 120\n",
                                      "attribute vec2 attrVertex;\n",
                                      "varying vec2 varyinTexCoordinate;\n",
                                      "uniform vec2 uniformOffset;\n",
                                      "void main() {\n",
                                      "    varyinTexCoordinate = attrVertex + uniformOffset;\n",
                                      "    gl_Position = vec4(attrVertex, 0.0, 1.0);\n",
                                      "}"
                                    ])
        print("Compiling vertex shader...")
        glCompileShader(vertex_shader)
        vertex_shader_log = glGetShaderInfoLog(vertex_shader)
        print(f"Vertex Shader Compilation Log: {vertex_shader_log.decode() if vertex_shader_log else 'No errors'}")

        fragment_shader = glCreateShader(GL_FRAGMENT_SHADER)
        glShaderSource(fragment_shader, ["#version 120\n",
                                        "precision mediump float;\n",
                                        "varying vec2 varyinTexCoordinate;\n",
                                        "void main() {\n",
                                        "  gl_FragColor = vec4(varyinTexCoordinate, 0.0, 1.0);\n",
                                        "}"
                                        ])

        print("Compiling fragment shader...")
        glCompileShader(fragment_shader)
        fragment_shader_log = glGetShaderInfoLog(fragment_shader)
        print(f"Fragment Shader Compilation Log: {fragment_shader_log.decode() if fragment_shader_log else 'No errors'}")

        # Create and link program
        program = glCreateProgram()
        glAttachShader(program, vertex_shader)
        glAttachShader(program, fragment_shader)
        print("Linking shader program...")
        glLinkProgram(program)
        program_log = glGetProgramInfoLog(program)
        print(f"Shader Program Link Log: {program_log.decode() if program_log else 'No errors'}")
        glUseProgram(program)

        # Get attribute and uniform locations
        vertex_pos_attrib = glGetAttribLocation(program, "attrVertex")
        offset_uniform = glGetUniformLocation(program, "uniformOffset")

        glEnableVertexAttribArray(vertex_pos_attrib)
        glVertexAttribPointer(vertex_pos_attrib, item_size, GL_FLOAT, GL_FALSE, 0, None)
        glUniform2f(offset_uniform, 1, 1) # ここを戻す

        glDrawArrays(GL_TRIANGLES, 0, num_items)

        # Get WebGL Info

        # ---  canvas.toDataURL() の代替処理 ---
        pixels = glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE)
        pixels_array = np.frombuffer(pixels, dtype=np.uint8).reshape((height, width, 4))
        #pixels_array = np.power(pixels_array/255.0, 2.2) * 255.0 # ガンマ補正をかける場合
        #pixels_array = pixels_array.astype(np.uint8) # ガンマ補正をかける場合
        image = Image.frombuffer("RGBA", (width, height), pixels_array, "raw", "RGBA", 0, 1)
        image = image.transpose(Image.FLIP_TOP_BOTTOM)  # OpenGLは上下反転した画像を生成するので修正
        buffered = io.BytesIO()
        image.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        info_list.append(f"data:image/png;base64,{img_str}")
        # ---  canvas.toDataURL() の代替処理 ここまで ---

        num_extensions = glGetIntegerv(GL_NUM_EXTENSIONS)
        print("Fetching WebGL information...")
        extensions = [glGetStringi(GL_EXTENSIONS, i).decode() for i in range(num_extensions)]
        
        aliased_line_width_range = glGetFloatv(GL_ALIASED_LINE_WIDTH_RANGE)
        print(f"WebGL aliased line width range: {aliased_line_width_range}")
        info_list.append("extensions:" + ";".join(extensions))
        info_list.append("webgl aliased line width range:" + format_parameter(glGetFloatv(GL_ALIASED_LINE_WIDTH_RANGE)))
        info_list.append("webgl aliased point size range:" + format_parameter(glGetFloatv(GL_ALIASED_POINT_SIZE_RANGE)))
        info_list.append("webgl alpha bits:" + str(glGetIntegerv(GL_ALPHA_BITS)))
        # コンテキスト属性の取得はPyOpenGLでは直接できないので、スキップ
        #info_list.append("webgl antialiasing:" + ("yes" if getContextAttributes().antialias else "no"))
        info_list.append("webgl blue bits:" + str(glGetIntegerv(GL_BLUE_BITS)))
        info_list.append("webgl depth bits:" + str(glGetIntegerv(GL_DEPTH_BITS)))
        info_list.append("webgl green bits:" + str(glGetIntegerv(GL_GREEN_BITS)))
        info_list.append("webgl max anisotropy:" + str(get_max_anisotropy()))
        info_list.append("webgl max combined texture image units:" + str(glGetIntegerv(GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS)))
        info_list.append("webgl max cube map texture size:" + str(glGetIntegerv(GL_MAX_CUBE_MAP_TEXTURE_SIZE)))
        info_list.append("webgl max fragment uniform vectors:" + str(glGetIntegerv(GL_MAX_FRAGMENT_UNIFORM_COMPONENTS) // 4))
        info_list.append("webgl max render buffer size:" + str(glGetIntegerv(GL_MAX_RENDERBUFFER_SIZE)))
        info_list.append("webgl max texture image units:" + str(glGetIntegerv(GL_MAX_TEXTURE_IMAGE_UNITS)))
        info_list.append("webgl max texture size:" + str(glGetIntegerv(GL_MAX_TEXTURE_SIZE)))
        info_list.append("webgl max varying vectors:" + str(glGetIntegerv(GL_MAX_VARYING_FLOATS) // 4))
        info_list.append("webgl max vertex attribs:" + str(glGetIntegerv(GL_MAX_VERTEX_ATTRIBS)))
        info_list.append("webgl max vertex texture image units:" + str(glGetIntegerv(GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS)))
        info_list.append("webgl max vertex uniform vectors:" + str(glGetIntegerv(GL_MAX_VERTEX_UNIFORM_COMPONENTS) // 4))
        info_list.append("webgl max viewport dims:" + format_parameter(glGetIntegerv(GL_MAX_VIEWPORT_DIMS)))
        info_list.append("webgl red bits:" + str(glGetIntegerv(GL_RED_BITS)))
        info_list.append("webgl renderer:" + glGetString(GL_RENDERER).decode())
        info_list.append("webgl shading language version:" + glGetString(GL_SHADING_LANGUAGE_VERSION).decode())
        info_list.append("webgl stencil bits:" + str(glGetIntegerv(GL_STENCIL_BITS)))
        info_list.append("webgl vendor:" + glGetString(GL_VENDOR).decode())
        info_list.append("webgl version:" + glGetString(GL_VERSION).decode())

        try:
            # デバッグ拡張はPyOpenGLでは直接対応するものがありません
            debug_renderer_info = glGetString(GL_EXTENSIONS).split()
            if b"WEBGL_debug_renderer_info" in debug_renderer_info:
                UNMASKED_VENDOR_WEBGL = 0x9245
                UNMASKED_RENDERER_WEBGL = 0x9246
                vendor = glGetString(UNMASKED_VENDOR_WEBGL)
                renderer = glGetString(UNMASKED_RENDERER_WEBGL)
                results.append(f"webgl unmasked vendor: {vendor.decode()}")
                results.append(f"webgl unmasked renderer: {renderer.decode()}")
        except Exception:
            pass

        # Precision formatはPyOpenGLでは直接取得できないため、スキップ

        return info_list

    except Exception as e:
        return f"not available: {e}"
    finally:
      glutLeaveMainLoop()


def get_max_anisotropy():
    anisotropy_ext = glGetFloatv(GL_MAX_TEXTURE_MAX_ANISOTROPY_EXT)
    if anisotropy_ext == 0:
        anisotropy_ext = 2
    return anisotropy_ext

def run_opengl_test():
    info = get_webgl_info()
    if isinstance(info, str):
      print(info)
    else:
      for i in info:
        print(i)

if __name__ == "__main__":
  run_opengl_test()