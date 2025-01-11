import numpy as np
from OpenGL.GL import *
from OpenGL.GLUT import *
from OpenGL.GLU import *
from PIL import Image
import io
import base64

def get_canvas_data_url():
    # Get the current viewport size (width, height)
    width, height = glGetIntegerv(GL_VIEWPORT)[2], glGetIntegerv(GL_VIEWPORT)[3]
    
    # Read the pixel data from the framebuffer (this is similar to canvas.toDataURL)
    pixel_data = glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE)
    
    # Convert the pixel data to an image using PIL (Pillow)
    image = Image.frombytes("RGBA", (width, height), pixel_data)
    
    # Save the image to a bytes buffer (in PNG format)
    img_buffer = io.BytesIO()
    image.save(img_buffer, format="PNG")
    
    # Convert the image to base64
    img_data_url = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
    
    # Format it like a data URL
    data_url = f"data:image/png;base64,{img_data_url}"
    
    return data_url

def setup_webgl():
    # Initialize OpenGL context
    glutInit()
    glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGB | GLUT_DEPTH)
    glutCreateWindow(b'WebGL Simulation in Python')

    # Setup OpenGL environment
    glClearColor(0, 0, 0, 1)
    glEnable(GL_DEPTH_TEST)
    glDepthFunc(GL_LEQUAL)
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)

    # Vertex and fragment shaders
    vertex_shader = """
    attribute vec2 attrVertex;
    varying vec2 varyinTexCoordinate;
    uniform vec2 uniformOffset;
    void main(){
        varyinTexCoordinate = attrVertex + uniformOffset;
        gl_Position = vec4(attrVertex, 0, 1);
    }
    """
    
    fragment_shader = """
    precision mediump float;
    varying vec2 varyinTexCoordinate;
    void main() {
        gl_FragColor = vec4(varyinTexCoordinate, 0, 1);
    }
    """

    # Compile and link shaders
    vertex_shader_id = glCreateShader(GL_VERTEX_SHADER)
    glShaderSource(vertex_shader_id, vertex_shader)
    glCompileShader(vertex_shader_id)

    fragment_shader_id = glCreateShader(GL_FRAGMENT_SHADER)
    glShaderSource(fragment_shader_id, fragment_shader)
    glCompileShader(fragment_shader_id)

    program = glCreateProgram()
    glAttachShader(program, vertex_shader_id)
    glAttachShader(program, fragment_shader_id)
    glLinkProgram(program)
    glUseProgram(program)

    # Create buffer data
    vertices = np.array([[-0.2, -0.9], [0.4, -0.26], [0.0, 0.732134444]], dtype=np.float32)
    vertex_buffer = glGenBuffers(1)
    glBindBuffer(GL_ARRAY_BUFFER, vertex_buffer)
    glBufferData(GL_ARRAY_BUFFER, vertices.nbytes, vertices, GL_STATIC_DRAW)

    # Attribute and uniform locations
    attr_vertex = glGetAttribLocation(program, "attrVertex")
    uniform_offset = glGetUniformLocation(program, "uniformOffset")
    
    glEnableVertexAttribArray(attr_vertex)
    glVertexAttribPointer(attr_vertex, 2, GL_FLOAT, GL_FALSE, 0, None)

    glUniform2f(uniform_offset, 1.0, 1.0)
    glDrawArrays(GL_TRIANGLE_STRIP, 0, len(vertices))

    # Get the canvas data URL (simulating toDataURL)
    data_url = get_canvas_data_url()
    print(f"Canvas Data URL: {data_url}")

# Call the function
if __name__ == "__main__":
    setup_webgl()
