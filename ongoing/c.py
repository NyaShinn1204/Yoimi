import io
import base64
import numpy as np
from PIL import Image
from OpenGL.GL import *
from OpenGL.GLUT import *
from OpenGL.GLU import *

# Function to check WebGL support
def is_glut_available():
    try:
        from OpenGL.GLUT import glutInit
        return True
    except ImportError:
        return False

# Check WebGL support
def is_webgl_supported():
    if not is_glut_available():
        print("GLUT is not available.")
        return False
    try:
        glutInit()  # Initialize GLUT
        glutCreateWindow(b"WebGL Test")
        glutHideWindow()
        print("GLUT initialized successfully.")
        return True
    except Exception as e:
        print(f"Error initializing GLUT: {e}")
        return False

def get_max_anisotropy():
    """Check for anisotropic filtering support and get the maximum value."""
    extension_name = b"GL_EXT_texture_filter_anisotropic"
    try:
        # Check if the extension is supported
        extensions = glGetString(GL_EXTENSIONS).split()
        if extension_name in extensions:
            # Dynamically get the anisotropy constant
            GL_MAX_TEXTURE_MAX_ANISOTROPY_EXT = 0x84FF  # Known value for this constant
            anisotropy_ext = glGetFloatv(GL_MAX_TEXTURE_MAX_ANISOTROPY_EXT)
            return anisotropy_ext
        else:
            return "Anisotropic filtering not supported"
    except Exception as e:
        return f"Error checking anisotropic filtering: {e}"

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

# Function to execute WebGL-like operations
def execute_webgl():
    results = []

    def format_range(param):
        return f"[{param[0]}, {param[1]}]"

    try:
        # Create buffer data
        buffer_data = np.array([-.2, -.9, 0, .4, -.26, 0, 0, .732134444, 0], dtype=np.float32)

        # Simulated WebGL calls (adapted for PyOpenGL)
        glClearColor(0, 0, 0, 1)
        glEnable(GL_DEPTH_TEST)
        glDepthFunc(GL_LEQUAL)
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        
        buffer = glGenBuffers(1)
        glBindBuffer(GL_ARRAY_BUFFER, buffer)
        glBufferData(GL_ARRAY_BUFFER, buffer_data, GL_STATIC_DRAW)

        results.append(get_canvas_data_url()) #実行するところが違う。これだと真っ黒になっちゃう

        # Simulate fetching extensions
        extensions = glGetString(GL_EXTENSIONS).decode()
        results.append(f"extensions: {extensions}")

        # Simulated WebGL parameters
        aliased_line_width_range = glGetFloatv(GL_ALIASED_LINE_WIDTH_RANGE)
        results.append(f"webgl aliased line width range: {format_range(aliased_line_width_range)}")

        aliased_point_size_range = glGetFloatv(GL_ALIASED_POINT_SIZE_RANGE)
        results.append(f"webgl aliased point size range: {format_range(aliased_point_size_range)}")

        results.append(f"webgl alpha bits: {glGetIntegerv(GL_ALPHA_BITS)}")
        results.append(f"webgl antialiasing: yes")
        results.append(f"webgl blue bits: {glGetIntegerv(GL_BLUE_BITS)}")
        results.append(f"webgl depth bits: {glGetIntegerv(GL_DEPTH_BITS)}")
        results.append(f"webgl green bits: {glGetIntegerv(GL_GREEN_BITS)}")

        # Example of fetching anisotropy extension
        anisotropy_ext = glGetString(GL_EXTENSIONS).find(b"EXT_texture_filter_anisotropic")
        if anisotropy_ext != -1:
            anisotropy_value = get_max_anisotropy()
            results.append(f"webgl max anisotropy: {anisotropy_value}")
        else:
            results.append("webgl max anisotropy: null")

        # Add other WebGL-like parameters
        results.append(f"webgl max texture size: {glGetIntegerv(GL_MAX_TEXTURE_SIZE)}")
        results.append(f"webgl max viewport dims: {format_range(glGetIntegerv(GL_MAX_VIEWPORT_DIMS))}")
        results.append(f"webgl red bits: {glGetIntegerv(GL_RED_BITS)}")
        results.append(f"webgl renderer: {glGetString(GL_RENDERER).decode()}")
        results.append(f"webgl shading language version: {glGetString(GL_SHADING_LANGUAGE_VERSION).decode()}")
        results.append(f"webgl stencil bits: {glGetIntegerv(GL_STENCIL_BITS)}")
        results.append(f"webgl vendor: {glGetString(GL_VENDOR).decode()}")
        results.append(f"webgl version: {glGetString(GL_VERSION).decode()}")

    except Exception as e:
        results.append(f"Error: {str(e)}")
    try:
        # Try to get the WEBGL_debug_renderer_info extension
        debug_renderer_info = glGetString(GL_EXTENSIONS).split()
        if b"WEBGL_debug_renderer_info" in debug_renderer_info:
            UNMASKED_VENDOR_WEBGL = 0x9245
            UNMASKED_RENDERER_WEBGL = 0x9246
            vendor = glGetString(UNMASKED_VENDOR_WEBGL)
            renderer = glGetString(UNMASKED_RENDERER_WEBGL)
            results.append(f"webgl unmasked vendor: {vendor.decode()}")
            results.append(f"webgl unmasked renderer: {renderer.decode()}")
    except Exception as e:
        pass  # Ignore errors for debug info collection

    # Shader precision formats
    def collect_shader_precision():
        """Helper to collect precision format details."""
        precisions = []
        try:
            shader_types = [GL_VERTEX_SHADER, GL_FRAGMENT_SHADER]
            precisions_levels = ["HIGH", "MEDIUM", "LOW"]
            value_types = ["precision", "rangeMin", "rangeMax"]

            for shader_type in shader_types:
                shader_name = "vertex" if shader_type == GL_VERTEX_SHADER else "fragment"
                for level in precisions_levels:
                    for value_type in value_types:
                        try:
                            precision_format = glGetShaderPrecisionFormat(shader_type, level)
                            value = precision_format[value_types.index(value_type)]
                            precisions.append(f"webgl {shader_name} shader {level.lower()} precision {value_type}: {value}")
                        except Exception as e:
                            pass
        except Exception as e:
            pass
        return precisions

    # Collect precision info and add to the list
    results.extend(collect_shader_precision())
    return results

if __name__ == "__main__":
    if is_webgl_supported():
        webgl_info = execute_webgl()
        for info in webgl_info:
            print(info)
    else:
        print("WebGL not available or GLUT is not installed.")
