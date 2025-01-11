import numpy as np
from OpenGL.GL import *
from OpenGL.GLUT import *
from OpenGL.GLU import *

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

def test_opengl():
    try:
        # Initialize OpenGL
        glClearColor(0.0, 0.0, 0.0, 1.0)
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        
        # Check some OpenGL capabilities
        print(f"OpenGL Vendor: {glGetString(GL_VENDOR).decode()}")
        print(f"OpenGL Renderer: {glGetString(GL_RENDERER).decode()}")
        print(f"OpenGL Version: {glGetString(GL_VERSION).decode()}")
        print(f"Shading Language Version: {glGetString(GL_SHADING_LANGUAGE_VERSION).decode()}")

        # Get anisotropic filtering support
        anisotropy = get_max_anisotropy()
        print(f"Max Anisotropy: {anisotropy}")

    except Exception as e:
        print(f"Error during OpenGL test: {e}")

if __name__ == "__main__":
    # Initialize GLUT
    glutInit()
    glutCreateWindow(b"Anisotropy Test")
    glutHideWindow()

    # Test OpenGL functionality
    test_opengl()
