from PIL import Image, ImageDraw, ImageFont
import io
import base64

def y():
    t = []
    img = Image.new('RGBA', (2000, 200), (255, 255, 255, 255))  # White background for RGBA
    draw = ImageDraw.Draw(img)

    # Canvas winding
    draw.rectangle([0, 0, 10, 10], fill=(0,0,0,255)) # Black fill for visibility
    draw.rectangle([2, 2, 8, 8], fill=(255,255,255,255)) # White "hole"
    # PIL doesn't directly support isPointInPath, so we approximate
    is_in_path = img.getpixel((5,5)) == (0,0,0,255)
    t.append(f"canvas winding:{'yes' if not is_in_path else 'no'}")



    # Text rendering (adjust font path as needed)
    try:
        font = ImageFont.truetype("Arial.ttf", 11) # Replace with actual font path
    except IOError:
        font = ImageFont.load_default()  # Fallback if Arial isn't found
        
    draw.rectangle([125, 1, 125 + 62, 1 + 20], fill="#f60")
    draw.text((2, 15), "Cwm fjordbank glyphs vext quiz, \ud83d\ude03", fill="#069", font=font)

    try:
        font18 = ImageFont.truetype("Arial.ttf", 18)  # Larger font
    except IOError:
        font18 = ImageFont.load_default() # Fallback

    draw.text((4, 45), "Cwm fjordbank glyphs vext quiz, \ud83d\ude03", fill=(102, 204, 0, 64), font=font18)


    # Circle drawing and compositing (using alpha blending)

    def draw_circle(center_x, center_y, radius, color):
        overlay = Image.new('RGBA', img.size, (0, 0, 0, 0))
        overlay_draw = ImageDraw.Draw(overlay)
        overlay_draw.ellipse([(center_x - radius, center_y - radius), (center_x + radius, center_y + radius)], fill=color)
        img.alpha_composite(overlay)  # Blend with main image

    draw_circle(50, 50, 50, (255, 0, 255, 255))
    draw_circle(100, 50, 50, (0, 255, 255, 255))
    draw_circle(75, 100, 50, (255, 255, 0, 255))


    # Even-odd fill (simulated using two overlapping circles)
    draw_circle(75, 75, 75, (255, 0, 255, 255))
    draw_circle(75, 75, 25, (255,255,255, 255))  # "Cut out" the inner circle


    # Data URL generation
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
    t.append(f"canvas fp:data:image/png;base64,{img_str}")

    return t



result = y()
print(result)