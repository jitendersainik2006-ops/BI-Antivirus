import os
import math
from PIL import Image, ImageDraw, ImageFilter

src = r"C:\Users\jitendersaini2006\.gemini\antigravity\brain\9c8af58a-fb69-4549-b393-ed106d7a72bf\.user_uploaded\media_1795681438746_71464ac2.jpg"
res_dir = r"D:\bit defender\bi_antivirus\resources"
android_res = r"D:\bit defender\android\app\src\main\res"

os.makedirs(res_dir, exist_ok=True)
os.makedirs(android_res, exist_ok=True)

im_orig = Image.open(src).convert("RGBA")
w, h = im_orig.size

# Exact center and radii of outer gold rim
cx, cy = 449.5, 437.0
rx, ry = 419.0, 428.0

print(f"Loaded source image: {w}x{h}")

# Step 1: Create 4x supersampled anti-aliased mask
scale = 4
mw, mh = w * scale, h * scale
mask_hi = Image.new("L", (mw, mh), 0)
draw = ImageDraw.Draw(mask_hi)

mcx = cx * scale
mcy = cy * scale
mrx = rx * scale
mry = ry * scale

# Draw filled ellipse with slight expansion to retain outer bevel
draw.ellipse([mcx - mrx, mcy - mry, mcx + mrx, mcy + mry], fill=255)

# Downsample with Lanczos for smooth edge anti-aliasing
mask_aa = mask_hi.resize((w, h), Image.Resampling.LANCZOS)

# Apply mask to image
im_transparent = im_orig.copy()
im_transparent.putalpha(mask_aa)

# Crop to tight bounding box of medallion
box = (
    int(cx - rx),
    int(cy - ry),
    int(cx + rx) + 1,
    int(cy + ry) + 1
)
medallion = im_transparent.crop(box)
mw_box, mh_box = medallion.size

# Place centered onto a square canvas without distortion
dim = max(mw_box, mh_box)
square_medallion = Image.new("RGBA", (dim, dim), (0, 0, 0, 0))
offset_x = (dim - mw_box) // 2
offset_y = (dim - mh_box) // 2
square_medallion.paste(medallion, (offset_x, offset_y), medallion)

print(f"Generated square medallion master: {dim}x{dim}")

# Save master transparent PNG
master_png = os.path.join(res_dir, "black_intel_emblem.png")
square_medallion.save(master_png, "PNG")
print(f"Saved master PNG: {master_png}")

# Save original square with black background
square_orig = os.path.join(res_dir, "black_intel_emblem_square.png")
im_orig.save(square_orig, "PNG")

# Step 2: Generate Windows multi-resolution sizes
win_sizes = [512, 256, 128, 64, 48, 32, 24, 16]
ico_layers = []

for s in win_sizes:
    resized = square_medallion.resize((s, s), Image.Resampling.LANCZOS)
    png_path = os.path.join(res_dir, f"black_intel_emblem_{s}.png")
    resized.save(png_path, "PNG")
    ico_layers.append(resized)
    print(f"  Generated {s}x{s} PNG: {png_path}")

# Save multi-resolution Windows ICO (containing 256, 128, 64, 48, 32, 24, 16)
ico_path = os.path.join(res_dir, "bi_antivirus.ico")
# Pillow saves multi-resolution icons when passed append_images
# First image should be 256x256
ico_sizes = [256, 128, 64, 48, 32, 24, 16]
ico_images = [square_medallion.resize((s, s), Image.Resampling.LANCZOS) for s in ico_sizes]
ico_images[0].save(
    ico_path,
    format="ICO",
    sizes=[(s, s) for s in ico_sizes],
    append_images=ico_images[1:]
)
print(f"Saved multi-resolution Windows ICO ({len(ico_sizes)} layers): {ico_path}")

# Step 3: Generate Android legacy mipmaps (ic_launcher.png and ic_launcher_round.png)
mipmap_densities = {
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192
}

for folder, size in mipmap_densities.items():
    folder_path = os.path.join(android_res, folder)
    os.makedirs(folder_path, exist_ok=True)
    
    # 1. Standard square launcher icon (with subtle dark round-rect background)
    bg_color = (10, 11, 14, 255) # #0A0B0E
    icon_canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw_canv = ImageDraw.Draw(icon_canvas)
    corner_radius = int(size * 0.22)
    draw_canv.rounded_rectangle([0, 0, size - 1, size - 1], radius=corner_radius, fill=bg_color)
    
    # Emblem placed inside rounded rect (90% size)
    emb_size = int(size * 0.88)
    emb_resized = square_medallion.resize((emb_size, emb_size), Image.Resampling.LANCZOS)
    pos = (size - emb_size) // 2
    icon_canvas.paste(emb_resized, (pos, pos), emb_resized)
    icon_canvas.save(os.path.join(folder_path, "ic_launcher.png"), "PNG")
    
    # 2. Round launcher icon
    round_canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw_round = ImageDraw.Draw(round_canvas)
    draw_round.ellipse([0, 0, size - 1, size - 1], fill=bg_color)
    round_canvas.paste(emb_resized, (pos, pos), emb_resized)
    round_canvas.save(os.path.join(folder_path, "ic_launcher_round.png"), "PNG")
    
    print(f"  Generated {folder} ({size}x{size}): ic_launcher.png, ic_launcher_round.png")

# Step 4: Generate Android Adaptive Icon Foreground
# Canvas: 108dp. Safe zone diameter: 72dp (ratio = 72/108 = 0.667).
# We generate drawable densities for ic_launcher_foreground.png
adaptive_densities = {
    "drawable-mdpi": (108, 72),
    "drawable-hdpi": (162, 108),
    "drawable-xhdpi": (216, 144),
    "drawable-xxhdpi": (324, 216),
    "drawable-xxxhdpi": (432, 288)
}

for folder, (canvas_sz, safe_sz) in adaptive_densities.items():
    folder_path = os.path.join(android_res, folder)
    os.makedirs(folder_path, exist_ok=True)
    
    fg_canvas = Image.new("RGBA", (canvas_sz, canvas_sz), (0, 0, 0, 0))
    # Medallion sized to fit comfortably inside safe zone (~96% of safe zone)
    fg_emb_sz = int(safe_sz * 0.94)
    fg_emb = square_medallion.resize((fg_emb_sz, fg_emb_sz), Image.Resampling.LANCZOS)
    fg_pos = (canvas_sz - fg_emb_sz) // 2
    fg_canvas.paste(fg_emb, (fg_pos, fg_pos), fg_emb)
    
    fg_canvas.save(os.path.join(folder_path, "ic_launcher_foreground.png"), "PNG")
    print(f"  Generated {folder} adaptive foreground: {canvas_sz}x{canvas_sz} (emblem: {fg_emb_sz}x{fg_emb_sz})")

# Also save high-res version to default drawable/
drawable_dir = os.path.join(android_res, "drawable")
os.makedirs(drawable_dir, exist_ok=True)

# 432x432 default foreground
fg_432 = Image.new("RGBA", (432, 432), (0, 0, 0, 0))
fg_emb_432 = square_medallion.resize((276, 276), Image.Resampling.LANCZOS)
fg_432.paste(fg_emb_432, ((432 - 276) // 2, (432 - 276) // 2), fg_emb_432)
fg_432.save(os.path.join(drawable_dir, "ic_launcher_foreground.png"), "PNG")

# In-app emblem for Compose screens (512x512)
app_emblem = square_medallion.resize((512, 512), Image.Resampling.LANCZOS)
app_emblem.save(os.path.join(drawable_dir, "ic_black_intel_emblem.png"), "PNG")
print(f"Saved in-app Compose emblem: {os.path.join(drawable_dir, 'ic_black_intel_emblem.png')}")

print("\nALL BRANDING ASSETS GENERATED SUCCESSFULLY!")
