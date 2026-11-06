from PIL import Image, ImageOps
from pathlib import Path

res = Path("app/src/main/res")
logo_path = res / "drawable" / "app_logo.jpg"

logo = Image.open(logo_path).convert("RGBA")

# Older Android launcher icon sizes
sizes = {
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192,
}

for folder, size in sizes.items():
    output_dir = res / folder
    output_dir.mkdir(parents=True, exist_ok=True)

    icon = ImageOps.fit(
        logo,
        (size, size),
        method=Image.Resampling.LANCZOS
    )
    icon.save(output_dir / "ic_launcher.png")

# Adaptive icon foreground: keep transparent padding
foreground_dir = res / "drawable-nodpi"
foreground_dir.mkdir(parents=True, exist_ok=True)

canvas = Image.new("RGBA", (432, 432), (0, 0, 0, 0))
foreground = ImageOps.contain(
    logo,
    (300, 300),
    method=Image.Resampling.LANCZOS
)

x = (432 - foreground.width) // 2
y = (432 - foreground.height) // 2
canvas.alpha_composite(foreground, (x, y))
canvas.save(foreground_dir / "ic_launcher_foreground.png")

print("Launcher icon images created successfully.")
