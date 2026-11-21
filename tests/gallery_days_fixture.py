"""Small disposable photo archive for the real-server browser check."""
from datetime import datetime
import os
from pathlib import Path
import sys
from PIL import Image, ImageDraw
from app.auth import UserStore

root = Path(sys.argv[1])
(root / 'media').mkdir(parents=True, exist_ok=True)
(root / 'data').mkdir(parents=True, exist_ok=True)
UserStore(root / 'data/users.json').add('tester', 'Local-gallery-123456', 'admin')
number = 0
for day, count in [(20, 5), (19, 2), (18, 17), (17, 1), (16, 7), (15, 16), (14, 30)]:
    for j in range(count):
        im = Image.new('RGB', (480, 360), (40 + day * 5, 70 + j * 4, 90 + number % 120))
        ImageDraw.Draw(im).text((30, 30), f'NOV {day} / PHOTO {j + 1}', fill='white', font_size=32)
        path = root / 'media' / f'photo-{number:03}.jpg'
        im.save(path)
        ts = datetime(2026, 11, day, 12, j).timestamp()
        os.utime(path, (ts, ts))
        number += 1
