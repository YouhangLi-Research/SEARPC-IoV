from pathlib import Path
from io import BytesIO
import math
import os
import tempfile
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib.ticker import PercentFormatter
from PIL import Image
from .style import OUTPUT_DIR, EPOCHS


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_panel(fig, folder: Path, stem: str):
    ensure_dir(folder)
    png = folder / f'{stem}.png'
    pdf = folder / f'{stem}.pdf'
    # Render in memory and validate before installing the complete raster file.
    buffer = BytesIO()
    fig.savefig(buffer, format='png', bbox_inches='tight', pad_inches=0.02, facecolor='white')
    fig.savefig(pdf, bbox_inches='tight', pad_inches=0.02, facecolor='white')
    plt.close(fig)
    with Image.open(BytesIO(buffer.getvalue())) as rendered:
        rendered.load()
        normalized = rendered.copy()
    encoded = BytesIO()
    normalized.save(encoded, format='PNG')
    with tempfile.NamedTemporaryFile(dir=folder, prefix=f'.{stem}.', suffix='.png', delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(encoded.getvalue())
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(png)
    with Image.open(png) as verified:
        verified.verify()
    return png


def make_contact_sheet(paths, out_path: Path, columns: int = 2, pad: int = 26):
    imgs = []
    for path in paths:
        with Image.open(path) as rendered:
            rendered.load()
            imgs.append(rendered.convert('RGB').copy())
    cols = columns
    rows = math.ceil(len(imgs) / cols)
    cell_w = max(im.width for im in imgs)
    cell_h = max(im.height for im in imgs)
    canvas = Image.new('RGB', (pad + cols*(cell_w+pad), pad + rows*(cell_h+pad)), 'white')
    for i, im in enumerate(imgs):
        r, c = divmod(i, cols)
        x = pad + c*(cell_w+pad) + (cell_w-im.width)//2
        y = pad + r*(cell_h+pad) + (cell_h-im.height)//2
        canvas.paste(im, (x, y))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = BytesIO()
    canvas.save(encoded, format='PNG')
    with Image.open(BytesIO(encoded.getvalue())) as verified:
        verified.verify()
    with tempfile.NamedTemporaryFile(dir=out_path.parent, prefix=f'.{out_path.stem}.', suffix='.png', delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(encoded.getvalue())
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(out_path)


def pct_axis(ax):
    ax.yaxis.set_major_formatter(PercentFormatter(xmax=100, decimals=0))


def add_epoch_bands(ax, label_size: float = 7.5):
    ymin, ymax = ax.get_ylim()
    yr = ymax - ymin
    for name, start, end, color in EPOCHS:
        ax.axvspan(start, end, color=color, alpha=0.45, zorder=0)
        if start > 1:
            ax.axvline(start, linestyle='--', color='#B0B0B0', linewidth=0.8)
        ax.text((start+end)/2, ymax + 0.02*yr, name, ha='center', va='bottom', fontsize=label_size, color='#777777', clip_on=False)


def line_legend(*items):
    handles=[]
    for label, color, marker, ls in items:
        handles.append(Line2D([0],[0], color=color, marker=marker, linestyle=ls, label=label))
    return handles


def patch_legend(*items):
    return [Patch(facecolor=color, edgecolor='none', label=label) for label, color in items]
