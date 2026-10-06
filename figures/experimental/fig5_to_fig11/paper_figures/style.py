import os
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib as mpl

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / 'data'
OUTPUT_DIR = Path(
    os.environ.get('SEARPC_FIGURE_OUTPUT_DIR', '/tmp/searpc_figures')
)

COLORS = {
    'blue': '#4C78A8',
    'orange': '#F58518',
    'green': '#54A24B',
    'red': '#E45756',
    'purple': '#9467BD',
    'brown': '#8C564B',
    'gray': '#7F7F7F',
    'lightgray': '#A9A9A9',
}

METHOD_COLORS = {
    'RF': COLORS['blue'],
    'HGBDT': COLORS['orange'],
    'SEARPC': COLORS['green'],
    'SEARPC w/o Role Separation': COLORS['blue'],
    'Single-role Beta': COLORS['blue'],
    'TWSL': COLORS['orange'],
    'Mean · NoCap': '#4D4D4D',
    'Mean · Cap': COLORS['blue'],
    'LCB · NoCap': COLORS['orange'],
    'LCB · Cap': COLORS['green'],
    'Static k13': '#9B9B9B',
    'Yadav direct': '#E06B6A',
    'Feedback fixed': '#6B8DB3',
    'Content only': '#F0963A',
    'Validator only': '#B58AAC',
    'Full set': COLORS['blue'],
    'Fixed k13': COLORS['orange'],
}

EPOCHS = [
    ('Warmup', 1, 200, '#F1F1F1'),
    ('A1', 201, 300, '#DCE7F2'),
    ('B', 301, 400, '#F1E6D5'),
    ('C', 401, 500, '#DCEBDB'),
    ('A2', 501, 600, '#E7DFF0'),
]


def apply_style():
    try:
        plt.style.use('default')
    except Exception:
        pass
    mpl.rcParams.update({
        'font.family': 'serif',
        'font.serif': ['Times New Roman', 'Times', 'Nimbus Roman', 'STIX Two Text', 'DejaVu Serif'],
        'mathtext.fontset': 'stix',
        'font.size': 9.0,
        'axes.labelsize': 10.0,
        'axes.titlesize': 10.0,
        'xtick.labelsize': 8.7,
        'ytick.labelsize': 8.7,
        'legend.fontsize': 8.2,
        'figure.facecolor': 'white',
        'axes.facecolor': 'white',
        'savefig.facecolor': 'white',
        'savefig.edgecolor': 'white',
        'grid.color': '#DDDDDD',
        'grid.alpha': 0.28,
        'grid.linewidth': 0.48,
        'axes.grid': True,
        'axes.axisbelow': True,
        'axes.spines.top': False,
        'axes.spines.right': False,
        'axes.edgecolor': '#4A4A4A',
        'axes.linewidth': 0.70,
        'lines.linewidth': 1.05,
        'lines.markersize': 3.7,
        'xtick.major.width': 0.65,
        'ytick.major.width': 0.65,
        'xtick.major.size': 2.8,
        'ytick.major.size': 2.8,
        'savefig.dpi': 500,
        'figure.dpi': 150,
        'pdf.fonttype': 42,
        'ps.fonttype': 42,
    })
