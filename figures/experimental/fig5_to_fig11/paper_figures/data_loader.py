import pandas as pd
from .style import DATA_DIR

PACKAGE_ROOT = DATA_DIR.parents[3]
RQ4_ROOT = (
    PACKAGE_ROOT
    / 'artifact'
    / 'results'
    / 'participation_control'
    / 'rq4_protocol_closed'
)
AUTHORITATIVE_RQ4 = {
    'RQ4_block_level.csv': RQ4_ROOT / 'RQ4_block_level.csv',
    'RQ4_risk_stream.csv': RQ4_ROOT / 'RQ4_risk_stream.csv',
    'RQ4_summary.csv': RQ4_ROOT / 'RQ4_summary.csv',
}

def load_csv(name: str):
    return pd.read_csv(AUTHORITATIVE_RQ4.get(name, DATA_DIR / name))
