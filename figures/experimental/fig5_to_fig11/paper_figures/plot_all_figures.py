from .fig5_message_evidence import render as render_fig5
from .fig6_role_authorization import render as render_fig6
from .fig7_safety_coverage import render as render_fig7
from .fig8_domain_cap import render as render_fig8
from .fig9_committee_ablation import render as render_fig9
from .fig10_dynamic_protocol import render as render_fig10
from .fig11_finality_cost import render as render_fig11
from .results_focused import render as render_results_focused

if __name__ == '__main__':
    render_fig5(); print('Rendered Fig.5')
    render_fig6(); print('Rendered Fig.6')
    render_fig7(); print('Rendered Fig.7')
    render_fig8(); print('Rendered Fig.8')
    render_fig9(); print('Rendered Fig.9')
    render_fig10(); print('Rendered Fig.10')
    render_fig11(); print('Rendered Fig.11')
    render_results_focused(); print('Rendered frozen manuscript figure projections')
