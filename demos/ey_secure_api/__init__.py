"""
EY Demo: AI-Assisted Secure Code Generation
============================================
This package demonstrates Devin's value proposition for federal security compliance.

Modules:
- secure_flask_api: Complete Flask API with all STIG security controls
- vulnerability_detection_demo: Before/after vulnerability remediation examples
- compliance_traceability: STIG/NIST control mapping documentation
"""

from .secure_flask_api import app
from .vulnerability_detection_demo import run_all_demos
from .compliance_traceability import demonstrate_compliance_traceability

__all__ = ['app', 'run_all_demos', 'demonstrate_compliance_traceability']
