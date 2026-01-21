"""
Federal Security Compliance Test Suite

This test package contains automated tests for verifying compliance with:
- NIST SP 800-207 (Zero Trust Architecture)
- NIST SP 800-53 (Security Controls)
- STIG (Security Technical Implementation Guides)
- FedRAMP requirements

Test Organization:
- test_zero_trust.py: Zero Trust principle verification
- test_stig_compliance.py: STIG control verification
- test_auth_controls.py: Authentication and session tests
- test_audit_logging.py: Audit logging verification

Running Tests:
    pytest tests/ -v
    pytest tests/ -v --cov=templates  # With coverage
"""
