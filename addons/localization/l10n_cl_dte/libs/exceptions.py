# -*- coding: utf-8 -*-
"""
Pure Python exceptions for DTE operations.
Maps to Odoo exceptions when available.

Pattern: Pure Python libs with optional Odoo integration
"""


class DTEError(Exception):
    """Base DTE exception (Pure Python)"""
    pass


class DTEAuthenticationError(DTEError):
    """SII authentication error (SOAP, CAF validation)"""
    pass


class DTEValidationError(DTEError):
    """DTE validation error (structure, business rules)"""
    pass


class DTEGenerationError(DTEError):
    """DTE generation error (XML, encoding, signature)"""
    pass


# Odoo integration (optional - for models that use libs/)
try:
    from odoo.exceptions import UserError, ValidationError

    # Map Pure Python exceptions to Odoo for better UX
    # When in Odoo context, DTEAuthenticationError IS-A UserError
    # This makes exceptions catchable by Odoo ORM
    DTEAuthenticationError.__bases__ = (UserError,)
    DTEValidationError.__bases__ = (ValidationError,)
    DTEGenerationError.__bases__ = (UserError,)

except ImportError:
    # Fallback for standalone usage (no Odoo available)
    # Exceptions work as plain Python exceptions
    pass


# Backward compatibility aliases (optional)
# If old code uses these names, map to new DTE* exceptions
def create_backward_compat_aliases():
    """Create backward compatibility aliases if needed"""
    import sys
    module = sys.modules[__name__]

    # Example: If old code used 'SIIAuthError', map to DTEAuthenticationError
    # setattr(module, 'SIIAuthError', DTEAuthenticationError)
    pass


create_backward_compat_aliases()
