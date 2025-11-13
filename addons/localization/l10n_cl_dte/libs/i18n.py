# -*- coding: utf-8 -*-
"""
Pure Python i18n for DTE libs.
Falls back to Odoo translation when available.

Pattern: Graceful degradation for internationalization
"""


def gettext(message):
    """
    Translate message (fallback to Odoo _() when available).

    Args:
        message (str): String to translate

    Returns:
        str: Translated message (if Odoo available), or original message

    Examples:
        >>> from odoo.addons.l10n_cl_dte.libs.i18n import gettext
        >>> error_msg = gettext("CAF signature validation failed")
        >>> # In Odoo context: Returns Spanish translation
        >>> # Standalone: Returns original English message
    """
    try:
        from odoo import _
        return _(message)
    except ImportError:
        # Fallback: return original message (no translation)
        return message


# Alias for convenience (matches Odoo convention)
_ = gettext


def ngettext(singular, plural, n):
    """
    Plural-aware translation (fallback to Odoo _lt when available).

    Args:
        singular (str): Singular form
        plural (str): Plural form
        n (int): Count

    Returns:
        str: Appropriate form based on count
    """
    try:
        from odoo.tools.translate import _
        # Odoo doesn't have ngettext, use singular/plural logic
        return _(singular) if n == 1 else _(plural)
    except ImportError:
        # Fallback: English plural rule (n == 1 → singular)
        return singular if n == 1 else plural


def set_language(lang_code):
    """
    Set language for translations (Odoo context only).

    Args:
        lang_code (str): Language code (e.g., 'es_CL', 'en_US')

    Note:
        No-op in standalone mode (requires Odoo)
    """
    try:
        from odoo import api
        # In Odoo context, language is set via context
        # This is a placeholder for future enhancement
        pass
    except ImportError:
        # Standalone: No language switching available
        pass
