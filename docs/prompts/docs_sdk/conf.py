# Sphinx configuration file for Odoo 19 Prompts SDK

import os
import sys
sys.path.insert(0, os.path.abspath('..'))

# Project information
project = 'Odoo 19 Prompts SDK'
copyright = '2025, Pedro Troncoso'
author = 'Pedro Troncoso'
release = '1.0.0'

# Extensions
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
]

# Templates
templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# HTML output
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Napoleon settings (for Google/NumPy docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = True

# Intersphinx
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
}
