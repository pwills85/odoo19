Odoo 19 Prompts SDK Documentation
===================================

Python SDK for automated Odoo 19 prompt system management and multi-agent audits.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   api
   tutorials
   architecture

Features
--------

* **Audit Runner**: Run multi-agent audits programmatically
* **Metrics Manager**: Track sprint metrics and generate dashboards
* **Template System**: Load and validate prompt templates
* **Cache Manager**: Cache audit results to reduce API costs
* **Multi-Agent Orchestration**: Coordinate multiple AI agents
* **Integrations**: Slack, Email, and GitHub notifications
* **CLI Interface**: Command-line tools for common operations

Quick Start
-----------

Install the SDK:

.. code-block:: bash

   pip install odoo19-prompts-sdk

Run an audit:

.. code-block:: python

   from prompts_sdk import AuditRunner

   runner = AuditRunner(
       module_path="addons/l10n_cl_dte",
       dimensions=["compliance", "backend"]
   )

   result = runner.run()
   print(f"Score: {result.score}/100")

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
