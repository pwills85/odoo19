# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## 📚 Project Documentation (Modular Structure)

This CLAUDE.md uses a modular architecture to optimize performance and reduce token usage. Content is split into focused modules in `.claude/project/`:

@include .claude/project/01_overview.md#Project_Overview

@include .claude/project/02_architecture.md#Architecture

@include .claude/project/03_development.md#Development_Commands

@include .claude/project/04_code_patterns.md#Code_Patterns

@include .claude/project/05_configuration.md#Configuration

@include .claude/project/06_files_reference.md#Files_Reference

@include .claude/project/07_planning.md#Planning

@include .claude/project/08_sii_compliance.md#SII_Compliance

@include .claude/project/09_quick_reference.md#Quick_Reference

---

**Last Updated:** 2025-10-23 22:30 UTC
**Modular Structure:** 9 modules + main file
**Total Size Reduction:** ~88% (44KB → 5KB main file)
**Performance Impact:** Significant reduction in token usage per session
**Recent Update:** AI Service - Anthropic 0.71.0 upgrade + Stack simplification (OpenAI removed)

---

## 💡 About This Modular Structure

This CLAUDE.md has been refactored from a monolithic 44KB file into a modular architecture for better performance:

**Benefits:**
- **Faster Loading:** Main file is 88% smaller
- **Easier Maintenance:** Update specific sections without editing entire file
- **Better Organization:** Each module has single responsibility
- **Scalability:** Add new modules without bloating main file
- **Token Economy:** Reduced context window usage

**Module Organization:**
- `01_overview.md` - Project status, recent sprints, ROI
- `02_architecture.md` - System architecture, components, dependencies
- `03_development.md` - Docker commands, testing, troubleshooting
- `04_code_patterns.md` - Key design patterns and validation flows
- `05_configuration.md` - Environment variables, service communication
- `06_files_reference.md` - Key file locations and descriptions
- `07_planning.md` - Roadmap, migration plans, documentation index
- `08_sii_compliance.md` - SII requirements, gap closure achievements
- `09_quick_reference.md` - Quick access info, credentials, monitoring

**To Edit:**
Navigate to `.claude/project/XX_module_name.md` and edit the specific module. Changes will be reflected automatically.
