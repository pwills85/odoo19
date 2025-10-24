# .claude/ Directory

**Purpose:** Claude Code project configuration and modular documentation

## Structure

```
.claude/
├── README.md                    # This file
├── MODULARIZATION_REPORT.md     # Detailed reorganization report
└── project/                     # Modular CLAUDE.md content
    ├── 01_overview.md           # Project status, sprints, ROI
    ├── 02_architecture.md       # System architecture, components
    ├── 03_development.md        # Docker, testing, troubleshooting
    ├── 04_code_patterns.md      # Design patterns, validation flows
    ├── 05_configuration.md      # Environment vars, service communication
    ├── 06_files_reference.md    # Key file locations
    ├── 07_planning.md           # Roadmap, migration plans
    ├── 08_sii_compliance.md     # SII requirements, gap closure
    └── 09_quick_reference.md    # Quick access, credentials
```

## Why Modular?

**Problem:** Original CLAUDE.md was 44KB, exceeding Claude Code's 40KB recommendation.

**Solution:** Split into 9 focused modules, referenced via `@include` in main CLAUDE.md.

**Result:**
- Main file: 44KB → 2.3KB (**95% reduction**)
- Token usage per session: ~11K → ~600 tokens (**94% reduction**)
- Faster performance, easier maintenance

## Usage

**Edit specific sections:**
- Project status? → Edit `project/01_overview.md`
- Architecture? → Edit `project/02_architecture.md`
- Commands? → Edit `project/03_development.md`

**Main CLAUDE.md automatically includes all modules via `@include` directives.**

## Rollback

If needed, restore original:
```bash
mv CLAUDE.md CLAUDE.md.modular
mv CLAUDE.md.backup CLAUDE.md
```

---

**Created:** 2025-10-23
**Status:** Active
**Maintenance:** Update modules, not main CLAUDE.md
