---
description: Show detailed git status with branch info
---

Display comprehensive git repository status:

```bash
echo "📊 Git Repository Status"
echo "======================="
echo ""

echo "🌿 Current Branch:"
git branch --show-current
echo ""

echo "🔄 Remote Status:"
git remote -v | head -2
echo ""

echo "📝 Uncommitted Changes:"
git status --short
echo ""

echo "📈 Recent Commits (last 5):"
git log --oneline --decorate --graph -5
echo ""

echo "🔍 Changed Files Summary:"
echo "  Modified: $(git status --short | grep '^ M' | wc -l)"
echo "  Added: $(git status --short | grep '^??' | wc -l)"
echo "  Deleted: $(git status --short | grep '^ D' | wc -l)"
echo ""

echo "💡 Next steps:"
echo "  - Review changes: git diff"
echo "  - Stage changes: git add <file>"
echo "  - Commit: git commit -m 'message'"
```

Quick overview of repository state, branch, and pending changes.
