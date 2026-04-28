SHELL := /bin/bash

.PHONY: sync-rules check-rules

sync-rules:
	@mkdir -p .claude/rules
	@rm -f .claude/rules/*.md
	@set -e; \
	for f in .github/instructions/*.instructions.md; do \
		base=$$(basename "$$f" .instructions.md); \
		awk 'NR==1 && $$0=="---" { in_front_matter=1; next } in_front_matter && $$0=="---" { in_front_matter=0; next } !in_front_matter { print }' "$$f" > ".claude/rules/$$base.md" || exit 1; \
	done

check-rules:
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	set -e; \
	mkdir -p "$$tmp/rules"; \
	for f in .github/instructions/*.instructions.md; do \
		base=$$(basename "$$f" .instructions.md); \
		awk 'NR==1 && $$0=="---" { in_front_matter=1; next } in_front_matter && $$0=="---" { in_front_matter=0; next } !in_front_matter { print }' "$$f" > "$$tmp/rules/$$base.md" || exit 1; \
	done; \
	diff -ru "$$tmp/rules" .claude/rules
