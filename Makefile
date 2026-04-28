SHELL := /bin/bash

.PHONY: sync-rules check-rules

sync-rules:
	@mkdir -p .claude/rules
	@rm -f .claude/rules/*.md
	@for f in .github/instructions/*.instructions.md; do \
		base=$$(basename "$$f" .instructions.md); \
		awk 'NR==1 && $$0=="---" { in_front_matter=1; next } in_front_matter && $$0=="---" { in_front_matter=0; next } !in_front_matter { print }' "$$f" > ".claude/rules/$$base.md"; \
	done

check-rules:
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	mkdir -p "$$tmp/rules"; \
	for f in .github/instructions/*.instructions.md; do \
		base=$$(basename "$$f" .instructions.md); \
		awk 'NR==1 && $$0=="---" { in_front_matter=1; next } in_front_matter && $$0=="---" { in_front_matter=0; next } !in_front_matter { print }' "$$f" > "$$tmp/rules/$$base.md"; \
	done; \
	diff -ru "$$tmp/rules" .claude/rules