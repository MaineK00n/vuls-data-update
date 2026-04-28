SHELL := /bin/bash

.PHONY: sync-rules check-rules check-shims check-docs check-harness

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

check-shims:
	@set -e; \
	for f in .github/prompts/*.prompt.md; do \
		base=$$(basename "$$f" .prompt.md); \
		test -f ".claude/skills/$$base/SKILL.md" || { echo "missing skill shim for $$f: expected .claude/skills/$$base/SKILL.md"; exit 1; }; \
	done; \
	for f in .github/agents/*.agent.md; do \
		base=$$(basename "$$f" .agent.md); \
		test -f ".claude/agents/$$base.md" || { echo "missing agent shim for $$f: expected .claude/agents/$$base.md"; exit 1; }; \
	done

check-docs:
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	set -e; \
	awk '/^## / { c++; if (c > 2) exit } c > 0' CLAUDE.md > "$$tmp/claude.intro"; \
	awk '/^## / { c++; if (c > 2) exit } c > 0' AGENTS.md > "$$tmp/agents.intro"; \
	diff -u "$$tmp/claude.intro" "$$tmp/agents.intro"

check-harness: check-rules check-shims check-docs
