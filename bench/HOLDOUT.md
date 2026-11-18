# Holdout protocol

The six tasks in `tasks.json` were designed alongside the policy. Results on them are therefore vulnerable to test-set bias: a rule may look effective because it was written with those targets in mind.

Before claiming the escalation policy works, build an independent task set:

1. **Different targets.** Choose binaries and apps not used while writing `SKILL.md` or `references/router.md`. Different vendors, toolchains, formats and packing states.
2. **Different authors of the keys.** Hand-made answer keys should be produced by someone who did not write the policy, or derived from an authoritative source (vendor docs, build metadata, a known protocol spec).
3. **Hold the targets fixed.** Do not change a target after seeing an arm's result. Version and hash every target in the task manifest.
4. **Freeze the policy.** Tag the skill/commit used for the holdout run. Do not edit the gate text between arms.
5. **Report both sets.** Development-set results are hypothesis-generating; only holdout results support a claim.

Add holdout tasks as a separate manifest and run with `python run.py --tasks <holdout.json> ...`. Keep the development set for debugging only.

Suggested holdout composition: one Electron app, one Go binary, one stripped native binary, one packed/obfuscated sample, one PE with UTF-16 strings, and one runtime-only question.
