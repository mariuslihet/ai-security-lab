# Demonstration scenarios

Use All suites + Paired comparison + Balanced for a broad walkthrough. Use Permissive to show more synthetic objective violations, and Resilient to show model refusals. Provider labels do not change fixture behavior.

Useful walkthrough: prompt injection → system prompt leak → benign controls → multi-turn crescendo → RAG poisoning → boundary scenarios. Inspect both raw and delivered output. In boundary scenarios the tool examples only propose synthetic actions, the mixed-refusal case leaks a marker despite a refusal prefix, and the final fixtures exercise error and inconclusive states.

Run history is persisted. Replay keeps the saved seed, configuration and fixture snapshot. Dataset fingerprints identify fixture changes. Repetitions are deterministic replays, not statistical evidence about commercial models. Execution limits stop jobs without fabricating remaining results. Partial runs retain evidence and an explicit incomplete state.

CLI: python main.py run-lab --suite all --compare --model balanced --seed 42

Exports are generated from stored run evidence. JSON contains full trace details; Markdown summarizes outcomes; the report page supports browser print / Save PDF. Old v1 loose report files remain on disk but are not silently mixed into the new run database.
