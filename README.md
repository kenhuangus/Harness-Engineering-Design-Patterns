# **Harness-Engineering-Design-Patterns**

Harness-Engineering-Design-Patterns is the public companion lab repository for **Harness Engineering: Design Patterns for Securing Long-Horizon Multi-Agent AI Systems** by Ken Huang.

The book argues that the decisive artifact in production agentic AI is not a clever prompt, a single model, or a single guardrail. The decisive artifact is the harness: the control plane that mediates what agents may know, remember, decide, delegate, execute, observe, resume, and improve. This repository turns that argument into runnable code. Each chapter has an executable scenario, a teaching README, and a deterministic result object that records what the harness allowed, blocked, escalated, or preserved as evidence.

The labs are deliberately dependency-free so that a student can run them with a normal Python installation and no cloud account, no paid model API, no live secrets, and no vendor-specific setup. That constraint is important. A production harness may integrate identity providers, model gateways, workflow engines, observability backends, vaults, DLP services, policy engines, sandboxes, CI systems, and ticketing platforms. Harness-Engineering-Design-Patterns keeps the first learning surface small enough to inspect while preserving the control-plane shape that those production systems need.

## Purpose

Harness-Engineering-Design-Patterns teaches secure harness engineering by making every control concrete. The core package models task-scoped identity, audience-bound credentials, intent contracts, context quarantine, memory ledgers, evidence envelopes, runtime checkpoints, fleet back-pressure, and data-governance routing. These are not final enterprise implementations. They are compact reference forms designed to be read in class, extended in assignments, and mapped to production platforms. The value of the repository is that students can inspect a whole harness pattern in one sitting, then ask how the same pattern would be expressed in a model gateway, policy engine, workflow engine, or platform service.

The labs also teach hill climbing as an engineering discipline. Long-horizon agents rarely move in a straight line from prompt to answer. They search locally over plans, tool calls, code changes, context, memory, evidence, evaluator feedback, and recovery states. That search creates value when the harness makes it bounded, observable, reversible, and evidence-driven. The same search creates risk when authority expands silently, when low-trust context becomes durable memory, when traces are too thin to explain a decision, or when a subagent acts under another agent's broad credentials. Harness-Engineering-Design-Patterns makes that tension visible in code.

## Quick Start

Use Python 3.11 or later.

```bash
git clone https://github.com/PacktPublishing/Harness-Engineering-Design-Patterns.git
cd Harness-Engineering-Design-Patterns
python -m pip install -e .
python -m harnesslab.cli list
python -m harnesslab.cli run ch07 --json
python -m harnesslab.cli run all
python -m harnesslab.cli pipeline
python -m harnesslab.cli measure
```

The installed console command is also available:

```bash
harnesslab list
harnesslab run all
harnesslab pipeline
harnesslab measure
```

Every chapter runner returns a `LabResult` with `chapter`, `title`, `passed`, `score`, `summary`, `decisions`, and `artifacts`. The decisions are the teaching surface. They show where the harness allowed low-risk work, denied an unsafe route, escalated an action for human approval, warned about drift, quarantined hostile context, or preserved evidence for replay. The artifacts show the state that would matter in production: a delegation chain, checkpoint, memory ledger entry, trace envelope, queue state, lineage record, or compliance hash.

Each chapter also stores an actual captured run under `chapters/chXX/LabResult/`. Those folders contain the parsed `result.json`, raw `stdout.txt`, raw `stderr.txt`, and a short README so instructors can compare expected evidence with a fresh local run. Each captured `LabResult/` folder is committed with the chapter so instructors can compare expected evidence with a fresh local run.

## Reference architecture

Before the ten chapters, the repository supplies one request path. `harnesslab/pipeline.py` runs a request through seven stages — model invocation, tool selection, authorization, execution, observation, state updates, termination — using the same core primitives the chapter labs use. Each stage records its decisions; the pipeline stops at the first denial or escalation and seals the run as evidence. Run it with `python -m harnesslab.cli pipeline`: one benign request executes end to end and checkpoints, a privileged vault read outside the intent contract is denied at authorization, and a poisoned memory write executes as a tool call but is denied by the memory gate at state updates.

The model is a `ModelAdapter` (`harnesslab/adapters.py`). In the labs it is a `ScriptedModel`: a deterministic stand-in that returns planned calls in order, so the adapter seam is exercised without a model API, a network call, or a secret. A production adapter implements the same protocol against a real model gateway. The proposal is data, not authority — every call it returns still passes the gateway, the intent contract, the budget, and the credential broker.

## Implementation boundaries

Four boundaries connect the security patterns to implementation. Each one has a home in this repository:

| Boundary | What it enforces | Where it lives |
|---|---|---|
| Tool contracts | A tool call carries its purpose, scope, and risk — nothing else runs | `ToolSpec` + `ToolGateway` in `harnesslab/core.py`; every lab call passes the gateway |
| Model adapters | The harness, not the model, decides what a model call may carry | `ModelAdapter` + `ScriptedModel` in `harnesslab/adapters.py`; the pipeline's stage 1 |
| Extension supply-chain | No extension runs without review, pinning, and a trust tier | `ExtensionRegistry` in `harnesslab/extensions.py`; unpinned, unreviewed, or unknown extensions are denied at load |
| Protocol boundaries | Credentials and calls are audience-bound at the system edge | `CredentialBroker` in `harnesslab/core.py`; short-lived audience-bound credentials, verified before authorization |

## Measured adversarial results

The repository measures its own claims. `python -m harnesslab.cli measure` runs four adversarial scenarios — poisoned context (ch05), unauthorized memory write (ch06), resume after credentials expired (ch03), and an external action that cannot simply be rolled back (ch08) — and reports task completion, harness latency, and human review for each. Latency is the harness `run()` median over 20 in-process runs, interpreter startup excluded. Measured on 2026-11-11: all four scenarios PASS with score 1.000, latency 0.2–1.8 ms median, and 1 escalation across 66 decisions — three of the four scenarios needed zero human review. Exact medians vary by machine; the command is the source of truth, re-run it to reproduce the numbers.

## Chapter Map

Titles match the published Kindle edition.

Chapter 1, **Harness as the Control Plane for Long-Horizon Multi-Agent Systems**, introduces the secure harness as the reference architecture for controlled agentic search. The lab starts with an unsafe shared-tool swarm and maps it to a control and evidence matrix.

Chapter 2, **Autonomy: Graduated Control and Human Oversight**, treats autonomy as a ladder instead of a switch. The lab demonstrates capability budgets, approval queues, non-waivable controls, authority expiry, renewal, and rollback hooks.

Chapter 3, **Identity: Per-Agent Identity and Delegation Chains**, replaces shared tokens with accountable agent, task, workload, tool, and resource identities. The lab exercises audience-bound credentials, revocation, pause/resume rotation, and least-privilege scope checks.

Chapter 4, **Intent: Contracts, Drift Detection, and Authorization by Purpose**, treats declared purpose as an authorization boundary. The lab checks tool scope, data scope, risk, evidence, stale goals, safe rewriting, and purpose-bound reauthorization.

Chapter 5, **Context: Trust Tiers, Provenance, and Context-Poisoning Containment**, treats context as both information and authority. The lab releases only trusted and fresh context, quarantines external instructions, blocks lethal-trifecta egress, and preserves quarantine evidence.

Chapter 6, **Memory: State Firewall, Ledger, and Forgetting**, treats memory as future behavior. The lab gates memory writes, records state in a ledger, promotes safe handoffs, isolates tenants, expires records, and tombstones poisoned memory.

Chapter 7, **Observability, Evals, and Hill-Climbing Evidence**, turns traces into the evidentiary layer for improvement. The lab emits redacted spans, hashes artifacts, builds replay bundles, detects benchmark regression, and governs recursive improvement.

Chapter 8, **Runtime Steering: Intervention, Policy Injection, and Safe Rollback**, shows how to steer a run after execution begins. The lab observes, warns, pauses, blocks, kills, quarantines, recovers, replays, compensates, and expires bounded policy overlays.

Chapter 9, **Scalability: Fleet Coordination Without Cascading Failure**, moves from a single run to a fleet. The lab covers tenant bulkheads, global queues, quota escalation, rate-limit back-pressure, idempotent retries, compromised-worker quarantine, and capacity epochs.

Chapter 10, **Data Governance: Classification-Aware Tools, Egress, and Compliance**, makes data governance a runtime property of the harness. The lab routes labeled data through approved profiles, blocks unsafe egress and residency drift, escalates secret leakage, persists labels across resume, and proves erasure across memory plus trace evidence.

## Teaching Method

The preferred teaching sequence is run, inspect, extend, and review. First, run a chapter and read the JSON output without looking at the implementation. Ask students to identify which decision represents the unsafe path and which artifact would matter to an auditor or incident responder. Second, inspect `scenario.py` and locate the harness control that changed the outcome. Third, extend the scenario with one realistic failure: stale approval after a pause, subagent use of a parent credential, external context that carries instructions, memory promotion from an untrusted source, a trace that omits an artifact hash, a retry that repeats a non-idempotent action, or a data label that disappears before egress. Fourth, review whether the new control preserves useful agency while making the run bounded, justified, traced, interruptible, and recoverable.

This sequence keeps the material from becoming a vocabulary tour. Students should not leave with a list of terms; they should leave with the habit of asking what authority is being granted, what purpose justifies it, what context informed it, what state will outlive it, what evidence explains it, and what recovery path remains. That habit is the core of secure harness engineering.

## Practitioner Use

For practitioner workshops, treat Harness-Engineering-Design-Patterns as a tabletop-to-code bridge. A security architect can run the Chapter 5 context lab and compare it with an internal retrieval pipeline. A platform team can run the Chapter 8 runtime-steering lab and ask whether its own agent platform can pause a compromised run without destroying forensic evidence. A governance team can run Chapter 10 and ask where labels are lost between intake, tools, memory, traces, and output. A DevSecOps team can wire the CLI into CI and use the tests as examples for policy-as-test gates.

The repository is also useful for design reviews. Pick one chapter, run the lab, and map every decision to an internal system. If the internal platform lacks a corresponding component, decide whether the gap belongs in the model gateway, tool gateway, workflow engine, identity plane, memory service, trace backend, CI pipeline, or governance layer. Then ask what evidence would convince a reviewer that the control worked. The goal is not to copy the toy implementation. The goal is to identify the production boundary that needs an explicit contract.

## Long-Running Agents

Long-running agents are the reason this repository emphasizes state. A short chatbot can fail in a single response. A long-horizon agent can fail because it resumes with stale context, renews credentials incorrectly, promotes unsafe memory, loses a trace boundary, retries a non-idempotent action, or carries a data label into the wrong region. Each chapter therefore includes a long-running-agent angle, and each lab includes at least one artifact that could survive beyond a single model call: a checkpoint, ledger entry, delegation chain, trace envelope, queue state, policy overlay, or lineage record.

When extending the labs, pay attention to what happens at pause and resume. Credentials may need rotation. Intent may need renewal. Context may need freshness checks. Memory may need promotion gates. Traces may need continuity. Runtime policy overlays may need expiry. Fleet queues may need idempotency. Data labels may need to persist across summaries, memory, traces, and outputs. These are the places where long-running systems quietly become unsafe even when every individual tool call looks reasonable.

## Quality Gates

The repository includes tests and a QA script because the labs are part of a book project, not disposable demos. `python -m unittest discover -s tests` verifies the core controls and registered lab execution. `python -m unittest discover -s tests` verifies the core controls and registered lab execution. GitHub Actions runs unit tests and executes every chapter lab across supported Python versions.

The quality bar is intentionally practical. A chapter is not complete because it prints JSON. It must show a success path and a bounded unsafe path. It must return deterministic artifacts. It must be readable without external services. It must teach the chapter's pattern rather than merely naming it. It must avoid repeated filler text, because repeated filler hides weak thinking and makes the course material harder to trust.

## Repository Structure

The repository has three layers. The first layer is `harnesslab/`, which contains the reusable control-plane primitives. `core.py` defines the security and governance vocabulary used across the labs: identities, task credentials, tool calls, policy decisions, intent contracts, context items, memory records, trace spans, evidence envelopes, checkpoints, runtime control, fleet coordination, and data-governance routing. `labs.py` is the registry that binds the public chapter keys to their scenario modules. `cli.py` is the thin command-line surface used by students and CI. This separation matters because students can see which ideas are shared harness infrastructure and which ideas belong to a specific chapter.

The second layer is `chapters/`. Each chapter folder contains its own `scenario.py`, `run.py`, README, and `LabResult/` folder. The scenario implements the chapter's executable teaching case. The runner keeps the direct module command simple. The README explains the security pattern, the failure mode, the long-running-agent concern, and the interpretation of the returned evidence. The `LabResult/` folder preserves a real run as JSON plus raw command output. Chapter folders should remain independent teaching modules; a student should be able to study Chapter 4 intent contracts without needing to understand every detail of Chapter 9 fleet coordination.

The third layer is the quality and release layer. `tests/` verifies the core contract and confirms that every registered lab runs. `.github/workflows/ci.yml` runs unit tests and executes every chapter lab across supported Python versions. `CONTRACTS.md` records the interface rules that chapter implementations must preserve. `SECURITY.md` clarifies that the project contains simulated unsafe paths for teaching, while still treating framework bugs, misleading controls, or accidental leakage as real security issues.
