# **Chapter 3: Identity: Per-Agent Identity and Delegation Chains**

Identity is the control plane that lets a secure harness answer four practical questions about long-horizon agent work: who is acting, what task are they acting for, who delegated that authority, and where is the credential allowed to be used. A prompt alone cannot answer those questions. A model can say "I am the patching agent" or "I am only reading the ticket," but a production system needs an inspectable object that says the same thing in a form policy code can verify.

This chapter turns identity into a runnable harness pattern. The scenario creates multiple agents, gives each task its own identity, issues short-lived credentials, binds those credentials to a specific audience, records delegation chains, revokes credentials, rotates credentials after a pause, and applies least-privilege scope to tools, data classes, and resources. Everything is deterministic and dependency-free so the chapter can run in a classroom or CI job without network access, cloud accounts, or real secrets.

The lesson is simple but important: agents should not borrow one broad service account and hope that logs sort it out later. A long-running multi-agent system should treat every worker and every task as an accountable principal. Credentials should be narrow, temporary, audience-bound, and revocable. Delegation should be explicit. A resume from checkpoint should not silently reuse an old bearer token. Tool access should be limited by purpose, data class, and resource.

## Why Identity Is Different For Agents

Traditional application identity often starts with a user, a service account, or a workload. That model is still useful, but agent systems add pressure in three ways.

First, an agent run may last longer than a single request. The run may read context, split work into subtasks, call tools, pause, resume, and hand off to other agents. If the system only has one identity for the whole run, every action looks the same. A ticket reader, repository patcher, and auditor all collapse into one principal, even though they need different permissions.

Second, agent systems frequently delegate. A planner may decide that one worker should read customer context and another should prepare a code change. Those workers did not receive authority directly from the user. They received it through the planner and the harness. A useful identity layer should preserve that chain so the audit record can show not only who acted, but why that actor was allowed to act.

Third, agents can drift. A worker that starts with a narrow task may encounter new context, generate a new plan, or attempt a tool call outside its lane. Identity does not solve drift by itself, but it gives policy something concrete to check. If the credential is only valid for the ticketing audience, using it against the repository service fails. If the task identity is only scoped to one tenant ticket, a cross-tenant ticket read fails. If a privileged deploy exceeds the task contract, the harness escalates instead of letting an automated worker cross a risk boundary.

The chapter scenario models these pressures without pretending to be a real identity provider. The core `CredentialBroker` issues HMAC-backed training credentials, verifies audience, checks expiry, and supports revocation by subject. The chapter code uses those primitives to demonstrate production shapes: agent identities, task identities, delegation chains, pause/resume rotation, and least privilege.

## The Scenario

The runnable lab simulates a security incident workflow for a tenant named `acme`. A planner coordinates three workers:

- `agent-reader` reads a customer-impacting ticket.
- `agent-patcher` prepares a repository patch.
- `agent-auditor` audits evidence for the run.

Each worker has a distinct `AgentIdentity`. The reader, patcher, and auditor all name the planner as their parent. That parent link is not a substitute for authorization, but it gives the harness an attributable handoff structure. If the patcher later attempts a privileged operation, the evidence can show that the planner delegated patch work to the patcher, not that an anonymous background process made the call.

The lab also creates a separate `TaskIdentity` for each work item. The task identity binds together the run id, task id, actor, creation time, and expiry. The chapter does not place raw timestamps in the final artifacts because the public result should remain deterministic, but the objects themselves carry the same temporal shape a production harness would use. This distinction matters: a worker can have a durable agent identity while each task receives a short-lived task identity. That lets policy distinguish "the patching agent in general" from "the patching agent acting on this one checkout-service remediation task."

After identities are established, the lab issues credentials:

- The reader receives a credential for the `internal-ticketing` audience.
- The patcher receives a credential for the `internal-repo` audience.
- The auditor receives a credential for the `training-console` audience.

The reader credential succeeds against ticketing and fails against the repository audience. The lab then force-expires a training credential and verifies that it is denied. This models short-lived credentials without adding sleeps or wall-clock flakiness to the test. In production, a short time-to-live reduces the damage window if a token leaks, appears in a trace, or is captured from a paused process. In the lab, the important control is that expiry is enforced by the broker, not by agent self-report.

The patcher credential includes a delegation chain from planner to patcher. The lab verifies that the chain is exactly the expected handoff. It then revokes the patcher's credential subject and shows that the previously valid credential no longer verifies. This is the key difference between an inspectable credential and a natural-language instruction. The patcher can still claim to be authorized, but the broker rejects the revoked token.

The long-running behavior appears in the pause/resume section. The auditor receives a credential, the runtime controller pauses the run, and the harness checkpoints state with credential generation `1`. Before resuming, the broker revokes the old runtime credential. The lab verifies that the old credential fails, resumes from the checkpoint, and issues generation `2`. The resumed credential verifies against the training console. The artifact records the checkpoint id, the state, and the rotated generation without exposing raw tokens.

Finally, the lab demonstrates least privilege. It uses intent contracts and the tool gateway from the core framework, plus a small chapter-specific resource scope check. The reader may use `read_ticket` for a single `acme` ticket. A read of a `globex` ticket is denied as out of resource scope. The patcher may use `patch_repo` against `repo:acme/checkout-service` with internal data. A repository patch carrying PII is denied by both the intent data boundary and the tool gateway. A privileged deploy is configured as an allowed tool in the patch contract only to demonstrate that tool presence is not enough: the risk still exceeds the contract maximum, so the harness escalates.

## What The Result Means

The chapter returns a `LabResult`. The `passed` field is true only when the scenario exercises the controls it claims to teach. The decisions include allowed, denied, warned, and escalated outcomes. That mix is intentional. A useful harness does not merely approve safe actions; it must also produce clear denials and escalations for unsafe or out-of-scope paths.

The result artifacts are designed for teaching and tests. They include agent ids, task ids, credential audiences, delegation chains, revoked subjects, checkpoint state, resource scopes, blocked examples, decision counts, and the set of exercised controls. They do not include bearer tokens, HMAC material, issued timestamps, or expiry timestamps. That is a deliberate artifact hygiene choice. Evidence should prove that the control ran without creating new secret-handling problems.

The scenario score comes from the framework's `score_from_checks` helper: it is the fraction of the scenario's own expected outcomes that held (a credential revoked, a delegation chain preserved, an out-of-scope read denied). A score of 1.0 means every expectation held; a control that fails lowers the score. The score is not an evaluation of security maturity by itself. It only says the lab exercised the expected controls and they held. In a real deployment, you would pair this kind of deterministic harness test with integration tests against your identity provider, replay tests for revoked tokens, and trace review for sensitive artifacts.

## Per-Agent Identity

Per-agent identity gives every worker a stable name, role, tenant, and optional parent. Without it, a multi-agent run becomes a shared bucket of actions. That weakens least privilege because policy cannot easily say "the reader may read tickets but may not patch code" or "the auditor may inspect traces but may not send customer email."

In production, per-agent identity can map to workload identity, SPIFFE ids, service account impersonation, or another identity provider pattern. The exact provider matters less than the invariant: the harness should know which agent is acting before a tool call reaches the tool. The identity should be available to policy, logs, traces, and incident response. It should also be stable enough to write rules against. A display name chosen by a prompt is not enough.

The chapter uses four simple `AgentIdentity` objects. Each has an `agent_id`, a role, and a tenant. The delegated workers also include `parent_id="agent-planner"`. The first decision in the scenario confirms that ids and roles are distinct and that the delegation parent links exist. If those identities collapsed, the lab would fail.

## Per-Task Identity

Per-task identity narrows a worker's authority to one unit of work. This matters because an agent role is usually broader than a single action. A repository patcher may be allowed to patch repositories, but not every repository and not forever. A ticket reader may read tickets, but not every tenant's ticket. Task identity gives the harness a place to bind the current run id, the task id, the actor, and expiry.

The lab creates one task for ticket reading, one for patch preparation, and one for audit evidence. Credential subjects include both the actor id and the task id. That means a token issued for the reader's ticket task is not interchangeable with the patcher's repository task. This is one of the most useful habits for secure agent design: do not grant permissions only to the agent class; grant permissions to the agent acting for a specific task.

Task identity also improves investigation. If a trace shows an unsafe tool call, responders can ask which task created the call, what its scope was, what credential generation was active, and whether the run was resumed from a checkpoint. That is much more actionable than "the automation service did it."

## Audience-Bound Credentials

Audience binding prevents a credential issued for one service from being replayed against another. This is especially important for agents because tool calls can be generated dynamically. A model may propose a call to a different service, or compromised context may encourage the worker to send a token somewhere else. The broker should reject that use even if the credential is otherwise valid.

In the lab, the reader credential is valid for `internal-ticketing`. Verification against that audience allows the call. Verification against `internal-repo` denies the call with an audience mismatch. The denial is not a failure of the lab; it is the control working. A safe harness needs both outcomes.

Audience binding should be combined with short lifetimes. A long-lived token bound to one audience is better than a long-lived all-purpose token, but it can still be abused for that audience. The lab demonstrates expiry by forcing a credential past its expiry and checking that the broker denies it. Production systems should use real clock-based expiry, refresh flows, and ideally proof-of-possession or workload identity where available.

## Delegation Chains

Delegation chains answer "how did this worker get authority?" The planner may be allowed to coordinate a run, but the planner should not silently become every worker. When it delegates to a patcher, the resulting credential should carry a chain like `planner -> patcher`. If the patcher delegates to an auditor, the chain can become `planner -> patcher -> auditor`.

The chapter records those chains on credentials and verifies the patcher chain exactly. The pause/resume credential for the auditor carries the longer chain. These are teaching examples, but the pattern maps cleanly to production evidence. A trace span, audit log, or policy decision can include the delegation chain without exposing the credential token itself.

Delegation chains are also useful for limiting authority. A broker can refuse chains that skip required approvers, exceed a maximum length, cross tenants, or try to delegate a permission the parent did not have. The simple core broker does not implement every production rule, but the chapter shows where that check belongs: at credential issue and verification time, before tool execution.

## Revocation

Revocation is the ability to make a previously valid credential invalid before its natural expiry. For long-running agents, revocation is not optional. Runs may pause for human review, a worker may be suspected of compromise, a policy may change, or a task may be canceled. Waiting for every token to expire can leave too much time for damage.

The lab revokes the patcher's credential subject and then verifies the old credential. The broker returns a denial. Later, during pause/resume, the lab revokes the auditor's generation `1` credential before issuing generation `2`. This models a safe resume posture: after a pause, do not assume the old token is still appropriate. Rotate it and prove the old one fails.

Real revocation can be implemented with token introspection, short TTL plus session state, certificate revocation, key rotation, or a deny list. Each has tradeoffs. The lesson for this chapter is provider-neutral: the harness should have a way to invalidate delegated authority and tests should prove that invalidation is enforced.

## Pause And Resume

Long-running agents are not always continuous. They may pause because they hit a risk threshold, wait for a human, run out of budget, lose a worker, or checkpoint before a deployment window. A resume is a new security moment. The world may have changed since the checkpoint. The original credentials may be close to expiry, already revoked, or too broad for the next step.

The scenario uses the `RuntimeController` to pause a run and checkpoint state. It then revokes the old runtime credential, verifies that revocation, resumes from the checkpoint, and issues a fresh credential generation. The artifact records the checkpoint state rather than the token. That gives students a concrete pattern: checkpoint operational state, not bearer secrets; rotate credentials on resume; and make the rotation visible in evidence.

In production, pause/resume should also re-evaluate policy overlays, data access, memory reads, and user intent. Identity is only one layer. However, identity is the layer that prevents a resumed process from quietly continuing with stale authority.

## Least Privilege

Least privilege means the agent gets only the authority needed for the task at hand. In agent systems, that usually requires several scopes at once:

- Tool scope: which tools can be called.
- Data scope: which classes of data can be handled.
- Resource scope: which concrete tenant, ticket, repository, or trace can be touched.
- Risk scope: which side effects are allowed automatically and which require escalation.
- Time scope: how long the authority lasts.
- Audience scope: which service can accept the credential.

The chapter demonstrates these scopes together. The reader can read one `acme` ticket and cannot read a `globex` ticket. The patcher can patch an internal repository path and cannot patch with PII data. A separate deployment review contract permits the harness to recognize the deploy tool while still escalating because deployment exceeds the reversible-write maximum. This is an important nuance. Tool allowlists are necessary, but not sufficient. A tool can still be too risky for the current task.

The reader also attempts to use `query_vault`, which is outside the ticket-reading contract. That call is denied as a tool-scope violation before the harness needs to debate the requested secret. The deployment example uses a separate review contract to show a different control: even when a high-impact tool is known to the harness, the risk can still require escalation.

Least privilege is easier to reason about when identity is specific. "Agent-patcher may use patch_repo" is broad. "Agent-patcher acting as task X may use patch_repo on repo:acme/checkout-service with internal data for the next ten minutes" is much safer. It is also easier to test.

## Running The Lab

From the `Harness-Engineering-Design-Patterns` directory, run:

```bash
python -m chapters.ch03.run
```

You can also use the Harness-Engineering-Design-Patterns CLI contract:

```bash
python -m harnesslab.cli run ch03
python -m harnesslab.cli run ch03 --json
```

The JSON form is useful for seeing every policy decision and artifact. Look for these expected outcomes:

- An allow decision for distinct per-agent identities.
- An allow decision for distinct per-task identities.
- An allow decision for the reader credential against `internal-ticketing`.
- A deny decision for the same reader credential against `internal-repo`.
- A deny decision for an expired credential.
- An allow decision for the patcher delegation chain.
- A deny decision after patch credential revocation.
- A warning when the run is paused for credential rotation.
- A deny decision for the old paused credential after revocation.
- An allow decision for the fresh resumed credential.
- Denials for cross-tenant resource access and PII repository patching.
- An escalation for privileged deployment risk.

If any of those disappear, the chapter should not be considered complete. The point is not merely that a safe path works. The point is that unsafe paths fail in predictable, inspectable ways.

## Design Notes

The implementation intentionally avoids dependencies and live integrations. It does not call a real identity provider, does not contact a ticketing system, and does not read secrets. That keeps the lab portable. The core shapes still resemble production patterns: identity objects, credential issue and verify operations, intent contracts, tool gateway checks, runtime checkpoints, and policy decisions.

The artifacts avoid raw credentials. This is worth copying into real systems. Security evidence often becomes a secondary data store, and secondary stores are a common place for secrets to leak. A trace can record the credential audience, subject shape, delegation chain, and credential generation without storing the token itself.

The lab also keeps resource scope chapter-local. The core framework owns shared abstractions, while chapters own scenario-specific adapters. A real product would likely centralize resource authorization in a policy engine, but here the small helper makes the teaching point without changing shared files.

Finally, the chapter treats denial and escalation as successful harness behavior. That can feel odd if you are used to tests where every operation should allow. Secure harnesses need expected failure paths. A blocked wrong-audience token, a revoked credential, and an escalated privileged deploy are all signs that the control plane is doing its job.

## Applying The Pattern

When adapting this chapter to a real agent system, start by inventorying the principals. Identify the durable agents, the tasks they perform, and the services they call. Replace shared service accounts with task-bound credentials where possible. Bind every credential to an audience. Keep lifetimes short. Record delegation chains. Make revocation testable. Rotate credentials after pauses and before resumes.

Next, connect identity to authorization. Do not stop at "this agent is authenticated." Ask whether this agent, for this task, with this delegation chain, can call this tool, on this resource, with this data class, at this risk level, for this amount of time. That sentence is long because the real control is multi-dimensional. A harness makes it manageable by turning each dimension into a check.

Then make the evidence useful. Logs should show task ids, agent ids, audiences, delegation chains, decision reasons, and control names. They should not show tokens. When a reviewer asks why a call was allowed or blocked, the answer should be visible in the decision record.

The strongest identity systems are boring in the best way. Credentials expire. Wrong audiences fail. Revoked subjects fail. Delegation chains are visible. Resumed work gets fresh authority. Tools and resources are scoped to the task. Chapter 3 gives students a small, runnable version of that posture so they can recognize and build it in larger systems.
