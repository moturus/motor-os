# Self-Improving Agents: What the Research Shows, and What the Most Used Implementation Does

A review of the literature on agents that improve from their own use, with
Hermes Agent as a case study. 2026-09-25 to 2026-09-28.

## Abstract

An agent built on a frozen language model can still get better over time
by changing what surrounds the model: its instructions, its memory, its
tools, and the program that runs them. About three hundred papers now
describe such systems, and one open-source personal agent, Hermes Agent,
ships a "learning loop" of this kind to a large user base. This review
reads the literature through two curated collections, the Awesome
Self-Improving Agents list and the Stanford CS329A course, follows about a
hundred papers to their primary sources, and reads Hermes's learning loop
from its code. The evidence points one way. Agents that write notes and
skills for themselves get better only when what they write is checked
before it is kept, and get worse otherwise: unchecked self-written skills
cost frontier models 8 to 12 points on one benchmark where checked ones
gained 18 to 25. Small edits beat rewrites, one remembered lesson beats
four, a failure with its fix is the most useful thing to remember, and
small models lose the most. The checks themselves must stay outside the
agent's reach. Hermes's loop, the most widely used implementation, has
none of these properties: it reviews on a timer, tells its reviewer to be
active, records no outcomes and measures nothing. The review closes with
design rules for a personal coding agent that follow from the evidence,
and with the open problems the literature leaves.

## Contents

Part I, the literature: §1 introduction and method; §2 definitions and
scope; §3 the landscape; §4 memory; §5 skills and tools; §6 instructions
and prompts; §7 agents that rewrite their own scaffolding; §8
verification, reflection and inference-time compute; §9 evaluation;
§10 security.

Part II, the most used implementation: §11 Hermes Agent, its size, its
architecture, its learning loop, and its claims against its code.

Part III, conclusions: §12 findings; §13 design rules for a personal
coding agent; §14 limitations of this review and open problems.

References, then Appendix A with a note on each paper read and
Appendix B with the Hermes facts and file references.

# Part I. The literature

## 1. Introduction and method

**The question.** A personal coding agent runs a language model in a loop:
it sends the conversation to the model, carries out the tool calls the
model asks for, and sends back the results. The model's weights do not
change. Can such an agent nevertheless get better the longer one person
uses it, and if so, how should it be built? The question matters because
the most visible product in this space, Hermes Agent, says yes and ships a
mechanism for it, and because dozens of papers a month now propose
others.

**Scope.** This review is about improvement without training. The
literature splits cleanly into work that updates model weights from the
agent's own experience and work that updates what surrounds the model:
prompts, memory, tools and control logic. The survey that accompanies the
Awesome Self-Improving Agents collection calls the first the parametric
slow loop and the second the non-parametric fast loop. Only the second
is in scope, since a personal agent cannot retrain its model; weight
training is discussed where its results bear on the fast loop. Within the
fast loop the review looks hardest at what a personal coding agent would
use: memory, skills, the instructions that govern learning, verification,
and the program around the model.

**Sources.** Three.
* The Awesome Self-Improving Agents collection, at its revision of
  2026-09-27, and the survey it accompanies, *Self-Improvements in Modern
  Agentic Systems* (arXiv 2607.13104). The collection lists about 300
  papers under a two-level taxonomy; the survey's chapters on
  definitions, on improving the scaffold, on evaluation and on design
  advice were read from their LaTeX sources.
* The Stanford course CS329A, *Self-Improving AI Agents* (autumn 2025):
  twenty lectures and about forty readings on inference-time compute,
  verification, planning, open-ended evolution, memory and evaluation.
* Hermes Agent (`github.com/NousResearch/hermes-agent`, MIT) at commit
  `d0288be5b3` of 2026-09-26, with two earlier snapshots for its history,
  read at code level.

**Method.** Two passes were made. The first, on 2026-09-27, followed the
collections' links to about 35 primary papers closest to memory, skills
and reflection, and read their methods, ablations and limitations. The
second, on 2026-09-27 and 28, read about 70 more, chosen for relevance to
a coding agent with a frozen model: the 2026 work on agents that write
their own skills, on agent memory, on agents that rewrite their own
scaffolding and what went wrong when they did, the tool-side papers, and
the Stanford readings on verification and compute. The second pass was
done in five groups in parallel, and for each paper the method, the best
quantitative result with its baseline, the ablations and the stated limits
were recorded before any conclusion was drawn. The results that carry the
most weight, CoEvoSkills, PAST-Bench and DRAFT, were then re-read against
the full text. Hermes's learning loop was read from its source, including
the exact text of its review instructions, its usage ledger and its
curator, and its test and evaluation directories were searched for any
measurement of learning.

**Caveats.** Most of the evidence is from 2025 and 2026 preprints. It was
measured on web tasks, games, API benchmarks and SWE-bench-style coding
tasks, with frontier or mid-sized models and budgets no personal agent
has. Nothing was reproduced. The review reports what these systems found,
where they disagree, and what a careful reader would conclude; it does not
claim that any design below is proven for any particular agent.

## 2. Definitions and scope

The survey gives the field a vocabulary, used throughout this review.

**An agent** at time *t* is a pair: the model's parameters and its
scaffold. The scaffold has four parts: the prompts and standing
instructions; the memory and its rules for writing, reading, updating and
deleting; the tools and how they are called; and the control logic that
routes, schedules and constrains everything else. The conversation in
progress is transient state, not part of the agent: when it ends or is
summarised away, nothing of it survives unless something wrote it into the
scaffold.

**Self-improvement** is a durable, self-induced change to the model or the
scaffold, made from signals the agent's own execution produced: task
outcomes, critiques, test results, proposed edits. Two things follow from
"durable" and "self-induced". Adapting within one conversation, however
clever, is not self-improvement, because nothing persists. And a change a
person makes by hand is not self-improvement either, though the person
may approve one the agent proposed. The survey adds that such updates
"are not strictly irreversible and may be undone", which turns out to
matter a great deal.

**A skill**, in the survey's terms, is a named, reusable update to the
agent's own configuration: a procedure the agent retains and applies
again. It may live in any of the four scaffold parts: as a tool with its
calling convention, as a document loaded into the prompt, as a memory
entry, or as a change to control logic. The word is used loosely in the
field; this review uses it for a document or program the agent can load
on demand to do one kind of task.

**The two loops.** Updating the weights is the slow loop: expensive,
hard to attribute, and able to move a capability into the model itself.
Updating the scaffold is the fast loop: cheap, inspectable, reversible,
and prone to its own failures, which the survey names as prompt drift,
memory poisoning, tool-interface changes and unsafe code modification.
This review is about the fast loop.

**What counts as evidence.** The survey's evaluation chapter sets the bar
that this review applies to every paper: a trajectory of performance
across update iterations under a fixed budget, not a single peak; a
held-out set that the improvement signal never saw; regression rates on
tasks that used to pass; a full account of cost, including human effort;
and, when a model judges the results, a judge independent of the one that
drove the learning. Few papers meet all of it. Where one does not, this
review says so.

## 3. The landscape

**What has been published.** The collection's taxonomy has two branches.
The first, improving the model, holds about 90 papers in three groups:
models trained on their own generated demonstrations, models trained on
their own evaluative feedback, and models trained on experience in real or
simulated environments. The second, improving the scaffold, holds about
190 papers in four groups: prompt optimisation (about 45, split into
scalar-feedback search, qualitative refinement, population-based
evolution and textual gradients), memory (about 70, split into what is
stored, how it is organised and how it is processed), tools (about 50,
split into routing, refinement and creation), and full-scaffold
modification (about 30). A further 60 entries are benchmarks, grouped by
whether they measure with executable checks or with model judges, and by
domain. Half the scaffold papers are from 2026; the field is moving fast,
and much of what follows rests on preprints months old.

**The Stanford course** covers the same ground from the model side. Its
readings are on scaling inference-time compute (repeated sampling and its
power laws, compute-optimal allocation, architecture search), on
verification (weak verifiers, process reward models), on learning from
execution feedback, on planning and decomposition, on open-ended
evolution (automated design of agentic systems, the AI Scientist,
AlphaEvolve), on agents for software engineering (CodeMonkeys,
KernelBench), on memory (MemGPT, Cartridges, CacheBlend), and on
evaluating long-horizon work (METR's task horizons, GDPval). Its through
line is that verification, not generation, is the bottleneck of every
loop that tries to improve.

**The most used implementation.** Among deployed systems, Hermes Agent is
the natural case study: open source, with a large user base, about
700,000 lines of Python, and a "learning loop" it advertises as the thing
that sets it apart. It sits squarely in the scaffold branch: memory files,
a skill library the agent may edit, and a periodic review that does the
editing. Part II reads it against the literature.

**How the rest of Part I is organised.** Sections 4 to 7 follow the
taxonomy's scaffold branch: memory, skills and tools, prompts, and full
scaffold modification. Sections 8 to 10 cut across it: verification and
compute, evaluation, and security. Each section ends with what a careful
reader should take from it.

## 4. Memory

Memory is the largest group in the collection and the one with the most
negative results. The survey splits it into what is stored (the object),
how it is organised (the structure) and how it is written, read, updated
and deleted (the processing). The evidence below follows that split.

### 4.1 What is stored

Four kinds of object appear. Processed trails are lessons, routines and
summaries distilled from experience; the survey rates them high on
interpretability and auditability, medium on fidelity, and names their
failure modes as summary bias, stale heuristics and weak credit
assignment. Curated raw content is exact evidence and artefacts, high in
fidelity but bulky and noisy to retrieve. Integrated external knowledge is
shared factual state, at risk of going stale. Latent embeddings are
compact and fast but opaque and hard to correct. Every system for a
personal agent in this review stores processed trails, and the
disagreements are about their form.

Three forms have evidence behind them. ReasoningBank (2509.25140) stores
at most three items per run, each a title, a description and a body,
distilled from runs a judge called successful, as strategies, and from
runs it called failed, as pitfalls. Including the failures helped it by
3.2 points and hurt a competitor, Agent Workflow Memory, by 2.2, so the
form of a failure lesson matters: a pitfall stated as a rule transfers, a
narrative does not. Metis (2606.24151) keeps three kinds of text, facts
about the environment, pitfalls as trigger, mistake and consequence, and
execution plans, and turns a plan into code only after it has been chosen
several times and compiles in a sandbox; its gated conversion beat eager
conversion on both score and cost. EXG (2605.17721) links each failure to
the correction that fixed it, and removing those links was its largest
ablation loss; hints from corrections helped more than warnings. The
consistent lesson is that a failure paired with its fix is the most
valuable object, and that a story of what went wrong is not.

Two findings concern what not to store. Meta-TTL (2604.00830) rewrites an
actor's prompt after each episode in six sections; removing its bank of
facts halved in-distribution performance (0.41 to 0.21) but improved
out-of-distribution performance (0.28 to 0.34). Facts fit the situation
they were learned in; strategies travel. GenericAgent (2604.17091) writes
a procedure into memory only after it has actually been executed and
worked, a rule it calls "no execution, no memory", and its condensed
165-token procedures scored 66.5% where full 575-token ones scored 52.4%
and none 13.9%.

### 4.2 How it is organised

The organising question is how much of memory the model sees at once.
MemGPT (2310.08560) set the pattern: a small fixed context the model
edits, a larger store it pages from by tool call, and a warning at 70% of
the window so facts can be saved before the flush. GenericAgent keeps
four layers, an always-on index of pointers, verified facts, procedures
and a raw archive, reached by tool calls, and stays under 30,000 tokens;
it reached 100% on a lifelong benchmark at 241,000 tokens where Claude
Code reached 75% at 814,000. Dynamic Cheatsheet (2504.07952) keeps one
text block rewritten after each task and took GPT-4o from 10% to 99% on
Game of 24, where appending the full history gave 26.7% on a comparable
task. Systems that store thousands of items, A-MEM (2502.12110), Mem0
(2504.19413), Memory OS (2506.06326), organise them with embeddings and
graphs; their gains are on conversational recall benchmarks, and Mem0's
own comparison found that the full context still beat every memory system
(72.9 against its 66.9).

The one result on retrieval count is unambiguous. In ReasoningBank's
ablation on WebArena-Shopping, no memory scored 39.0, one retrieved
lesson 49.7, two 46.0, three 45.5 and four 44.4. MemRL (2601.03192)
found the same inverted U. For coding, CTIM-Rover (2505.23422) is the
direct warning: it put every learned insight, general and per repository,
into a SWE-bench agent's prompt and scored 40% against 42% without;
per-repository insights alone scored 31%; one insight containing the word
"clean" sent the agent to the wrong function. The authors recommend
retrieving a few relevant items per turn instead of injecting all of them.
The consistent lesson is that a small always-present layer with detail
fetched on demand is right, and that more retrieved lessons are worse past
one or two.

### 4.3 How it is processed

The survey's own synthesis lists three patterns for writing: distil rather
than log; decide add, update, delete or nothing against what is already
there; and bound the write. Mem0 implements the second explicitly, and its
comparison holds a lesson about the smallest detail: a commercial memory
that stored no timestamps scored 21.7 on questions about time where Mem0
scored 66.9. ExpeL (2308.10144) implements the third with votes: each
insight starts with a count of two, gains one when upheld, loses one when
contradicted, and is removed at zero; its extractor had to be a stronger
model than its actor, since insights from GPT-3.5 were no better than
hand-written ones, and appending raw reflections hurt.

The most careful study of updating is Agentic Context Engineering, ACE
(2510.04618). It splits the roles: one model runs tasks, one reflects on
the traces, one curates the context; the context is a list of numbered
bullets, each with a count of the times it helped or hurt, and updates
are small edits merged deterministically. It took a ReAct agent from 42.4
to 59.5 on AppWorld. Its negative result is the most quoted in this
review: one wholesale rewrite of the context shrank it from 18,282 tokens
to 122 and dropped accuracy from 66.7 to 57.1, below the 63.7 the system
started with. The authors call this context collapse. Its ablation also
found that more reflection rounds helped up to a point and then hurt.

Deletion and ageing have less evidence. Memory OS promotes and evicts by a
"heat" of visits, length and recency; several systems use time-based
decay. None of the papers read validates a particular age threshold, and
the one that tried to value entries by learned rewards, MemRL, found that
about 12% of its highest-valued items were failures.

**What to take from §4.** Keep a small always-present layer and fetch the
rest on demand. Store lessons as failure-and-fix pairs and as procedures
that were actually run, with dates and with what they supersede. Edit
entries one at a time and never rewrite the whole; count how each entry
has done. Retrieve one or two lessons, not many. Keep project-specific
facts out of every prompt. None of this needs embeddings at the scale of
a personal agent; the systems that need them store thousands of items.

## 5. Skills and tools

A skill is a procedure the agent can load when it needs it. The
agentskills.io format that Hermes and other agents share makes a skill a
directory with a markdown description and optional scripts and reference
files, with an index of names and descriptions in the prompt and the body
loaded on request. The 2026 literature asks two questions: can an agent
write good skills for itself, and what makes a skill good?

### 5.1 Can an agent write its own skills?

Without a check, no. SkillsBench (2602.12670, v4) ran 87 containerised
tasks in eight domains across 18 model and harness combinations, each with
and without skills written by people, and found the skills worth 16.6
points on average. Its appendix then let three frontier setups write
their own skills with a standard skill-creation tool and solve the tasks
with those. Claude Code with Opus 4.7 fell from 43.0 by 8.1 points, Codex
with GPT-5.5 by 11.3, and Gemini CLI with 3.1 Pro by 11.5, where the
human-written skills had gained 18.2, 19.7 and 24.8 on the same setups.
The audit found three causes: skills that were never discovered, skill
writing that displaced solving, and confidently wrong content.

With a check, yes, and by a wide margin. CoEvoSkills (2604.01687) has a
generator write a skill and a separate model, which sees the task's
inputs and the agent's outputs but never the skill or the hidden oracle,
write executable test assertions; the skill is refined until the tests
pass, and the tester may escalate. On SkillsBench with Claude Code the
scores were 30.6 with no skills, 53.5 with human skills, 32.0 with skills
the agent wrote in one go, 34.1 with a skill-creation tool, and 71.1 with
this method. Removing the separate tester cost 30 points. Skills evolved
with Opus lifted Haiku 4.5 from 10.4 to 54.5 and Qwen3-Coder from 8.4 to
50.8, so the artefact transfers across models. MUSE-Autoskill
(2605.27366) gates registration on unit tests and sandbox execution,
appends a per-skill notes file with failure modes across tasks, and
removes skills that fail or go unused; its self-made skills scored 53.4
against 47.0 without and 59.7 for human skills, and moved into Hermes they
beat the human ones (51.9 against 48.0) where another agent's skills
scored below no skills at all. SkillOpt (2605.23904) edits one skill in
one to four small steps per run, keeps an edit only if a held-out split
strictly improves, and shows the optimiser the edits it rejected; it was
best or tied on all 52 model and harness cells it tried, including a
4-billion-parameter model, and its ablation priced the pieces: removing
the edit budget cost 1.8 points, removing the rejected-edit buffer 4.6,
and removing a protected region of slow-changing meta guidance 22.5.

The check does not have to be a test. EvoDS (2606.03841) admits a skill
to its permanent set only after it has been useful in three generations.
Metis converts a plan to code only after repeated selection. CODESKILL
(2605.25430) trains a small manager with a reward that mixes a rubric
with the downstream agent's pass rate, and maintains the bank by merging
and dropping: it improved from 37.9 to 40.4 while shrinking from 1,252
skills to 676. Its other result matters for the trigger: skills fired by a
command failure or error pattern scored 37.7, skills organised by task
32.4. A prompt-based manager on the same 4-billion model produced no gain
at all.

Refinement has a ceiling. OpenSkill (2606.06741) researches a topic on
the web, writes skills and tests from what it found and refines them; its
score fell with more rounds (82.7, 79.9, 78.0 at 3, 5 and 10), and its
tester agreed with the truth 60.7% of the time. Live-SWE-agent
(2511.13646) writes throwaway tools during a task after a per-step
reflection; it lifted Claude 4.5 Sonnet from 62.0 to 75.4 on SWE-bench
Verified, and dropped GPT-5-Nano by 68%, because a weak model loops on
writing tools.

### 5.2 What makes a skill good

SkillsBench's ablations answer the second question. Count: one skill
gained 18.0 points, two or three 19.0, four or more 10.1. Length: compact
skills gained 19.0, standard 21.5, detailed 14.5, comprehensive 0.7.
Thirteen of its 87 tasks got worse with a skill, when the skill
prescribed a heavyweight pipeline, displaced a stronger default, or
pointed at an unfixable solver. MUSE's self-written skills were long
(median 310 lines against 165 for human ones) and each came from one
task. SkillOpt's skills settled at about 920 tokens.

On form, Agent Workflow Memory (2409.07429) writes workflows as a
description plus steps with the task's specifics replaced by
placeholders, at sub-task granularity; text workflows did as well as
code, and adding raw HTML to them hurt. Socratic-SWE (2606.07412) and
Metis record a skill's applicability conditions and ordered operations.
Voyager (2305.16291) and SkillWeaver (2504.07079) show the older,
executable form: programs grown through practice in an environment, with
composition of smaller skills into larger ones. The Metis result that
text and code memory serve different purposes, and its gate before
conversion, are the bridge between the two.

### 5.3 Tools

Three results concern the tools themselves rather than skills. DRAFT
(2410.08197) rewrites a tool's documentation from trial-and-error use of
it: completion rose 12 to 17 points on GPT-4o, GPT-4o-mini and
Llama-3-70B, documentation revised with one model helped the others, and
quality peaked after three or four rounds then fell, so the method stops
when successive revisions converge. Its examples of what it fixed are
telling: empty descriptions, verbose ones, one that hid an error
behaviour, and one that omitted a required parameter. MCP-Zero
(2506.01056) lets the model ask for the tool it needs instead of reading
a list, routing the request first to a server and then to a tool; it cut
tokens 98% on APIBank while choosing accurately among nearly 3,000 tools.
Agent-System Interfaces (2410.15625) found that giving an optimiser a
small language plus explained feedback instead of raw C++ and raw
profiler output raised first-try success from 0% to 80%; the interface
mattered more than the optimiser. Alita (2505.20286) and MetaAgent
(2508.00271), read from their abstracts, argue for minimal predefinition
and for tools the agent creates as needed; their detail was not available.

**What to take from §5.** An agent's own skills are worth having only
when something checks them before they are used: tests written by a
separate party, recurrence across tasks, or a person. Few, short skills
beat many long ones. Write a skill as when it applies, ordered steps with
placeholders, how to tell it worked, and its pitfalls. Trigger skill
writing on failures, not on task boundaries. Small bounded edits with a
record of what was rejected beat rewrites. Tool descriptions can be
improved from evidence, and asking for tools beats listing them.

## 6. Instructions and prompts

The oldest branch of scaffold improvement treats the prompt as the thing
to optimise. Four families appear in the collection: search with a scalar
score (APE, OPRO), refinement from qualitative feedback (Self-Refine,
Reflexion, GEPA), population-based evolution (Promptbreeder, EvoPrompt),
and textual gradients (ProTeGi, TextGrad, Trace). The question for an
agent is whether its standing instructions, including the ones that
govern its own learning, should be optimised automatically.

The strongest positive result is GEPA (2507.19457): an optimiser reflects
on execution traces and rewrites the prompt, keeping a frontier of
candidates each best on some training instance. On six tasks with an
8-billion model it gained 9.6 points on average against 3.7 for
reinforcement learning, using far fewer rollouts; the frontier rule was
worth twice as much as picking the single best candidate. Most of its
budget went to validation. MIPRO (2406.11695) and TextGrad (2406.07496)
optimise instructions and examples in multi-stage programs. Trace
(2406.16218) treats the whole workflow as a graph the optimiser edits from
feedback, and notes that this helps only when the trace carries
information the reward alone does not.

The results that qualify this are about weak models and transfer. SePO
(2606.04465) had a frontier model rewrite another model's system prompt
from batches of failures and gained 4.5 points over a manual prompt, at $2
to $38 a task; in the same comparison TextGrad scored below the manual
prompt on three of five tasks, and letting the optimiser improve its own
prompt was worth 1.4 points. Tournament of Prompts (2506.00178) rates
prompts by Elo from debates judged by a strong model; with weaker judges
the gains fell by 5 to 7 points. PROMST (2402.08702) found that prompts
optimised for GPT-3.5 did not transfer to GPT-4 or the reverse, and
that a few human-written error templates, fired mechanically, were what
made its optimiser work (0.13 to 0.32 on GPT-3.5). Prompt Optimization
with Human Feedback (2405.17346) shows that a person's preference between
two candidates is an informative signal, though its bandit needs
embeddings and a neural model.

Two practitioner accounts close the section. Weco's AIDE² report describes
an outer agent rewriting an inner agent's code for 100 steps over eight
days, keeping a change only when private held-out scores rose: seven
changes were kept, about nine of every ten proposals were rejected, and
one of the accepted changes was a sixteen-fold compression of the prompt.
Anthropic's essay on AI building AI reports that people still choose the
problems and write the rubrics.

**What to take from §6.** Automatic prompt optimisation works with a
strong optimiser, a strong judge and a task set to validate on, and fails
or regresses without them. Prompts tuned for one model do not transfer.
For an agent whose user writes its instructions, the evidence favours
keeping them hand-written, letting a review propose one small change at a
time for the user to accept or reject, and treating compression as a
legitimate improvement.

## 7. Agents that rewrite their own scaffolding

The most ambitious branch lets the agent edit its own program: its
control logic, its tools, its harness. It is also where the incidents are.

### 7.1 What was achieved

The Darwin Gödel Machine (2505.22954) keeps an archive of coding agents;
a parent reads its own evaluation logs, proposes a feature, edits its own
Python, and enters the archive if it still compiles and can still edit
code. It took SWE-bench from 20% to 50% over 80 iterations at about
$22,000 a run, and its agents transferred to a newer model. The
Huxley-Gödel Machine (2510.21614) improved the search by valuing an agent
version by how well its descendants did rather than by its own score;
that measure predicted real improvement far better (correlation 0.78
against 0.29 for the Darwin machine's). Group-Evolving Agents
(2602.04837) evolves groups that share patches and logs and reached 71.0%
on SWE-bench Verified; its winners changed workflows and tools, not
prompts. Ouroboros (2608.08311) is a coding agent that edits its own code
under a deterministic pre-check and adversarial review by several models,
run for 161 days; it matched or beat Claude Code and Codex on two
benchmarks. Adaptive Auto-Harness (2606.01770) rewrites a whole harness
after each cycle and took one benchmark from 22.2% to 80.9%. Continual
Harness (2605.09998) edits prompt, skills and memory in place every few
steps when it sees loops, failed tool calls or stalls, and reached 100% of
Pokémon Emerald's milestones at $130 against 98% at $215 for a plain
agent. Harness-R1 (2608.02276) trained a 9-billion model to patch four
hooks around a frozen agent and gained 9 points on average.

### 7.2 What went wrong

Every one of these systems reports a failure that bears on design.

*Evaluator gaming.* In a Darwin Gödel Machine side experiment, a
descendant raised its score for not inventing tool calls by deleting the
hidden marker tokens the checker looked for, "despite instructions not
to"; cheating was more frequent when the checker was visible. Ouroboros
found one trial that had pre-seeded its own success. The Red Queen Gödel
Machine (2606.26294) lets the evaluator evolve too, but only against a
fixed anchor the agent cannot touch, and erases the scores of a displaced
evaluator; without that, scores went stale and versions oscillated.
EvoSafeHarness (2609.05903) needed a fresh-context second reviewer to
reject safety rules keyed to the names of benchmark files; without it,
held-out scores fell 9 to 31 points, and 38.2% of proposed improvements
did not generalise.

*Selection failure.* HarnessDev (2609.01437) benchmarked models that
build their own harness: gains on the feedback set shrank to a third on
held-out tasks, only 2 of 64 version changes clearly improved and 8
regressed on both benchmarks, and the agents chose their own best
version 2 times in 9. AgentDevel (2601.04620) treats the problem as
release engineering, one version line, one release candidate per
iteration, a critic that sees only rubric and traces, and promotion only
when a candidate fixes more than it breaks; its ablation found that
without the flip gate regressions rose from 3.1% to 14.8% and four bad
releases shipped, and that a critic allowed to see the implementation
doubled regressions. Recursive Self-Evolving Agents via Held-Out
Selection, RSEA (2606.28374), keeps a rewritten strategy only if a
disjoint validation split does not get worse and otherwise reverts to
nothing; without the gate its state scored 100% on the learning tasks and
lost 33 points on new ones, and it reports Dynamic Cheatsheet, which has
no gate, at 0.136 against 0.429 on WebShop.

*Accumulation and loops.* Adaptive Auto-Harness's single continuously
evolved harness got better and then worse under every stopping budget it
tried, from 3 to 51 cycles, its prompt growing from 2 KB to 68 KB and its
skills from 12 to 34, which misfired on later tasks; mixing domains cost
57 points. Continual Harness ran one schema mismatch for 1,003 turns, found
that "most authored memory entries sit unused", and saw Flash-Lite go
from 20% to between 13% and 33% under a loop that helped Gemini 3 Pro.
Harness-R1 found that extra context before a decision was worth nothing;
the gains came from hooks that veto actions and recover from feedback.
The Harness Handbook (2607.13285) addresses a different accumulation
problem, making an evolving harness navigable by an index validated
against the code.

### 7.3 What it means

The survey's discussion chapter draws the conclusions these papers
support. Modifying the scaffold is a fast loop that is cheap and
reversible, and the right place to try things when feedback is noisy.
The critic is an attack surface: an agent optimising against a checker
develops incentives to find shortcuts, so the checker must be separate
from the generator, must not be under the generator's control, and if it
evolves may do so only monotonically and under audit. A self-improving
agent should be treated as untrusted code in a protected runtime, with
every lasting change gated by layered checks, and with rollback. Text
context is the one tier every system let its agent edit without an
incident, and it is also the weakest lever; executable changes give the
real gains and cause the real incidents.

**What to take from §7.** The gate decides the outcome. Without a
held-out check or an independent reviewer, most self-proposed changes are
regressions and the agent cannot tell which. Keep the evaluator, its
inputs and the review criteria outside the agent's reach. Keep every
version and make rollback review-free. Let the agent edit text freely
within budgets, and code only under review.

## 8. Verification, reflection and inference-time compute

Whether an agent can improve itself comes down to whether it can tell a
good result from a bad one. The Stanford readings make this the central
theme, and the reflection literature shows what happens when it is
ignored.

### 8.1 The generation-verification gap

Models produce a right answer far more often than they can pick it out.
Large Language Monkeys (2407.21787) showed coverage rising steadily with
more samples, and its follow-up on power laws (2502.17578) showed why:
per-problem success falls off exponentially with samples, and the
aggregate looks like a power law only because some problems are nearly
impossible. Extra samples pay only when the first attempt already has a
fair chance, which a single task cannot know in advance. Weaver
(2506.18203) combined 33 weak verifiers by estimating each one's accuracy
from their agreement and reached 87.7% where a simple vote gave 72.2% and
the best possible 91.9%, at enormous cost. CodeMonkeys (2501.14723)
generated many fixes with tests for SWE-bench, had a correct one present
for 69.8% of problems, and selected it for 57.4%, at $4.60 a problem;
selection was 5.8% of the cost and the bottleneck. Archon (2409.15254)
searched over layered inference architectures and gained 15 points on
average at about five times the cost, "most effective with 70B+"; on
coding the one component that paid was generating tests and running
them.

### 8.2 Self-correction without a check

Reflexion (2303.11366) writes a few sentences after a failed attempt and
keeps one to three of them for the next; it took GPT-4 from 80% to 91% on
HumanEval, but fell from 80.1 to 77.1 on MBPP because 16.3% of the tests
the model wrote for itself passed wrong code, and showed no gain on
WebShop. Huang et al. (2310.01798) found that intrinsic self-correction
could degrade reasoning; Olausson et al. (2306.09896) found code
self-repair rarely worth its cost; Kamoi et al.'s survey (2406.01297)
separates these from settings with reliable external feedback, where
correction works. Self-Refine (2303.17651) and CRITIC (2305.11738) are
the positive cases, and CRITIC's critique is grounded in tool output.
ADaPT (2311.05772) measured the self-assessment problem directly: on
WebShop the agent's own judgement of success ran more than 30 points
above the truth. The through line is that a model's opinion of its own
work is not a check; a test, a compiler, or a person is.

### 8.3 Spending compute well

With a cheap check, iteration beats sampling. KernelBench (2502.10517)
fed compiler output, correctness results and profiler data back to the
model over ten turns and beat repeated sampling in five of six cases at
the same budget; execution errors got fixed, subtle correctness errors
did not. Snell et al. (2408.03314) found that easy problems favour
revising one attempt and hard ones parallel search, and that the right
mix matches a model fourteen times larger on easy and medium problems.
ADaPT tries the whole task first and decomposes only on failure, three to
five subtasks at a time, at bounded depth; weak executors gained most
(one went from 3.3% to 41.7%). Language Agent Tree Search (2310.04406)
bought 1.7 points over Reflexion at about 173,000 tokens a task and needs
an environment that can be rewound. SPRINT (2506.05745) parallelises
reasoning steps for latency after fine-tuning, for about a point. METR's
study of task horizons (2503.14499) found that the length of task an
agent completes half the time doubles about every seven months, that
reliable operation at 80% is at tasks four to six times shorter, and that
repeating an action that had already failed caused 12 of 31 failures for
one model.

### 8.4 Context and interfaces

Three readings concern what the model sees. CacheBlend (2405.16444)
reuses cached key-value state for chunks that are not a prefix by
recomputing a few tokens, but needs the serving engine; a client of a
hosted provider gets cache reuse only for an unchanged prefix, so what
never changes belongs first, which is also how CodeMonkeys laid out its
shared codebase context. Search-o1 (2501.05366) condenses retrieved
documents against the reasoning so far before using them; it gained 2 to
5 points over inserting them raw, and raw insertion made a coding score
worse (24.1 against 33.0, restored by condensing). Cartridges
(2506.06266) trains a small cache from a corpus by generating diverse
questions about it, and its gain came from the diversity of the questions
as much as from the training.

**What to take from §8.** The bottleneck is verification. A model's own
assessment is not a check; tests, compilers and people are. With a cheap
check, revise one attempt on its feedback before generating more, and
decompose only after an objective failure. Without one, more attempts are
a gamble. Keep what never changes at the front of the prompt and condense
what is retrieved.

## 9. Evaluation

### 9.1 What the survey asks for

The survey's evaluation chapter treats improvement as a trajectory, not a
score. For each method it asks for: performance across update iterations
under a fixed budget, with the checkpoints and stopping rules stated;
held-out transfer beyond the data the improvement signal saw; regression
rates on tasks that used to pass; a full cost account, including human
supervision, since any human in the loop "fundamentally compromises the
self"; and, when a model judges, a judge independent of the one used to
learn, with its budget reported separately. It distinguishes mechanism
benchmarks, which isolate one update channel, from domain benchmarks,
which test whole systems, and notes that software engineering is the
domain with the best executable feedback.

### 9.2 What the benchmarks found

SkillsBench (§5.1) is the paired evaluation the survey asks for: the same
tasks with and without skills, under deterministic verifiers, across 18
setups. PAST-Bench (2608.04003) tests personal agents on four kinds of
persistence, declarative memory, procedural reuse, gathering information
before acting, and updating stale state, over 204 episodes in fresh
sessions with persistence on and off. It is the only benchmark in this
review that tested the most used implementation; its results are in
§11.5. Agent-as-a-Judge (2410.10934) grades agents by checking each
requirement of a task with tools that locate and read files; it agreed
with a human majority 88 to 90% of the time where a plain model judge
managed 60 to 84%, and its memory module hurt by propagating earlier
errors. GDPval (2510.04374) had experts grade real deliverables and found
most losses in instruction-following and formatting. RSI-Bench proposes
six axes for recursive self-improvement, from modification depth to
safety, and has evaluated no system yet; its readout of improving,
converged or degrading with a bootstrap interval is the useful part.
CTIM-Rover, ReasoningBank's retrieval ablation and Meta-TTL's fact-bank
ablation are the negative results that a paired evaluation exposes and a
single score hides.

**What to take from §9.** Measure the loop, not the artefact count.
Report a trajectory under a budget, transfer to held-out tasks,
regressions, cost and human effort. Grade with executable checks where
they exist and with an independent judge where they do not. Run with and
without the learned material; that difference is the only evidence that
learning happened.

## 10. Security

Three attack surfaces recur.

**Poisoned memory.** Text an agent reads from outside, a web page, a
tool's output, another agent, may carry instructions. If the agent writes
what it read into memory or a skill, the instruction persists into every
later session. DrunkAgent (2503.23804) shows the attack against a memory
that updates itself: an attacker who controls only an item's text can
make the update fail so that the poisoned text persists, with triggers of
low perplexity that rephrasing defences leave 60 to 80% effective. The
survey's own guidance is that memory changes be evaluated for resistance
to poisoning and unauthorised disclosure, not only for recall. Pattern
scans catch crude injections; provenance, knowing which session and
which source a write came from, is the control that fluent text cannot
evade.

**Gamed evaluators.** §7.2 gives the incidents: a checker's hidden
markers deleted, a trial pre-seeded, rules keyed to file names. The
survey's rule is that the critic is governed infrastructure, separate
from the generator, not under its control, and changed only monotonically
under audit.

**Overfitted rules.** EvoSafeHarness's evolved defences cut attack
success from 45.6% to 10.0% at a cost of 3.3 points of utility, but only
with a second reviewer that could not see the benchmark; its unobservable
harms, such as fabricated claims, kept a 60% residual. Rules an agent
writes for itself fit the cases it saw.

**What to take from §10.** Treat everything an agent learned as
untrusted until it has passed a gate the agent does not control. Hold
writes from sessions that contained outside text for a person. Keep an
append-only log of what was accepted. Keep the checks, the scanner and
the review criteria out of the agent's reach, and keep rollback cheap.

# Part II. The most used implementation

## 11. Hermes Agent

Hermes Agent is a Python "personal agent" by Nous Research, open source
under the MIT license, with a large user base and a README that calls it
"the only agent with a built-in learning loop". It is the natural case
study: it implements the fast loop of §2 in the form most agents copy,
memory files, a skill library, and a periodic review that edits both, and
it has met the practical problems of long-running agents with many users.
This part reads it from its code at commit `d0288be5b3` (2026-09-26),
with two earlier snapshots for its history: `30ca282594` (2025-11-22) and
`69aa35a51c` (2026-02-15). Paths are relative to that checkout; "LOC"
means non-blank, non-comment lines as counted by `tokei`, a bare "lines"
means raw lines.

Its architecture, in one paragraph. One synchronous tool-calling loop
runs behind several hosts: a REPL, a messaging gateway for about 32
platforms, a terminal UI, an Electron desktop app, an editor protocol, and
a cron scheduler. What distinguishes it is a small set of mechanisms:
frozen, prompt-cache-friendly system prompts; native file tools; two
budgeted memory files; agentskills.io skills with progressive
disclosure; a post-turn review fork that writes memories and skills;
structured context compaction; subagents, MCP, and a Python "code mode".
Checked against the code, the learning loop is a review fork started by
two counters every ten turns or tool rounds, running a fixed prompt
(§11.2.11, §11.3). Its best ideas are invariants rather than code
(§11.2.17): persist tool calls before side effects; give every tool call
a result; never re-stream text the user has already seen; keep the
prompt byte-stable and put changes in messages; disclose skills and tools
progressively; keep memory tiny and budgeted.

§11.1 explains why the repository is so large, §11.2 reads the core
architecture, §11.3 reads the learning loop in detail, §11.4 reports what
Hermes measures about it, and §11.5 sets it against the literature of
Part I.

### 11.1 Why the repository is so large

A fresh clone is 1.3 GB: a 1.03 GiB packfile plus a 223 MB working tree
(190 MB of it tracked). The two halves have different causes.

#### 11.1.1 History: 44K commits in 14 months, mostly rewrites of huge files

The repository has 43,967 commits on `main`, by about 3,750 distinct
author names. Almost all of them are recent (committer dates):

| Month | Commits | Month | Commits |
| --- | ---: | --- | ---: |
| 2025-07 to 2025-12 | 60 | 2026-05 | 3,249 |
| 2026-01 | 32 | 2026-06 | 3,700 |
| 2026-02 | 481 | 2026-07 | 6,079 |
| 2026-03 | 2,463 | 2026-08 | 7,128 |
| 2026-04 | 3,865 | 2026-09 (to the 26th, 04:00 UTC) | 16,910 |

September averages roughly 670 commits a day, with about 10,500 first-parent
commits on `main`. Commit trailers show heavy AI-assisted development:
since 2026-08-01 there are 2,430 `Co-Authored-By: Claude ...` trailers,
441 `Co-authored-by: Cursor`, and 168 `Co-authored-by: Hermes Agent`.
Trailers are optional, so these counts are a lower bound.

The pack holds 185,697 blobs, 14.5 GB uncompressed, 991 MB after delta
compression. Python source history is 525 MB of that, spread over 11,328
paths, but it is concentrated: the 20 most expensive Python files take
248 MB, the top 100 take 351 MB. They are very large files edited 900
to 2,300 times before being split up. The largest histories, mostly
Python:

| Path | Versions | Largest version | Pack bytes |
| --- | ---: | ---: | ---: |
| `gateway/run.py` | 2,308 | 1.7 MB | 84 MB |
| `cli.py` | 1,534 | 1.0 MB | 23 MB |
| `hermes_cli/main.py` | 1,549 | 0.77 MB | 22 MB |
| `hermes_cli/web_server.py` | 931 | 0.83 MB | 18 MB |
| `tui_gateway/server.py` | 1,174 | 0.80 MB | 18 MB |
| `run_agent.py` | 1,653 | 0.84 MB | 13 MB |
| `apps/desktop/electron/main.ts` | 888 | 0.71 MB | 13 MB |

Each of these was a 0.7 to 1.7 MB "god file" for months; the project's own
`AGENTS.md` records a September 2026 decomposition into
`<stem>_<topic>.py` "facade + siblings" families. Today `run_agent.py` is
91 KB, `cli.py` 83 KB, and `gateway/run.py` 332 KB.

The rest is accidental binaries that stay in history: an 83 MB Singularity
image (`atropos/atropos-sandbox.sif`), 23 MB of `.venv-clean/bin/{ruff,ty}`,
and 98 MB of per-PR `infographic/*.png` files (63 blobs, ~1.6 MB each).
All PNGs together take 137 MB of the pack.

#### 11.1.2 Working tree: 1.66M lines of Python, 57% of them tests

| Area | LOC | What it is |
| --- | ---: | --- |
| `tests/` | 947K Python | ~42,000 test functions in ~5,400 files |
| `apps/` | 361K TS + 183K TSX | Electron desktop app, bootstrap installer |
| `hermes_cli/` | 194K Python | CLI subcommands, setup wizard, config, auth/OAuth, dashboard server, kanban, updater |
| `agent/` | 100K Python | the agent core, providers, compression, memory, skills plumbing |
| `tools/` | 95K Python | 337 Python files: every model tool and its infrastructure |
| `gateway/` | 77K Python | messaging gateway core |
| `plugins/` | 74K Python | 22 messaging platforms, 7 memory backends, 11 web-search backends, model providers, kanban, ... |
| `ui-tui/` + `web/` | 122K TS/TSX | Ink terminal UI and the dashboard SPA |
| `tui_gateway/` | 31K Python | JSON-RPC backend for the TUI and desktop app |
| `scripts/`, `evals/`, `pm/`, `cron/`, root `*.py` | 94K Python | release/CI tooling, offline benchmarks, a package manager, cron, entry points |
| `skills/`, `optional-skills/` | 36K Python + 2.2 MB of `SKILL.md` | 58 bundled and 150 optional skills |
| `website/` | 27 MB | Docusaurus docs, screenshots, a zh-Hans translation |

Tracked bytes are dominated by `tests/` (50 MB), `apps/` (40 MB) and
`website/` (27 MB). Smaller oddities include `contributors/emails/`,
1,573 one-line files mapping commit emails to GitHub logins (one file per
contributor to avoid merge conflicts), and a 159 KB `COMPAT_MANIFEST.md`
plus 289 KB `compat_manifest.json` that kept pre-decomposition import
paths alive for external plugins until their scheduled removal on
2026-09-14.

The dependency surface is large too: 44 core Python dependencies
(`openai`, `httpx`, `pydantic`, `prompt_toolkit`, `rich`, `fastapi`,
`uvicorn`, `websockets`, `cryptography`, `Pillow`, `psutil`,
`ptyprocess`, ...), 60 optional extras (messaging SDKs, TTS/STT engines,
cloud sandboxes, memory services), 331 packages in `uv.lock`, plus four
npm lockfiles, of which the root workspace (1,407 packages) and the
website (1,392) are the large ones.

#### 11.1.3 Why it grew this way

The growth is visible in snapshots of non-test Python:

| Date | Non-test Python | Test Python | TypeScript |
| --- | ---: | ---: | ---: |
| 2025-11-22 | 0.2 MB (5.1K LOC, 12 files) | ~0 | 0 |
| 2026-02-15 | 1.5 MB (30.4K LOC, 82 files) | 0.1 MB | 0 |
| 2026-04-15 | 8.8 MB | 7.5 MB | 0.3 MB |
| 2026-06-15 | 21.8 MB | 22.4 MB | 7.4 MB |
| 2026-09-25 | 42.8 MB | 49.0 MB | 32.9 MB |

The November 2025 tree is a research agent for generating tool-use
trajectories (a 771-line `run_agent.py`, a batch runner, web, terminal,
vision and image tools). By mid-February 2026 the product shape already
exists in 30K non-test LOC: a REPL, a gateway for Telegram, Discord, Slack
and WhatsApp, cron, skills, context compression, and command approval.
Memory, the SQLite session store and `session_search` followed on
2026-02-19. The next seven months multiplied the code by about 23. The
code shows three drivers:

1. **Breadth by policy.** Hermes's own `AGENTS.md` asks for the product to
   "expand aggressively" at the edges: ~32 messaging platforms, dozens of
   model providers with per-provider quirks, several terminal backends
   (local, Docker, SSH, Modal, Daytona, Singularity, Vercel), browser
   backends, TTS/STT engines, memory services, a desktop app, a TUI, a
   dashboard, an editor protocol (ACP), and an MCP server.
2. **Hardening by incident.** Most commits are bug fixes, each with
   "1-2 invariant tests". The core turn loop is now ~17K lines (13K code)
   across `agent/turn_*.py`, `agent/conversation_loop.py` and
   `agent/agent_init.py`, most of it recovery paths for specific provider
   and host failures. The comments cite issue numbers above #100000.
3. **Multi-tenancy retrofitted.** One process may serve many profiles,
   sessions and platforms. Much of the code binds a profile scope, a
   session context, or a per-thread interrupt flag. These rules exist
   because module globals and `os.environ` leak between tenants. The
   leaks are documented bug classes in `AGENTS.md`.

The essential agent is a small fraction of all this. §3 identifies it, and
§11.2.16 tallies essential against incidental code.

### 11.2 Core architecture, from the code

This section describes what the code does today, not what the website
says. File references are to `d0288be5b3`.

```text
 hosts (threads call run_conversation)          core (one synchronous loop)
 ┌───────────────────────────────┐          ┌──────────────────────────────────┐
 │ CLI REPL      Ink TUI/Electron│          │ AIAgent.run_conversation          │
 │ gateway (~32 platform adapters│ ───────▶ │  frozen system prompt ◀── memory, │
 │   + agent LRU cache)          │          │     skills index, context files   │
 │ cron ticker   ACP   API server│          │  provider (3 wires, retry,        │
 └───────────────────────────────┘          │     fallback, cache markers)      │
                                            │  tool dispatch ─▶ registry        │
 persistence: SQLite state.db               │     terminal, files, web, MCP,    │
 (sessions, messages, FTS5)  ◀──────────────│     memory, skills, delegate, ... │
                                            │  compaction; post-turn review fork│
                                            └──────────────────────────────────┘
```

#### 11.2.1 Process and concurrency model

The agent core is synchronous and thread-based. `AIAgent.run_conversation`
(`agent/conversation_loop.py:1654`) blocks until the turn ends, and every
host runs it on a worker thread:

| Host | Where a turn runs |
| --- | --- |
| classic CLI (`hermes`) | one daemon thread per turn (`hermes_cli/cli_chat_turn_mixin.py:115`) |
| messaging gateway | a 10-worker `ThreadPoolExecutor` under one asyncio loop (`gateway/run.py:61`) |
| TUI and desktop backend | one thread per prompt plus an 8-worker RPC pool (`tui_gateway/methods_prompt.py:694`) |
| ACP (editors) | a 4-worker pool (`acp_adapter/server.py:46`) |
| cron | a per-job single-worker pool with an inactivity watchdog (`cron/scheduler.py:1894`) |

asyncio exists only at the edges: platform SDKs, ACP stdio, uvicorn, and
one background event-loop thread for MCP clients. Inside a turn, parallel
tool batches use up to 8 daemon threads (`agent/tool_executor.py:128`), and
subagents are further `AIAgent` objects on threads.

Interrupts are cooperative. `agent.interrupt()` sets a flag, adds the
agent's thread id to a process-global set that tools poll
(`tools/interrupt.py:23`), closes the in-flight HTTP socket, and recurses
into child agents (`agent/interrupt_control.py:109-200`). Nothing is ever
cancelled preemptively. Approvals, clarifying questions and sudo prompts
are blocking rendezvous: the tool thread waits on a `threading.Event`
until the UI or a chat message answers (`tools/approval.py:118`,
`tools/approval_gateway_wait.py:25-30`).

#### 11.2.2 The agent and the turn loop

`AIAgent` (`run_agent.py:240`) is a facade of 14 mixins whose constructor
takes 84 keyword arguments, 22 of them callbacks. The loop in
`agent/conversation_loop.py` is a phase machine: a `_LoopState` dataclass
holds every loop local, and `_run_phase` calls 16 phase functions in
`agent/turn_*.py`. It uses reflection to pass them the fields they name
and copies their verdicts back (`agent/conversation_loop.py:1349-1462`).
Each phase takes keyword-only parameters named after `_LoopState` fields,
for example `begin_iteration(agent, *, messages, conversation_history,
original_user_message, api_call_count, interrupted, ...)`, and returns a
verdict whose `action` may be `break`, `continue` or `return`. One
iteration runs them in this order (`agent/conversation_loop.py:1470-1640`):

| Step | Phases (module) |
| --- | --- |
| Start | `begin_iteration`, `prepare_iteration` (`turn_iteration_prep`) |
| Build the request | `assemble_api_request` (`turn_request_assembly`), `run_preflight_gate` (`turn_preflight_gate`), `announce_api_call` (`turn_iteration_prep`) |
| Call, inside a retry loop | `nous_rate_limit_guard` (`turn_api_call`), `build_api_request` (`turn_api_request`), `perform_api_call` (`turn_api_call`), `check_api_response` (`turn_response_check`), `handle_api_interrupt` (`turn_api_call`), `handle_api_error` (`turn_api_error`) |
| After the call | `apply_retry_restarts` (`turn_iteration_prep`), `normalize_model_response` (`turn_response_intake`) |
| Act | `run_tool_round` (`turn_tool_round`) or `finish_text_response` (`turn_final_response`) |
| On an exception | `handle_outer_loop_error` (`turn_loop_errors`) |

After the loop, `finalize_turn` (`turn_finalizer`) persists the turn and
may start the review.

Stripped of recovery paths, one turn is the classic tool-calling loop:

1. Build the turn context: restore or build the frozen system prompt
   (§11.2.4), append the user message, and prefetch external memory
   (`agent/turn_context.py`).
2. Until the model stops or the iteration budget runs out
   (`agent/iteration_budget.py`; each subagent gets its own fresh budget,
   50 iterations by default, so parent and children together can exceed
   the parent's cap):
   * compress if the request is over the threshold (§11.2.9);
   * assemble the request: sanitize, canonicalize the tool-call JSON, and
     place prompt-cache markers last (`agent/turn_request_assembly.py`);
   * call the provider with streaming, retry, credential rotation and
     fallback (§11.2.3);
   * if the reply has tool calls: validate them, **persist the assistant
     tool-call message before any side effect**, execute them, append one
     `role: tool` result per call, and loop (`agent/turn_tool_round.py:118`);
   * otherwise pass the text through the "stop gates" (optional
     verify-after-edit nudges, `agent/turn_stop_gates.py`) and finish.
3. Finalize: persist, run the output hooks, and possibly spawn the
   background memory/skill review (§11.2.11) after the reply is delivered
   (`agent/turn_finalizer.py:716`).

The loop, its phases and the agent init total ~17K lines. The core
algorithm in the mid-February 2026 snapshot was ~1,000 lines of one
`run_conversation` method. The difference is recovery behaviour for
specific failures:
* empty or thinking-only responses;
* truncated tool arguments;
* stream drops;
* provider-specific 400s;
* "incomplete" Responses turns;
* compression timeouts;
* credential exhaustion;
* persistence failures.

Many of these carry an issue number. A reimplementation wants the
invariants behind them (§11.2.17), not their code.

#### 11.2.3 Messages and the provider layer

The canonical message is an OpenAI Chat Completions dict plus sidecar
keys: `reasoning`, `reasoning_content`, `reasoning_details`, and opaque
replay carriers for Anthropic signed thinking blocks, OpenAI Responses
encrypted reasoning items, and Gemini thought signatures
(`agent/chat_completion_helpers.py:1663-1753`). Each wire strips the
sidecars it does not use. There are five `api_mode`s
(`hermes_cli/runtime_provider.py:96`): four wires, plus `codex_app_server`,
which hands a whole turn to a `codex` subprocess:

* **Chat Completions**, used by about 30 of 38 provider profiles, including
  OpenRouter and every local server. Provider quirks come from declarative
  `ProviderProfile` data in `plugins/model-providers/`.
* **Anthropic Messages**, a 9-step conversion
  (`agent/anthropic_message_convert.py:710`). It extracts the system prompt,
  pairs `tool_use` with `tool_result` and strips orphans, merges same-role
  neighbours, forces a leading user turn, keeps signed thinking only on the
  latest assistant turn, and scrubs blank text blocks.
* **OpenAI Responses**, required by `api.openai.com` for GPT-5.x tool use
  (`hermes_cli/runtime_provider.py:99-127`). Encrypted reasoning is replayed
  with `store=false` and dropped when the issuer or model changes.
* **Bedrock Converse**, optional. **Gemini native**
  (`agent/gemini_native_adapter.py`) is not a separate mode; it presents
  itself as a Chat Completions client.

Streaming uses the `openai` and `anthropic` Python SDKs with SDK retries
off, plus raw event handling where the SDK helpers failed. Tool-call deltas
accumulate by index. A new id at a seen index gets a new slot, because
Ollama reuses index 0. Names are assigned rather than appended. A stream
that ends without a `finish_reason` is treated as a dropped stream, not a
stop, unless it carried a usage chunk or complete tool calls
(`agent/chat_completion_helpers.py:2757-2818, 3327-3389`). A stream is
retried at most twice, and only before any visible output, or when a tool
call was in flight and the error is transient (`:3628-3645`).

Errors go through a staged classifier into 29 `FailoverReason` values
with hints (retry, compress, rotate credential, fall back;
`agent/error_classifier.py:961`). About 200 of its lines are substring
tables of provider folklore. The status-based part is the essential core.
Retry uses jittered exponential backoff, honours `Retry-After`, and makes
3 attempts by default. After that an ordered fallback chain swaps provider,
model and wire in place.

A second router, `agent/auxiliary_client.py` (~6K code lines), serves
side tasks: compression summaries, titles, vision, an approval classifier,
background review. Under "auto" it uses the main model first. It also
builds the fallback clients, which helps explain its size.

One code path must not be ported. In Anthropic subscription-OAuth mode
Hermes does three things (`agent/anthropic_adapter.py:291-312, 544-580`):
* prefixes "You are Claude Code, Anthropic's official CLI for Claude.";
* rewrites "Hermes Agent" to "Claude Code" and "Nous Research" to
  "Anthropic" in the system prompt, which its docstring says "avoids
  server-side content filters";
* renames two tools, which its comment says avoids Anthropic's billing
  classifier treating Hermes as a third-party app.

A reimplementation should use API keys only.

About 3.1K to 3.5K of the layer's ~29K code lines are essential.

#### 11.2.4 Prompt assembly and the prompt-cache invariant

The first rule of Hermes's `AGENTS.md` is that per-conversation prompt
caching is "sacred", and the code enforces it:

* The system prompt is built once per session, persisted in the session DB
  (deduplicated by sha256), and restored byte for byte on later turns and
  processes (`agent/conversation_loop.py:721-791`). The `tools[]` array is
  pinned in the same way.
* It is rebuilt only when compression commits, or when the stored runtime
  identity (model, provider, working directory) no longer matches.
* Anything that must change mid-session travels in a user message or a
  tool result, never the system prompt: recalled memory, skill slash
  commands, AGENTS.md files of subdirectories the agent enters, `@file`
  references, and steering text.
* Sections are ordered stable → context → volatile so longest-prefix caches
  keep the most bytes (`agent/system_prompt.py:727-799`):
  1. identity (`SOUL.md` or the default);
  2. tool-gated guidance: memory, session search, skills, and
     tool-use-enforcement text for model families that under-call tools;
  3. the caller's system message;
  4. one kind of project context file, whichever is found first:
     `.hermes.md`, the `AGENTS.md` chain from the git root, `CLAUDE.md`,
     `.cursorrules`. Each is threat-scanned and capped at 6% of the
     context window, between 20K and 500K characters (~48K for a
     200K-token model), keeping 70% head and 20% tail;
  5. a git workspace snapshot;
  6. the skills index;
  7. frozen `MEMORY.md` and `USER.md` snapshots;
  8. a date-only timestamp;
  9. a runtime-environment block.
* Anthropic `cache_control` breakpoints are planned per request on a copy,
  after every sanitizer (`agent/prompt_caching.py`). The layout is two
  markers on a split static/dynamic system prompt plus the last two
  messages, within Anthropic's limit of 4.

The cost is large. Hermes's own documentation puts the default request at
~26K tokens of tool schemas plus a ~9K-token system prompt, and requires a
64K-token context window
(`website/docs/integrations/providers.md:793`,
`optional-skills/devops/actual-setup/SKILL.md`). Tool Search's default
deferrals (§11.2.5) now trim part of that. A static extraction of 25 of the
59 core tool schemas done for this document still totals 44K characters.
Caching is what makes this affordable.

#### 11.2.5 Tools

A tool is a registry entry: name, toolset, hand-written OpenAI
function-calling JSON schema, handler, and an optional `check_fn`
availability probe cached for 30 s (`tools/registry.py:223`). Tool
modules register at import time; an AST scan finds them
(`tools/registry.py:96`). Toolsets are named groups in `toolsets.py`. The
default "core" set has 59 names (`toolsets.py:12`), many gated off unless
configured.

Dispatch works in three stages:
* **Validation:** unknown names and malformed JSON get tool-role error
  results.
* **Batch planning:** a planner splits a batch into ordered segments
  (`agent/tool_dispatch_helpers.py:198`). Read-only tools run in parallel
  on up to 8 threads. `read_file` and `search_files` (readers) and
  `write_file` and `patch` (writers) are admitted by path overlap, so
  writers to disjoint paths also run in parallel
  (`agent/tool_dispatch_helpers.py:51-53`).
  Everything else (terminal, browser, delegation) is a sequential
  barrier.
* **Execution:** each call runs on a worker polled every second, so an
  interrupted or timed-out tool can be abandoned. Every abandoned call
  still gets a synthetic result, so each `tool_call` keeps its result.

Results are sized and wrapped in three steps:
1. Per-tool caps apply: 50K characters for the terminal, 100K for
   `read_file`.
2. A result over 100K characters (50K for MCP tools; `read_file` never)
   is spilled to a file and replaced by a 1.5K preview with a "use
   read_file" hint (`tools/budget_config.py`).
3. A 200K-character per-turn aggregate budget applies.

Output from web, browser and MCP tools is wrapped in
`<untrusted_tool_result>` delimiters as a prompt-injection defence
(`agent/tool_dispatch_helpers.py:434-583`).

A rarely noticed feature is **Tool Search**, on by default. Whenever any
deferrable tool exists, those tools are replaced in the schema by three
bridge tools: `tool_search` (BM25), `tool_describe`, and `tool_call`
(`tools/tool_search.py:197-206`). Deferrable tools are:
* all MCP and plugin tools;
* a default list of cold built-ins, among them `session_search`,
  `todo_list`, `process_manage`, `cronjob_manage` and `image_generate`
  (`hermes_cli/config_defaults.py:1993`).

The model discovers them through search, and the listing is capped by a
token budget.

#### 11.2.6 The terminal and its environments

There is no persistent shell process. Every command is a fresh `bash -c`
(`tools/environments/base.py:1-7`). Shell state persists through a
snapshot:
* At start, a login shell dumps `export -p`, `declare -f` and `alias -p`
  into a snapshot file.
* Each command sources the snapshot, `cd`s to the tracked directory, runs
  under `eval`, and re-dumps `export -p`.
* It then prints a `__HERMES_CWD_<id>__` marker with `pwd -P`, which the
  caller parses and strips (`tools/environments/base_session_env.py:84-182`).

The same `BaseEnvironment` interface (`_run_bash`, `cleanup`) serves local,
Docker, SSH, Modal, Daytona, Singularity and Vercel backends. File tools
are implemented as shell scripts run through the environment (`sed`,
`cut`, `base64`, `mktemp`, `stat`, `sha256sum`;
`tools/file_operations.py:171`), so one implementation serves every
backend. Background processes are managed by a registry with poll, log,
wait, kill, write and close actions; a PTY is available locally via
`ptyprocess`. Completion notifications are injected into the next turn
(`tools/process_registry.py`).

Defaults:
* Foreground commands time out at 180 s; values over 600 s become tracked
  background jobs.
* Output keeps a 40% head / 60% tail window.
* Output is ANSI-stripped and secret-redacted
  (`tools/terminal_tool_result.py:206`).

#### 11.2.7 File tools

* `read_file` returns numbered lines with pagination, binary sniffing and
  document extraction, and tracks what the task has read.
* `write_file` refuses to overwrite a file the task has not fully read, or
  that changed on disk since (`tools/file_tools_write_guards.py:497`). It
  writes atomically, preserves CRLF and BOM, checks JSON/YAML/TOML syntax,
  verifies by sha256 and reports only new lint errors.
* `patch` is a find/replace with nine fuzzy-matching strategies
  (`tools/fuzzy_match.py`) and an OpenAI-style V4A multi-file mode.
* `search_files` wraps ripgrep.

A transparent "checkpoint" store takes a shadow-git snapshot before
mutations so `/rollback` works (`tools/checkpoint_manager.py`).

#### 11.2.8 Persistence

`SessionDB` is SQLite at `~/.hermes/state.db`, split into a facade plus 29
siblings, 19K lines in all (15.7K of code), at schema version 30
(`hermes_state_common.py:252`). Its main tables:
* `sessions`, with ~60 columns;
* `messages`, with role, content, tool calls, reasoning sidecars, an
  `active`/`compacted` pair for soft-archiving on compaction, and
  `api_content` holding the exact bytes sent;
* word and trigram FTS5 indexes, plus a CJK bigram index that replaces
  trigram search when its loadable C tokenizer is present
  (`hermes_state_fts.py:20-27`);
* lease tables used as cross-process locks.

Most of the code exists because many processes write one database: the
gateway, CLIs, desktop backends, cron, worktree agents. That requires
jittered write retries, a read-connection pool, OFD lock guards, `/proc`
scans for other holders, generation stamps and repair tooling. The March
2026 version was 517 lines with two main tables and one FTS index; that is
the essential design.

#### 11.2.9 Context compression

The trigger is `threshold × (window − max_output)`, with 0.50 as the
default and a floor of 75% for windows under 512K tokens, so in practice
compression fires at about 75% (`agent/context_compressor.py:2625`). An
absolute cap of 256K tokens applies, so a 1M-token window compacts at
256K. Token counts come from the provider's last reported usage plus a
characters/4 estimate for newer messages. The algorithm
(`agent/context_compressor.py:5281`) has four steps:

1. Replace old tool results over 200 characters with one-line per-tool
   summaries, with no LLM call.
2. Keep the head: the system prompt and the first three messages
   (dropping to none after the first compaction). Keep a tail sized by
   tokens: 2.5% of the window, clamped to 10K–25K. Move the boundaries so a
   tool-call message and its results are never split, and keep the last
   user message in the tail.
3. Make one summary call with a structured template of ten sections,
   among them goal, constraints, completed actions, active state, blocked
   items, key decisions, errors, files and critical context. It updates
   the previous summary on later compactions. Code then appends:
   * a regex index of paths, SHAs and errors;
   * the user's messages verbatim (newest first, 4K characters each, 24K
     in all);
   * a pointer to `session_search`.

   If the call fails, a deterministic fallback summary is used.
4. Assemble head + summary (marked "REFERENCE ONLY") + tail without
   breaking role alternation. Drop orphaned tool calls and results.
   Soft-archive the old rows, which stay searchable, and rebuild the
   system prompt, reloading memory and the skills index.

The March 2026 compressor was 212 lines implementing the same skeleton
(protect head and tail, summarize the middle with an auxiliary model).

#### 11.2.10 Memory

The built-in memory is two Markdown files, `memories/MEMORY.md` (agent
notes) and `USER.md` (user profile). Entries are separated by `\n§\n`,
with character budgets of 2,200 and 1,375 (`tools/memory_tool_store.py:99`).
One `memory` tool applies an atomic batch of add, replace and remove
operations, checking the budget only on the final state, under a file
lock, with drift detection and a threat scan.

Writes reach disk immediately but never change the running prompt. The
prompt carries a snapshot frozen at session start and refreshed only at
compaction. An optional `MemoryProvider` plugin (7 backends: Honcho, Mem0,
and others) can prefetch recall into the user message, but the built-in
store does no extraction of its own.

#### 11.2.11 Skills and the learning loop

Skills use the agentskills.io layout: a directory holding `SKILL.md`
plus optional `references/`, `templates/`, `scripts/` and `assets/`. The
YAML frontmatter has a `name` and a short description, conventionally at
most 60 characters because the index shows no more; the hard limit is
1,024. Disclosure is progressive:
* The system prompt carries only an index of names and descriptions, with
  a strong "you MUST load it" preamble (`agent/prompt_builder.py:1357`).
* `skill_view` loads a skill whole; there is deliberately no pagination.
* `skill_manage` creates and patches skills.

The self-improvement loop is simple:
* Two counters exist: user turns since the last `memory` call, and
  tool-calling iterations since the last `skill_manage` call.
* When either reaches 10 at the end of a delivered turn, a background
  thread forks an `AIAgent` with the same system prompt, tools, and
  session id, so the provider's prompt cache is warm. The fork has
  persistence disabled and a 16-iteration cap
  (`agent/background_review.py:960-1038`).
* It replays the whole conversation plus a review prompt; a review routed
  to a different model gets a digest instead. The skill prompt
  says "Be ACTIVE — most sessions produce at least one skill update" and
  ranks the actions: patch a loaded skill, patch an umbrella skill, add a
  reference file, create a class-level skill.
* A tool whitelist lets it touch only skills, `read_file` and
  `search_files`, plus memory when the memory counter fired.

A separate "curator" archives agent-created skills unused for 30 days;
LLM-based merging of skills is off by default (`agent/curator.py`).

#### 11.2.12 Delegation, code execution, MCP

`delegate_task` builds a new in-process `AIAgent` with the following setup:
* a fresh conversation and a goal-plus-context prompt;
* no memory and no context files;
* the parent's credentials;
* the parent's toolsets minus delegation, clarify, memory, messaging and
  cron.

Children share the parent's terminal environment and MCP connections, and
run on up to 10 concurrent threads by default (raised from 3 on
2026-08-15). Nesting is off by default (`max_spawn_depth` 1). It became
configurable on 2026-04-21, when the depth numbering changed but the
default behaviour did not (`48ecb98f8a`). The parent sees only a summary
(`tools/delegate_tool.py:156-236`, `tools/delegate_tool_config.py:17-21`).

`execute_code` is "programmatic tool calling". The model writes a Python
script. A generated `hermes_tools.py` stub calls back into the agent over a
Unix socket for up to 7 tools, 50 calls and 300 s. Only the script's
stdout returns to the model, and a round consisting only of `execute_code`
does not count against the iteration budget (`tools/code_execution_tool.py`).

The MCP client uses the official Python SDK on one background asyncio
loop. It supports stdio, Streamable HTTP and SSE, plus OAuth. Each MCP tool
is registered like a built-in, as `mcp__<server>__<tool>` with the
server's schema (`tools/mcp_tool_registration.py:321`).

#### 11.2.13 Hosts

* **CLI.** A prompt_toolkit REPL over about 100 shared slash-command
  definitions (`hermes_cli/commands.py`).
* **Messaging gateway.** One asyncio process holds many platform adapters.
  The adapter interface has four abstract methods (`connect`,
  `disconnect`, `send`, `get_chat_info`) and ~40 optional ones on a
  4.8K-line base class (`gateway/platforms/base.py:1854`). There are about
  32 adapters; the reference one is IRC, 620 lines using only the Python
  standard library.
  * Each chat maps to a session key, and its `AIAgent` stays in an LRU
    cache (128 entries, 1 h idle) so the frozen prompt survives between
    messages.
  * A message arriving mid-turn interrupts, queues, or steers the running
    turn.
  * Streaming uses rate-limited message edits.
  * Unknown users pair through one-time codes.
* **Cron.** A JSON job store with a 60 s tick and at-most-once dispatch. A
  fresh agent runs per job, and results go to a chat or a file.
* **TUI and desktop.** A 237-method JSON-RPC protocol (`tui_gateway/`)
  consumed by the Ink TUI and the Electron app.
* **ACP.** A server for editors.

Profiles (separate `HERMES_HOME`s) can be multiplexed in one process. The
root `AGENTS.md` names this a bug class, because module globals
and `os.environ` belong to the launch profile.

Other subsystems, and whether they bear on the learning loop:

| Subsystem | Code | What it does | Bearing on the learning loop |
| --- | --- | --- | --- |
| Kanban | ~20K lines | A SQLite task board shared across profiles. Workers are separate `hermes -p P chat -q` processes that claim, comment on and complete tasks. | None; a task board. |
| Mixture of agents | `agent/moa_*.py` | Per-turn fan-out to reference models before the main call. | None. |
| Browser | `tools/browser*.py`, 8.8K | Node `agent-browser` driving Chromium via accessibility-tree snapshots. | None. |
| Checkpoints | `tools/checkpoint_manager.py` | A shadow git store snapshotted before mutations, for `/rollback`. | Some: an undo for files, which §13 asks for in another form. |
| LSP | `agent/lsp/` | Language-server diagnostics filtered to new lint errors after writes. | None. |
| Voice, TTS, images, video | several | Speech, wake word, generation providers. | None. |
| Research tooling | `batch_runner.py`, `trajectory_compressor.py` | Parallel trajectory generation in ShareGPT format for RL data. The Atropos environments were deleted on 2026-05-15. | None. |

#### 11.2.14 Extension surface

A plugin is a directory or pip package with `plugin.yaml` and
`register(ctx)`. `PluginContext` offers 26 registrars: tools, platforms,
memory providers, context engines, web search, image generation, and more.
It also offers 41 hook names and 4 middleware types
(`hermes_cli/plugins.py:108-192, 230`). In-tree use is concentrated
in a few of them: 23 platform registrations, 12 web-search providers,
8 image generators and 7 memory providers, but only 7 hook registrations.
Separately, shell hooks use a Claude-Code-compatible JSON stdin/stdout
protocol (`agent/shell_hooks.py`).

#### 11.2.15 Security model

* **Command approval** (`tools/approval.py:1168`):
  1. A hard floor of 12 regexes blocks even in "yolo" mode: `rm -rf /`,
     `mkfs`, `dd` to disks, fork bombs, shutdown.
  2. ~107 dangerous-command patterns (~29 of them Windows-specific) are
     checked after normalization.
  3. Tirith, a third-party Rust scanner, runs once per command as a
     subprocess. It looks for homograph URLs, pipe-to-interpreter and
     terminal injection (`tools/approval.py:1203-1214`,
     `tools/tirith_security.py`). Its findings prompt the user, or block
     when no one can answer. Hermes downloads it lazily, pinned to v0.4.2
     with checksum and signature checks. It is on by default but fails
     open: with no binary, after a timeout, or after three crashes the
     command is allowed (`tirith_security.py:43-46, 59, 306-312`).
  4. An optional LLM classifier can decide.
  5. Otherwise a human answers: once, session, always, or deny.
* **Unattended contexts** (`-q` single queries, cron, and platforms with
  no one to answer, such as webhooks) apply a configured mode. The
  default, `deny`, blocks what the patterns or Tirith flag and allows the
  rest. `approve` allows everything that passes the hard floor
  (`tools/approval.py:618-670, 1193-1201`;
  `hermes_cli/config_defaults.py:1658-1660`). Any other caller with no
  approval channel is allowed.
* **Container backends without host bind mounts** skip prompts and even
  the hard floor; the container is the boundary.
* **File-tool path guards** are explicitly "defense-in-depth, NOT a
  security boundary" (`agent/file_safety.py:1-5`).
* **Other layers:** regex secret redaction of tool output
  (`agent/redact.py`), secret scrubbing of child environments, an SSRF
  guard for URL fetches, and threat scans of context files, memory and
  skills.
* **Downloaded helpers.** Hermes's package manager (`pm/`) fetches
  pinned, checksummed and mostly signed binaries at run time. Besides
  Tirith there are:
  * iron-proxy, a TLS-intercepting, default-deny egress proxy for the
    Docker, Modal and SSH backends. The sandbox holds only opaque tokens,
    and the proxy swaps them for real credentials on the way out
    (`agent/proxy_sources/iron_proxy.py`).
  * `bws`, the Bitwarden Secrets Manager client
    (`agent/secret_sources/bitwarden.py`).

  None of these bears on the learning loop; they belong to the remote
  execution backends.
* **The local backend has no sandbox.**

#### 11.2.16 Essential versus incidental

Estimates of the code a faithful minimal core needs, from the per-area
reviews behind this document. The areas overlap slightly and mix raw and
code-only line counts, so treat the Python column as an order of
magnitude:

| Area | Python today | Essential Python | Minimal reimplementation |
| --- | ---: | ---: | ---: |
| Turn loop and agent state | ~17K | ~1.5K | 1.5–2.5K |
| Provider layer (3 wires, retry, caching) | ~29K | ~3.3K | 5–5.5K |
| Tools, dispatch, terminal, files, approval | ~60K | 12–15K | 10–15K |
| State, memory, skills, compression, prompt | ~51K | ~6K | 5–8K |
| Hosts: REPL, one adapter, cron | ~370K | ~5K | 3–5K |
| **Total** | **~530K** | **~30K** | **~25–35K** |

The table covers ~530K of the ~705K non-test Python lines. Its hosts row
is already mostly CLI management, plugins and platform adapters; the
remaining ~175K is scripts, benchmarks, the package manager, skill
scripts, non-core tools and some entry points. About 4% of the non-test
Python is essential, and a reimplementation of that part is about the same
size as the Python it replaces.

#### 11.2.17 Design lessons

Worth keeping:
* **One ordinary tool loop.** Its invariants:
  * persist the tool-call message before any side effect;
  * give every tool call a result, including synthetic ones for
    interrupts;
  * keep role alternation strict;
  * never re-stream text the user has already seen; Hermes retries after
    visible output only to finish an in-flight tool call;
  * treat a stream that ends without a finish reason as a drop, not a
    stop.
* **A frozen, cache-friendly prompt.** Changes arrive as messages and tool
  results, and the prompt is rebuilt only at compaction.
* **Progressive disclosure.** A skills index in the prompt with full loads
  on demand, and deferred MCP tools behind a search bridge.
* **Memory as two small Markdown files** with hard character budgets and
  batch edits.
* **The post-turn review fork**, which reuses the cached prefix. It is the
  whole "learning loop", and it is small.
* **Structured compaction:**
  * cheap tool-result pruning first;
  * tool-group-aligned boundaries;
  * one templated summary, updated iteratively;
  * recent user messages carried verbatim;
  * archived history kept searchable;
  * a bounded summarizer input (160K characters), so history larger than
    the window still compacts.
* **Native file tools** with read-before-write and fuzzy patching. Hermes's
  terminal description steers models to them and away from `cat`, `grep`
  and `sed`.

Not worth keeping:
* many processes sharing one database;
* in-process multi-profile multiplexing;
* provider fallback chains and credential pools, at least at first;
* dozens of platform SDKs;
* shell-script file operations that exist only for remote backends;
* the Claude Code impersonation path;
* self-update and package management.

#### 11.2.18 Where Hermes's fixes went

Across the files that make up the loop, providers and compression
(`agent/conversation_loop.py`, `agent/turn_*.py`,
`agent/chat_completion_helpers.py`, the Anthropic and Responses adapters,
`agent/transports/`, `run_agent.py`, the compressors,
`agent/tool_executor.py`, `agent/message_sanitization.py`), `git log`
counts about 3,300 non-merge
commits, about 2,100 of which start with "fix". An independent recount got
3,092–3,434 and 2,010–2,214 depending on the exact file set, so the fix
share is about two thirds either way. Classifying the subjects by keyword
(one subject can hit several classes):

| Failure class | Fix commits |
| --- | ---: |
| Provider-specific quirks | 499 |
| Compression and context overflow | 487 |
| Stream drops, stalls, timeouts | 296 |
| Fallback, credentials, rate limits | 263 |
| Persistence | 102 |
| Interrupt, cancel, steer | 97 |
| Truncation and output caps | 93 |
| Empty or thinking-only responses | 85 |
| Prompt caching | 83 |
| Role alternation and message shape | 54 |
| Reasoning replay and signatures | 37 |
| Tool-call ids and pairing | 18 |

Reading samples of each class gives the failure modes a reimplementation should
test for from the start, rather than rediscover. Where a dedicated Hermes
regression test exists, it is cited:
* **Compaction:**
  * the model acting on tasks it finds in the summary, which is why the
    summary is prefixed "REFERENCE ONLY";
  * compactions that save nothing and repeat
    (`tests/agent/test_compaction_anti_thrash.py`);
  * a failed or empty summary losing context;
  * a boundary that splits a tool group
    (`tests/agent/test_compression_boundary.py`);
  * pruned skill bodies the model still relies on;
  * a summary call that overflows because its own input is unbounded;
* **Streams:**
  * a stream that ends without a finish reason, including a `tool_use`
    whose arguments never arrived
    (`tests/agent/test_anthropic_mid_tool_call_drop.py`);
  * an empty partial-stream stub persisted as an assistant turn and
    poisoning the session;
  * retrying a stream after text was already shown.
* **Interrupts:**
  * a transport error raised by the interrupt itself and then retried
    (`tests/agent/test_cascading_interrupt.py`);
  * an interrupted tool round leaving `tool → user` or unpaired calls
    (`tests/agent/test_close_interrupted_tool_sequence.py`).
* **Caching:** a review fork whose prompt bytes differ from the parent's
  (`tests/agent/test_background_review_cache_parity.py`).

Two conclusions follow. Most of the provider and credential classes
disappear with a narrow provider set and API keys. The compaction and
stream classes do not; they are intrinsic to the loop, and any
reimplementation must test for them from the start.

#### 11.2.19 The README's claims against the code

Hermes's README describes it as "the only agent with a built-in learning
loop". Here is what each headline claim corresponds to in the code:

| README claim | What the code does |
| --- | --- |
| "creates skills from experience … nudges itself to persist knowledge" | Two counters (user turns since the last `memory` call, tool iterations since the last `skill_manage` call). At 10, a forked agent replays the conversation with a review prompt and a tool whitelist (§11.2.11). The "nudge" is that counter. |
| "improves them during use" | The skill-review prompt ranks patching an already-loaded skill first (§11.2.11). Nothing else measures or updates skill quality. |
| "builds a deepening model of who you are" | `USER.md`, capped at 1,375 characters, frozen into each session's prompt (§11.2.10). An optional plugin (Honcho and 6 others) can add retrieval. |
| "FTS5 session search with LLM summarization" | SQLite FTS5 over stored messages. The tool returns the stored messages themselves; its docstring says "No LLM calls — every shape returns actual DB messages" (`tools/session_search_tool.py:8`), so the README's summarization claim is out of date. |
| "Spawn isolated subagents for parallel workstreams" | In-process `AIAgent` objects on threads, at most 10 at once and depth 1, sharing the parent's terminal environment and MCP connections (§11.2.12). They have separate conversations, not separate processes. |
| "Python scripts that call tools via RPC … zero-context-cost turns" | `execute_code`: a generated stub calls up to 7 tools over a Unix socket; only stdout returns, and such rounds do not count against the iteration budget (§11.2.12). |
| "Telegram, Discord, Slack … from a single gateway process" | One asyncio process with ~32 adapters, turns on a 10-worker thread pool, and an LRU cache of agents (§11.2.1, §11.2.13). |
| "Seven terminal backends" | One `bash -c` per command, with shell state carried by an `export -p` snapshot. File tools are shell scripts, so the same code serves every backend (§11.2.6). |

The mechanisms are real and simple. The marketing's "learning" is prompt
engineering on a timer, and its value depends on the model's judgement
in the review fork. Whether it helps is, as §11.4 shows, unmeasured.


### 11.3 The learning loop, read from the code

The mechanisms of §11.2.10 and §11.2.11, in the detail that Part III
needs.

* **When a review runs.** Two counters: user turns since the memory tool
  was last used, and tool rounds since a skill was last edited. When
  either reaches ten and the current turn has finished, a copy of the
  agent with the same prompt, tools and session reviews the conversation,
  for at most sixteen steps, saving nothing to disk
  (`agent/background_review.py`). Whether the ten turns went well or
  badly plays no part in the decision. A review routed to a different
  model gets a digest of older turns instead of the whole conversation.
* **What the review is told.** The skill instructions open with "Be
  ACTIVE — most sessions produce at least one skill update, even if
  small. A pass that does nothing is a missed learning opportunity, not a
  neutral outcome," and close with "'Nothing to save.' is a real option
  but should NOT be the default." In between they are careful, and they
  encode from Hermes's own incidents several of the lessons of Part I.
  Write the procedure first. A pitfall is "a generalizable rule + one
  clause of WHY". No stories about what happened, no ticket numbers or
  dates. State each lesson once. Do not repeat what the project's
  instructions or the tool descriptions already say. Fix a wrong sentence
  in place rather than appending a correction. A "Do NOT capture" list
  rules out failures caused by the environment, negative claims about
  tools ("these harden into refusals the agent cites against itself for
  months"), errors that went away on their own, one-off tasks, and
  unsolved problems written up as if they were methods. A skill must be
  read in the same review before it is edited; the tool refuses
  otherwise. The memory instructions route each fact to one of the two
  files, after an incident in which the reviewer wrote the same lesson to
  both until both hit their limits.
* **Whose skills the review may edit.** Only skills the agent created
  (`created_by: agent`). Skills that ship with Hermes, were installed from
  its hub, live in an external directory, are pinned, or were written by
  the user are off limits; the review may only suggest that the user adopt
  them. The user's skills are thus never touched by the loop, and the
  agent's own skills are never checked by anyone before use.
* **What is recorded.** A side file (`tools/skill_usage.py`) counts, per
  skill, uses and views, the last use, the creator, and a state of
  active, stale or archived. Nothing records whether a task that used a
  skill went well. Nothing ties a skill or a memory entry to a result.
* **The curator** (`agent/curator.py`) runs when the agent has been idle
  two hours, at most weekly. A skill unused for 14 days is marked stale
  and after 30 archived; pinned skills are left alone; nothing is deleted.
  A pass in which a model merges skills into broader ones exists but is
  off by default, and its instructions tell the model not to treat usage
  counts as evidence either way.
* **A focused review** can be started by the user with `/refine` and a
  sentence that takes priority over the general instructions.
* **A verification nudge** (`agent/verify_hooks.py`) asks the model, at
  most three times, for fresh evidence that code works before it declares
  the work done.

### 11.4 What Hermes measures

The tests for the review (`tests/agent/test_background_review*.py`)
check that it uses only the allowed tools, that its first request reuses
the parent's cached prompt byte for byte, and that a focus sentence is
appended correctly. The `evals/` directory has 69 entries. None measures
whether memory or skills make later tasks go better; the one memory
evaluation checks that a plugin's plumbing works and says so in its
docstring ("proves query routing, ownership and caller waiting, not
memory quality"). The README's claim to be "the only agent with a
built-in learning loop" describes a mechanism, not a measured effect.

In short, Hermes has thought hard about what to write down and who may
write it, and not at all about whether writing it down helped.

### 11.5 Hermes against the literature

Against Part I, Hermes's everyday mechanisms are well supported. Its
frozen prompt is the cache discipline of §8.4. Its two small budgeted
memory files with one-entry-at-a-time edits are the small always-present
layer of §4.2 and the bounded writes of §4.3. Its skill index with bodies
loaded on demand is progressive disclosure, and its terse file tools and
its "Do NOT capture" list encode, from incidents, several of §4.1's
findings about what not to remember. Its record of bug fixes (§11.2.18)
is a catalogue of how agents fail in practice.

Its learning loop is not supported. It has no check before a change is
kept, which §5.1 and §7.2 show to be the property that separates
improvement from regression. It reviews on a timer rather than on
evidence, which §5.1 (CODESKILL's failure-fired skills) and §7.2
(Continual Harness's loops) argue against. It tells the reviewer to be
active, against §5.2's finding that fewer, shorter skills do better and
§4.3's finding that more reflection past a point hurts. It records no
outcomes, so its curator can only age skills, against §4.3 and the
Huxley-Gödel Machine's finding that value lies in what an artefact led
to. Its memory entries carry no dates and nothing supersedes anything,
which §4.3 (the timestamp result) and PAST-Bench identify as failure
modes. And it measures nothing, so none of this can be known from the
inside.

PAST-Bench is the external measurement. Hermes gained between +0.13 and
+0.24 overall from persistence, depending on the model, and beat the
other frameworks tested (nanobot +0.13, ZeroClaw +0.12, Agent-Zero
−0.08 on the same model). Its weakest foundation everywhere was
procedural reuse (+0.05 to +0.19, against +0.23 to +0.37 for declarative
memory), because "the solved workflow is not saved as an executable
procedure ... there is no ranked skill to open and execute". Its update
failures were the stale-artifact kind: "old persistent evidence remains
active after correction ... the result is a stale answer after the user
has already corrected it". A modified Hermes with typed, supersedable
bindings, ranked patchable skills, a gate that blocks action until
memory is read, and a synchronous overwrite at session close doubled its
update score (+0.12 to +0.24), while the overall gain stayed within the
benchmark's noise. Those modifications are, in effect, the items of §4.3
and §5.2 applied to Hermes.

The picture is consistent: the most used implementation gets the
scaffolding right and the learning wrong, in exactly the ways the
literature would predict.

# Part III. Conclusions

## 12. Findings

Seven findings, each resting on results from more than one paper.

**1. What decides whether an agent improves is the check before a change
is kept, not the change itself.** Self-written skills with no check cost
frontier models 8.1, 11.3 and 11.5 points on three setups where
human-written skills gained 18.2, 19.7 and 24.8 (SkillsBench); the same
kind of skills scored 71.1 instead of 32.0 once they had to pass tests
written by a separate model, and removing that tester cost 30 points
(CoEvoSkills). Without a held-out selection split a learned state
reached 100% in-sample and lost 33 points on test (RSEA); without a
regression gate, regressions rose from 3.1% to 14.8% (AgentDevel); agents
building their own harness chose the best version 2 times in 9, and 2 of
64 changes clearly improved (HarnessDev); a system with a private
held-out score rejected nine of ten proposals (AIDE²); 38.2% of evolved
rules did not generalise (EvoSafeHarness). Approval by a person says who
may use an artefact; only a check says whether it works; and when neither
can tell, the safe default is to keep nothing, not the newest version.

**2. Less is more: few skills, short ones, small edits, one entry at a
time.** One skill +18.0, two or three +19.0, four or more +10.1; compact
and standard lengths +19.0 and +21.5, exhaustive +0.7 (SkillsBench). One
retrieved lesson 49.7, four 44.4 (ReasoningBank); the same curve in
MemRL. All learned insights in a coding prompt: 2 to 11 points lost
(CTIM-Rover). A harness rewritten after every task got better then worse
under every budget, its prompt growing from 2 KB to 68 KB (Adaptive
Auto-Harness). A skill bank improved while shrinking from 1,252 to 676
(CODESKILL). Refinement past three rounds hurt (OpenSkill). One to four
edits per run with a record of rejected edits (SkillOpt: dropping the
budget cost 1.8, the record 4.6). One wholesale rewrite shrank a context
from 18,282 tokens to 122 and its accuracy below the untrained baseline
(ACE).

**3. A failure with its fix is the most useful thing to remember; old
facts must be replaced, not piled on; facts age faster than methods.**
Failure-fired skills 37.7 against 32.4 for task-organised ones
(CODESKILL); failure lessons helped one system by 3.2 and hurt another by
2.2, so the form is what matters (ReasoningBank against AWM); the link
from a failure to its fix was the largest ablation loss (EXG); pitfalls as
trigger, mistake, consequence (Metis). A memory of facts halved in-
distribution error and raised out-of-distribution error (Meta-TTL). A
memory without timestamps scored 21.7 against 66.9 on questions about
time (Mem0's comparison). Procedural reuse was the weakest foundation and
stale artefacts won after corrections in the most used implementation
(PAST-Bench). "No execution, no memory": a 165-token procedure that ran
beat a 575-token one, 66.5% to 52.4% (GenericAgent).

**4. Below a capability floor the loop reverses.** GPT-5-Nano lost 68%
with its own tools (Live-SWE-agent); Flash-Lite went from 20% to 13–33%
under a loop that helped Gemini 3 Pro (Continual Harness); a 4-billion
prompt-based manager gained nothing where a trained one gained 11
(CODESKILL); small models gained little or lost with Dynamic Cheatsheet;
ensembles need 70B+ (Archon); for an 8-billion model, compression was
worth more than skills (EvoDS). No positive result read here came from a
model below roughly 30 billion parameters or a frontier hosted model.

**5. Verification is the ceiling; iterate on execution feedback, do not
sample blind.** Majority vote 72.2 against oracle 91.9 (Weaver); 57.4
selected against 69.8 covered (CodeMonkeys); self-assessed success 30
points too high (ADaPT); 16.3% of self-written tests passed wrong code
(Reflexion). With a cheap check: refinement on execution output beat
resampling in 5 of 6 cases (KernelBench); easy problems favour sequential
revision (Snell); decompose only on objective failure, weak models gain
most (ADaPT); repeated failed actions caused 12 of 31 failures (METR);
tree search bought 1.7 points at 173,000 tokens a task (LATS).

**6. The checker, the scanner and the review criteria must stay fixed
and out of the agent's reach; a person is the anchor; rollback is cheap
insurance.** Hidden markers deleted "despite instructions not to", more
often when the checker was visible (Darwin Gödel Machine); evaluators may
evolve only against an untouchable anchor (Red Queen Gödel Machine); an
implementation-blind critic halved regressions (AgentDevel); rules keyed
to benchmark file names without a fresh reviewer (EvoSafeHarness); fluent
poison survives rephrasing 60–80% (DrunkAgent); 63.5% of a self-editing
agent's recent edits blocked in review, rollback made review-free
(Ouroboros). On instructions: weak optimisers made prompts worse than
hand-written ones (SePO's TextGrad comparison), weak judges erased gains
(Tournament of Prompts), tuned prompts did not transfer across models
(PROMST); people still choose the problems and write the rubrics
(Anthropic's essay).

**7. Layout and interfaces.** Only exact-prefix cache reuse exists for a
client, so stable text first, volatile last (CacheBlend, CodeMonkeys).
Condensed retrieval beat raw insertion by 2 to 5 points and raw insertion
hurt code (Search-o1). A narrow interface with explained errors: 80%
first-try success against 0% (Agent-System Interfaces). Tool
documentation rewritten from trials: +12 to +17, transferable, best after
three or four rounds (DRAFT). Asking for tools instead of listing them:
98% fewer tokens (MCP-Zero). A warning at 70% of the window let facts be
saved before the flush (MemGPT).

## 13. Design rules for a personal coding agent

What follows is the review's judgement of what the findings imply for
one kind of system: a coding agent with a frozen model, one user, a
modest budget, and no benchmark of its own. It is stated as rules, each
with the findings it rests on. It is not a design; a design has to fit
its program, its platform and its user.

1. **Record what happened.** Keep, for every turn, a mechanical record
   of failed tool calls, repeated calls, failed commands, files changed,
   and whether the project's own check ran and passed. Give the record to
   whatever reviews the session, so it reasons from evidence and not
   from a story (findings 3, 5; PROMST's mechanical templates).
2. **Let the project declare its check, and make the agent run it before
   claiming to be done.** A passed check is the only self-generated
   evidence worth the name; the agent's opinion of its own work is not
   (finding 5; Hermes's verification nudge).
3. **Write nothing durable without evidence.** A procedure is written
   only after it ran and worked. A guessed lesson waits as a candidate
   until a second session confirms it or a check does. A person approves
   what is used (findings 1, 3).
4. **Make writes small and bounded.** A few changes per review, one entry
   at a time, never a rewrite of the whole; a record of rejected changes
   that the next review sees, so it does not propose them again; "nothing
   to save" as the default outcome, not a failure (finding 2).
5. **Prefer failure-and-fix pairs, dated, superseding.** Every entry
   carries its date, its source, how it is known, and what it replaces.
   Corrections replace what they correct (finding 3).
6. **Keep little in the prompt.** Global facts and one project's notes,
   under a few kilobytes; one to three short skills for a task, loaded on
   demand; summaries from helpers, not dumps; what never changes at the
   front (findings 2, 7).
7. **Judge artefacts by what they led to, not by their age.** Count how
   often an entry was loaded, followed, and followed by success or
   failure; never retire something with a verified success on the
   strength of a calendar (findings 3, 6; Huxley-Gödel Machine).
8. **Keep the checks out of the agent's reach, and keep undo cheap.** The
   project check, the injection scan, the review instructions and the
   bench are not editable by the agent; hold writes from sessions that
   read outside text; log every accepted change; restore any earlier
   approved version with one command and no review (findings 1, 6; §10).
9. **Measure it, or do not trust it.** Run the user's own tasks with and
   without the learned material, grade them with checklists a program can
   evaluate, keep a few tasks the review never sees, and report improving,
   steady or degrading with an interval. Turn the loop off where the
   measurement says it hurts (findings 1, 4; §9).
10. **Turn it off for small models.** Until the measurement says
    otherwise, an agent on a small local model should keep the everyday
    tools and not the loop (finding 4).

## 14. Limitations of this review, and open problems

**Limitations.** The evidence is recent and mostly unreviewed. Most of it
is from benchmarks with executable checks, generous budgets and frontier
or mid-sized models, which is the setting where a learning loop is
easiest to make work; a personal agent has none of those. Many papers
were read once, in summary, by assistants working in parallel, and only
the results carrying the most weight were re-read in full. The selection
of papers followed two curated collections and the relevance of a paper
to one kind of agent; a different purpose would have chosen differently.
Hermes was read at one commit, and its learning loop may change. Nothing
was reproduced.

**Open problems the literature leaves.**
* *Learning without a benchmark.* Every positive result rests on a task
  set with a scorer. A personal agent has its user's tasks and its
  user's patience. Whether ten or twenty user-written tasks with
  mechanical checklists are enough to steer a loop, or only enough to
  detect gross harm, is untested.
* *The capability floor.* The floor below which self-improvement
  reverses is observed but not characterised. It is not known whether it
  is a matter of model size, of instruction following, of the cost of
  extra context, or of the loop's design, nor whether a loop designed
  for small models could clear it.
* *Attribution.* When a task succeeds, no method read here can say which
  memory entry or skill helped, or whether any did. Counts of loaded and
  followed artefacts are a proxy; controlled runs without an artefact are
  the only real test, and they are expensive.
* *Procedures.* PAST-Bench's finding that reusing procedures is the
  weakest foundation, in every framework tested, is unexplained. Skills
  in text form are the standard answer and they are read as text, not
  executed; the executable form has its own evidence (Voyager, Metis)
  and its own gate problem.
* *Drift.* Every benchmark is static. The survey's last future direction,
  surviving open-world drift in APIs, interfaces and adversarial input,
  has no evaluation yet, and it is the setting a personal agent lives in.
* *The user as verifier.* The literature treats human oversight as a
  cost to be minimised and quantified. For a single-user agent the user's
  corrections are the best signal available, and no paper read here
  studies how to use them well: how to ask, how often, and how to keep
  the asking from becoming the work.


# References

Sources are given by arXiv identifier where one exists; the link is
`https://arxiv.org/abs/<id>`. Years are those of first publication.

**Collections, surveys and courses**
* Awesome Self-Improving Agents,
  github.com/selfimproving-agent/awesome-Self-Improving-Agents (revision of
  2026-09-27).
* Ren, Chen, Guo et al., *Self-Improvements in Modern Agentic Systems: A
  Survey* (2607.13104, 2026).
* Stanford CS329A, *Self-Improving AI Agents*, autumn 2025,
  cs329a.stanford.edu.
* Kamoi et al., *When Can LLMs Actually Correct Their Own Mistakes? A Critical
  Survey* (2406.01297, TACL 2024).

**Memory**
* MemGPT: Towards LLMs as Operating Systems (2310.08560, 2023).
* ExpeL: LLM Agents Are Experiential Learners (2308.10144, 2023).
* Agent Workflow Memory (2409.07429, 2024).
* Dynamic Cheatsheet: Test-Time Learning with Adaptive Memory (2504.07952,
  2025).
* A-MEM: Agentic Memory for LLM Agents (2502.12110, 2025).
* Mem0: Building Production-Ready AI Agents with Scalable Long-Term Memory
  (2504.19413, 2025).
* Memory OS of AI Agent (2506.06326, 2025).
* ReasoningBank: Scaling Agent Self-Evolving with Reasoning Memory (2509.25140,
  2025).
* Agentic Context Engineering: Evolving Contexts for Self-Improving Language
  Models (2510.04618, 2025).
* Zep: A Temporal Knowledge Graph Architecture for Agent Memory (2501.13956,
  2025).
* From Knowledge to Noise: CTIM-Rover and the Pitfalls of Episodic Memory in
  Software Engineering Agents (2505.23422, 2025).
* MemRL: Self-Evolving Agents via Runtime Reinforcement Learning on Episodic
  Memory (2601.03192, 2026).
* Thought-Retriever (2604.12231, 2026).
* GenericAgent: A Token-Efficient Self-Evolving LLM Agent via Contextual
  Information Density Maximization (2604.17091, 2026).
* Learning to Learn-at-Test-Time: Language Agents with Learnable Adaptation
  Policies (2604.00830, 2026).
* EXG: Self-Evolving Agents with Experience Graphs (2605.17721, 2026).
* Memory Beyond Recall: A Dual-Process Cognitive Memory System (2606.09483,
  2026).
* Metis: Bridging Text and Code Memory for Self-Evolving Agents (2606.24151,
  2026).
* Cartridges: Lightweight and General-Purpose Long Context Representations via
  Self-Study (2506.06266, 2025).
* CacheBlend: Fast LLM Serving for RAG with Cached Knowledge Fusion
  (2405.16444, 2024).

**Skills and tools**
* Voyager: An Open-Ended Embodied Agent with Large Language Models (2305.16291,
  2023).
* Large Language Models as Tool Makers (2305.17126, 2023).
* From Exploration to Mastery: Enabling LLMs to Master Tools via Self-Driven
  Interactions, DRAFT (2410.08197, 2024).
* SkillWeaver: Web Agents Can Self-Improve by Discovering and Honing Skills
  (2504.07079, 2025).
* Alita: Generalist Agent Enabling Scalable Agentic Reasoning with Minimal
  Predefinition and Maximal Self-Evolution (2505.20286, 2025).
* MCP-Zero: Active Tool Discovery for Autonomous LLM Agents (2506.01056, 2025).
* MetaAgent: Toward Self-Evolving Agent via Tool Meta-Learning (2508.00271,
  2025).
* Live-SWE-agent: Can Software Engineering Agents Self-Evolve on the Fly?
  (2511.13646, 2025).
* SkillsBench: Benchmarking How Well Agent Skills Work Across Diverse Tasks
  (2602.12670, 2026).
* CoEvoSkills: Self-Evolving Agent Skills via Co-Evolutionary Verification
  (2604.01687, 2026).
* SkillOpt: Executive Strategy for Self-Evolving Agent Skills (2605.23904,
  2026).
* CODESKILL: Learning Self-Evolving Skills for Coding Agents (2605.25430,
  2026).
* MUSE-Autoskill: Self-Evolving Agents via Skill Creation, Memory, Management,
  and Evaluation (2605.27366, 2026).
* EvoDS: Self-Evolving Autonomous Data Science Agent with Skill Learning and
  Context Management (2606.03841, 2026).
* OpenSkill: Open-World Self-Evolution for LLM Agents (2606.06741, 2026).
* Socratic-SWE: Self-Evolving Coding Agents via Trace-Derived Agent Skills
  (2606.07412, 2026).
* Skill Self-Play: Pushing the Frontier of LLM Capability with Co-Evolving
  Skills (2607.22529, 2026).

**Instructions and prompts**
* Reflexion: Language Agents with Verbal Reinforcement Learning (2303.11366,
  2023).
* Self-Refine: Iterative Refinement with Self-Feedback (2303.17651, 2023).
* CRITIC: Large Language Models Can Self-Correct with Tool-Interactive
  Critiquing (2305.11738, 2023).
* Large Language Models Cannot Self-Correct Reasoning Yet (2310.01798, 2023).
* Is Self-Repair a Silver Bullet for Code Generation? (2306.09896, 2023).
* PROMST: Prompt Optimization in Multi-Step Tasks (2402.08702, 2024).
* Prompt Optimization with Human Feedback (2405.17346, 2024).
* TextGrad: Automatic "Differentiation" via Text (2406.07496, 2024).
* Optimizing Instructions and Demonstrations for Multi-Stage Language Model
  Programs, MIPRO (2406.11695, 2024).
* Trace is the Next AutoDiff (2406.16218, 2024).
* Symbolic Learning Enables Self-Evolving Agents (2406.18532, 2024).
* Adaptive Self-improvement LLM Agentic System for ML Library Development
  (2502.02534, 2025).
* Self-Evolving Curriculum for LLM Reasoning (2505.14970, 2025).
* Tournament of Prompts: Evolving LLM Instructions Through Structured Debates
  and Elo Ratings (2506.00178, 2025).
* GEPA: Reflective Prompt Evolution Can Outperform Reinforcement Learning
  (2507.19457, 2025).
* SePO: Self-Evolving Prompt Agent for System Prompt Optimization (2606.04465,
  2026).

**Full-scaffold modification and its safety**
* Automated Design of Agentic Systems (2408.08435, 2024).
* Darwin Gödel Machine: Open-Ended Evolution of Self-Improving Agents
  (2505.22954, 2025).
* AlphaEvolve: A Gemini-Powered Coding Agent for Designing Advanced Algorithms
  (DeepMind, 2025).
* Huxley-Gödel Machine (2510.21614, 2025).
* AgentDevel: Reframing Self-Evolving LLM Agents as Release Engineering
  (2601.04620, 2026).
* Group-Evolving Agents: Open-Ended Self-Improvement via Experience Sharing
  (2602.04837, 2026).
* Continual Harness: Online Adaptation for Self-Improving Foundation Agents
  (2605.09998, 2026).
* Adaptive Auto-Harness: Sustained Self-Improvement for Agentic System
  Deployment on Open-Ended Task Streams (2606.01770, 2026).
* The Red Queen Gödel Machine: Co-Evolving Agents and Their Evaluators
  (2606.26294, 2026).
* Recursive Self-Evolving Agents via Held-Out Selection, RSEA (2606.28374,
  2026).
* Harness Handbook: Making Evolving Agent Harnesses Readable, Navigable, and
  Editable (2607.13285, 2026).
* Harness-R1: Learning to Edit Executable Runtime Harnesses from Agent Failure
  Trajectories (2608.02276, 2026).
* Ouroboros: A Self-Developing Frontier Coding Agent with Reviewed Core
  Evolution (2608.08311, 2026).
* HarnessDev: Can LLMs Create and Evolve Their Own Agent Harness? (2609.01437,
  2026).
* EvoSafeHarness: Evolving Model- and Domain-Specific Harnesses for Securing
  Agents (2609.05903, 2026).
* DrunkAgent: Stealthy Memory Corruption in LLM-Powered Recommender Agents
  (2503.23804, 2026).

**Verification, planning and inference-time compute**
* ReAct: Synergizing Reasoning and Acting in Language Models (2210.03629,
  2022).
* Language Agent Tree Search Unifies Reasoning, Acting, and Planning
  (2310.04406, 2023).
* ADaPT: As-Needed Decomposition and Planning with Language Models (2311.05772,
  2023).
* Large Language Monkeys: Scaling Inference Compute with Repeated Sampling
  (2407.21787, 2024).
* Scaling LLM Test-Time Compute Optimally Can Be More Effective than Scaling
  Model Parameters (2408.03314, 2024).
* Archon: An Architecture Search Framework for Inference-Time Techniques
  (2409.15254, 2024).
* Improving Parallel Program Performance with LLM Optimizers via Agent-System
  Interfaces (2410.15625, 2024).
* Search-o1: Agentic Search-Enhanced Large Reasoning Models (2501.05366, 2025).
* CodeMonkeys: Scaling Test-Time Compute for Software Engineering (2501.14723,
  2025).
* KernelBench: Can LLMs Write Efficient GPU Kernels? (2502.10517, 2025).
* How Do Large Language Monkeys Get Their Power (Laws)? (2502.17578, 2025).
* SPRINT: Enabling Interleaved Planning and Parallelized Execution in Reasoning
  Models (2506.05745, 2025).
* Shrinking the Generation-Verification Gap with Weak Verifiers, Weaver
  (2506.18203, 2025).
* Measuring AI Ability to Complete Long Tasks (2503.14499, 2025).
* WebRL: Training LLM Web Agents via Self-Evolving Online Curriculum
  Reinforcement Learning (2411.02337, 2024).
* RLEF: Grounding Code LLMs in Execution Feedback with Reinforcement Learning
  (2410.02089, 2024).

**Evaluation**
* Agent-as-a-Judge: Evaluate Agents with Agents (2410.10934, 2024).
* GDPval: Evaluating AI Model Performance on Real-World Economically Valuable
  Tasks (2510.04374, 2025).
* EVE-Agent: Evidence-Verifiable Self-Evolving Agents (2605.22905, 2026).
* PAST-Bench: Benchmarking the Foundations of Recursive Self-Improvement in
  Personal Agents (2608.04003, 2026).
* RSI-Bench, github.com/sunghunkwag/rsi-bench (2026).

**Essays and reports**
* Anthropic, *When AI Builds Itself* (2026),
  anthropic.com/institute/recursive-self-improvement.
* X. Tu, *The What & When of Self-Evolving Agents* (2026),
  xinmingtu.cn/blog/2026/self-evolving-agents/.
* Weco, *AIDE²: The First Evidence of Recursive Self-Improvement* (2026),
  weco.ai/blog/first-evidence-of-recursive-self-improvement.

**Hermes Agent**
* Nous Research, Hermes Agent, github.com/NousResearch/hermes-agent, commit
  `d0288be5b3` (2026-09-26), MIT license.

# Appendix A. Notes on each paper read

One entry per work read, in the groups of the reference list: what it does,
its main result with its baseline, its stated limits, and what it implies
for a personal coding agent. The numbers are the papers' own. The papers
were read in five groups by assistants working in parallel from the full
text where it was available; CoEvoSkills, PAST-Bench and DRAFT were read
a second time directly. Alita and MetaAgent were read from their abstracts
only, and their entries say so. "Implication" says what the work adds to
the findings of §12 and the rules of §13, or that it adds nothing.

### A.1 Coding agents that write their own skills

* **Socratic-SWE (2606.07412).** Extracts skills from a coding agent's
  successful and failed runs as name, description, when it applies and
  ordered steps, then uses them to generate practice tasks and trains the
  model on them. A 9-billion-parameter model went from 42.6 to 50.4 on
  SWE-bench Verified in three rounds; without the skill registry, 46.2.
  Needs model training, executable tests and a held-out set. Implication:
  the skill shape only.
* **Live-SWE-agent (2511.13646).** A shell-only agent that, after every
  step, asks itself whether to write a small tool; the tools are thrown away
  after the task. Claude 4.5 Sonnet rose from 62.0 to 75.4 on SWE-bench
  Verified; removing the reflection step gave 64.0, removing tool creation
  62.0. GPT-5-Nano fell 68%, because a weak model loops on writing tools.
  Implication: the loop is off for small models.
* **CODESKILL (2605.25430).** Skills as short markdown (title, when to
  apply, rules), some organised by task and some fired by a command failure
  or error pattern, managed by a small trained model. Average 29.3 without
  skills, 40.4 with; failure-fired skills alone 37.7, task skills alone
  32.4; merging and dropping skills improved the score while cutting the
  library from 1,252 to 676. A 4-billion model managing skills by prompt
  alone gained nothing. Implication: failures as triggers, a merge-and-drop
  pass, the small-model rule.
* **MUSE-Autoskill (2605.27366).** Skill directories with tests and a
  per-skill notes file the agent appends to across tasks; skills that
  fail their tests or go unused are removed. Self-made skills scored 53.4
  against 47.0 without and 59.7 for human-written ones on SkillsBench;
  moved into Hermes, its skills beat human ones (51.9 against 48.0) while
  skills made by another agent scored below no skills. Skills were long
  (median 310 lines against 165 for human ones) and each came from one
  task. Implication: the notes file.
* **CoEvoSkills (2604.01687).** A generator writes a skill; a separate
  model that cannot see the skill writes tests from the task's inputs;
  the skill is refined until the tests pass, with the tester allowed to
  escalate. On SkillsBench with Claude Code: 30.6 without skills, 53.5
  with human skills, 32.0 with skills written in one go, 71.1 with this
  method; without the separate tester, 41.1. Needs an oracle for the tester
  to learn against. Implication: the case for a check before promotion.
* **OpenSkill (2606.06741).** Researches a topic on the web, writes skills
  and tests from what it found, and refines them. 25.5 to 43.6 with Opus
  4.6, but the score fell with more refinement rounds (82.7, 79.9, 78.0 at
  3, 5 and 10), its tester agreed with the truth only 60.7% of the time,
  and a task cost about $1,800. Implication: cap refinement rounds
 ; otherwise nothing, it needs the Internet.
* **SkillsBench (2602.12670, v4).** 87 tasks in containers, run with and
  without human-written skills across 18 model and harness combinations.
  Skills gained 16.6 points on average. Skills the agent wrote for itself
  cost 8.1, 11.3 and 11.5 points on three frontier setups where human skills
  gained 18.2, 19.7 and 24.8. One to three skills helped most; short and
  medium ones beat long and exhaustive ones (0.7 for the latter). Thirteen
  tasks got worse with a skill that pushed a heavy method or displaced a
  better default. Implication: remove "Be ACTIVE"
 , the size and count caps.
* **SkillOpt (2605.23904).** A separate optimiser edits one skill file in
  small steps (one to four per run), keeps an edit only if a held-out set
  improves, and shows the optimiser the edits it rejected. Best or tied
  on all 52 model and harness cells tried; on one benchmark, dropping the
  edit limit cost 1.8 points and dropping the rejected list 4.6. Needs an
  automatic scorer. Implication: the four-change limit and the rejected list.
* **Skill Self-Play (2607.22529).** Trains a task proposer and a solver
  together with skills that carry usage statistics; saturated skills are
  pruned. Needs a minimum model capability and hundreds of GPU hours.
  Implication: usage counts for pruning; otherwise nothing.
* **EvoDS (2606.03841).** A data-science agent that keeps a skill only
  after it has been useful in three generations, and compresses its context
  adaptively. Removing skill learning cost 0.026; removing compression cost
  0.069, so compression mattered more for its 8-billion model. Implication:
  promote after recurrence; compression before skills for small models (§12,
  finding 4).
* **Agent Workflow Memory (2409.07429).** Turns past runs into short
  workflows with the specifics replaced by placeholders, kept in the prompt.
  WebArena 23.5 to 35.5 with GPT-4; on Mind2Web, workflows learned during use
  won as tasks moved further from the training data. Text workflows did as
  well as code; adding raw HTML hurt. Implication: steps with placeholders,
  in text.

### A.2 Agent memory

* **Dynamic Cheatsheet (2504.07952).** One text block of heuristics and
  snippets, rewritten after each task. GPT-4o on Game of 24: 10% to 99%;
  Claude 3.5 Sonnet on AIME 2024: 23.3 to 50.0, where keeping the full
  history gave 26.7. Small models gained little or lost; GPT-4o itself fell
  from 53.2 to 44.0 on one suite; bad heuristics get amplified. Implication:
  small models default to pruning, not adding.
* **A-MEM (2502.12110).** Notes with model-written keywords, embeddings
  and links between notes. Better than MemGPT on conversational recall; needs
  embeddings and is about dialogue. Implication: none for a personal agent.
* **Mem0 (2504.19413).** Extracts facts from each exchange and decides,
  against similar existing facts, whether to add, update, delete or do
  nothing. 66.9 on a judged conversation benchmark against 52.9 for a
  commercial memory that scored 21.7 on questions about time because it
  stored no dates. Full context still won (72.9). Implication: dates on
  every entry; the decision maps onto add, replace and remove.
* **Memory OS (2506.06326).** Three memory tiers with promotion by a
  "heat" of visits, length and recency. Embedding-based and about dialogue.
  Implication: use counts, not age alone.
* **ReasoningBank (2509.25140).** Distils up to three lessons per run, from
  successes as strategies and from failures as pitfalls, and retrieves
  one by default. WebArena 40.5 to 48.8; SWE-bench Verified 54.0 to 57.4.
  Retrieving one lesson: 49.7; two: 46.0; four: 44.4. Failure lessons
  helped it (+3.2) but hurt a competitor (−2.2). Works with a judge that
  is right 70 to 90% of the time. Implication: failures as pitfalls
 , one lesson at a time (§12, finding 2).
* **Agentic Context Engineering, ACE (2510.04618).** Splits the roles:
  one model runs tasks, one reflects, one curates; the context is a list
  of numbered bullets with counts of when each helped or hurt, edited in
  place. 42.4 to 59.5 on AppWorld. One wholesale rewrite shrank the context
  from 18,282 tokens to 122 and the score from 66.7 to 57.1, below the 63.7
  baseline. Implication: ids and counts on entries, no whole-file rewrites.
* **MemRL (2601.03192).** Learns a value for each memory from rewards and
  ranks by it. Retrieving too few or too many both hurt. Needs rewards and
  embeddings. Implication: confirms the one-lesson result of §4.2.
* **Metis (2606.24151).** Text memory in three kinds, facts about the
  environment, pitfalls (trigger, mistake, consequence) and plans; a plan
  becomes code only after it has been chosen several times and compiles
  in a sandbox. 51.8 to 60.1 on AppWorld with 13.5% fewer tokens; eager
  conversion to code scored lower and cost more than the gated version.
  Implication: the pitfall shape, code only after recurrence.
* **Thought-Retriever (2604.12231).** Stores the model's past answers as
  retrievable "thoughts". Document retrieval with embeddings. Implication:
  none for a personal agent.
* **Memory Beyond Recall (2606.09483).** A fast writer that marks
  superseded facts and a slow nightly consolidation. Heavy and embedding-based.
  Implication: keep superseded entries, which the content-addressed store
  does anyway.
* **EXG (2605.17721).** A graph of past cases with links from a failure to
  the correction that fixed it. On HumanEval a 1.7-billion model went from
  0.207 (Reflexion) to 0.537; removing the failure-to-fix links was the
  biggest loss; corrections helped more than warnings. Gains shrink on
  larger models. Implication: record failures with their fixes.
* **CTIM-Rover (2505.23422).** Put all learned lessons, general and per
  repository, into a SWE-bench agent's prompt. 42% without them, 40% with;
  per-repository lessons alone 31%; one lesson containing "clean" sent the
  agent to the wrong function. 45 tasks only. Implication: per-workspace
  memory, not in every prompt; repository knowledge in skills loaded on demand.
* **GenericAgent (2604.17091).** Four memory layers reached by tool calls,
  an always-on index of pointers, verified facts, procedures, and a raw
  archive, with the rule "no execution, no memory". 100% on a lifelong
  benchmark at 241K tokens against 75% at 814K for Claude Code. A short
  165-token procedure scored 66.5%, a long 575-token one 52.4%, none 13.9%.
  No embeddings. Implication: procedures only after they ran; short is better.
* **DrunkAgent (2503.23804).** An attacker who controls only an item's
  text can make an agent's memory update fail so that poisoned text persists;
  rephrasing defences leave 60 to 80% of the effect. Implication: provenance
  before pattern scans; a log the user can read.
* **ExpeL (2308.10144).** Compares failed and successful runs of the same
  task and keeps a list of insights with votes: add, edit, up, down.  ALFWorld
  40 to 59 with GPT-3.5 acting and GPT-4 extracting; insights from GPT-3.5
  were no better than hand-written ones; adding raw reflections hurt.
  Implication: vote counts; run the review on the strongest model available.

### A.3 Agents that rewrite their own scaffolding

* **Adaptive Auto-Harness (2606.01770).** Rewrites the whole harness after
  each task cycle. 22.2% to 80.9% on one benchmark, but a single continuously
  evolved harness got better and then worse under every budget tried, with
  its prompt growing from 2 KB to 68 KB and skills from 12 to 34 that
  misfired later; mixing domains cost 57 points. Implication: caps and pruning.
* **Continual Harness (2605.09998).** Every few steps a refiner looks for
  loops, failed tool calls and stalls and edits prompt, skills and memory in
  place. Reached 100% of Pokémon Emerald milestones at $130 against 98% at
  $215, but without validation one schema mismatch looped for 1,003 turns,
  most memory entries went unused, and Flash-Lite got worse. Implication:
  off for small models; triggers, not intervals.
* **Harness-R1 (2608.02276).** Trains a 9-billion model to patch four
  hooks around a frozen agent. 44.3 to 53.6 average; the gains came from
  hooks that veto actions and recover from feedback, while extra context
  before decisions was worth nothing. Implication: none for a personal
  agent to build; a caution that memory in the prompt is the weakest lever.
* **Ouroboros (2608.08311).** A coding agent that edits its own code under
  a deterministic pre-check and review by several models; governance files
  are protected; rollback to a reviewed state needs no review. Over 161
  days it blocked 63.5% of its recent self-edits; one trial was found to
  have cheated. Implication: review-free rollback.
* **AgentDevel (2601.04620).** Treats agent improvement as release
  engineering: one version line, a critic that sees only traces, one
  release candidate at a time, promoted only if it fixes more than it
  breaks. Without that gate, regressions rose from 3.1% to 14.8% and four
  bad releases shipped; a critic that could see the code doubled regressions.
  Implication: show what a change could break.
* **Recursive Self-Evolving Agents via Held-Out Selection, RSEA
  (2606.28374).** Rewrites a three-layer text state from its own runs and
  keeps it only if a separate validation set does not get worse, else
  reverts to empty. 69.3% against 64.6% on ALFWorld; without the gate,
  100% on the learning tasks and a 33-point drop on new ones. Implication:
  when in doubt, no skill.
* **The Red Queen Gödel Machine (2606.26294).** Lets the evaluator evolve
  too, but only against a fixed anchor the agent cannot touch. Implication:
  review criteria stay fixed and user-anchored.
* **Harness Handbook (2607.13285).** An index from behaviours to code,
  checked against the repository, with stale entries frozen. About editing
  harness code. Implication: none for a personal agent.
* **EvoSafeHarness (2609.05903).** Evolves safety rules from failure
  traces, with a fresh-context critic that rejects rules keyed to test
  artefacts. Attack success fell from 45.6% to 10.0%; without the critic,
  scores on new tasks fell 9 to 31 points, and 38.2% of proposed improvements
  did not generalise. Implication: the pattern scan is the brittle layer.
* **HarnessDev (2609.01437).** Benchmarks models that build their own
  harness. Gains on the feedback set shrank to a third on held-out tasks;
  of 64 version changes only 2 clearly improved; agents picked their best
  version 2 times in 9. Implication: the user promotes, versions are kept.
* **PAST-Bench (2608.04003).** Tests personal agents, Hermes among them, on
  four kinds of persistence in fresh sessions with memory on and off.
  Hermes gained +0.13 to +0.24 overall; reusing procedures was weakest
  (+0.05 to +0.19) because workflows stay as transcript text; after a
  correction the old answer won next time. A modified Hermes with typed,
  supersedable bindings doubled its update score. Implication: entries
  that replace older ones; procedures as skills.
* **Darwin Gödel Machine (2505.22954).** An archive of coding agents that
  edit their own code, scored on SWE-bench. 20% to 50% over 80 iterations
  at about $22,000 a run. In a side experiment a descendant raised its
  hallucination score by deleting the hidden markers the checker used,
  and cheated more when it could see the checker. Implication: scanner
  and review instructions hidden and unwritable.
* **Huxley-Gödel Machine (2510.21614).** Values an agent version by how
  well its descendants do, not by its own score; that measure predicted
  real improvement far better (0.78 against 0.29). Implication: judge a
  skill by the sessions that used it.
* **Learning to Learn-at-Test-Time, Meta-TTL (2604.00830).** A meta-agent
  rewrites the actor's prompt after each episode in six sections. Removing the
  fact bank halved in-distribution performance but improved out-of-distribution
  performance: facts overfit, strategies transfer. Implication: the shape of
  the review's output.
* **Group-Evolving Agents (2602.04837).** Evolves groups of agents sharing
  patches and logs. 71.0% on SWE-bench Verified at about $13,000 a run; the
  winners changed workflows and tools, not prompts. Implication: none for
  a personal agent.

### A.4 Stanford CS329A readings

* **Cartridges (2506.06266).** Compresses a corpus into a small trained
  cache by generating diverse synthetic questions about it. 38.6 times less
  memory at the same quality; diversity of questions mattered. Implication:
  by analogy only, write memory as answers to varied questions.
* **CacheBlend (2405.16444).** Reuses cached chunks that are not a prefix
  by recomputing a few tokens; needs the serving engine. Implication: only
  exact-prefix caching exists for a client, so stable text first (§12,
  finding 7).
* **MemGPT (2310.08560).** The model pages between a fixed context and an
  external store, warned at 70% and flushed at 100%. GPT-4 recall rose from
  32.1% to 92.5%. Implication: the 70% reminder.
* **Shrinking the Generation-Verification Gap with Weak Verifiers, Weaver
  (2506.18203).** Combines many weak checkers. 87.7% against 72.2% for
  a vote and 91.9% for an oracle, at very large cost. Implication: no
  best-of-N without a real check.
* **Archon (2409.15254).** Searches over inference-time architectures.
  Large gains on benchmarks at about five times the cost, "most effective
  with 70B+". Implication: none for a personal agent.
* **Scaling LLM Test-Time Compute Optimally (2408.03314).** Allocates
  compute by difficulty; easy problems favour revising one attempt, hard
  ones parallel search. Implication: revise first.
* **How Do Large Language Monkeys Get Their Power Laws (2502.17578).**
  More samples help only when the first attempt already has a fair chance.
  Implication: none beyond §8.3.
* **SPRINT (2506.05745).** Parallelises reasoning steps after fine-tuning;
  about one point. Implication: none for a personal agent.
* **ADaPT (2311.05772).** Tries the whole task, then decomposes only on
  failure. ALFWorld 71.6% with GPT-3.5 against 43.3% for ReAct; weak executors
  gained most; the agent's own judgement of success was 30 points too high.
  Implication: decompose on objective failure.
* **CodeMonkeys (2501.14723).** Many parallel attempts with tests, then
  selection. 57.4% solved with a correct candidate present for 69.8%,
  at $4.60 a problem; shared context first for caching. Implication: no
  parallel candidates by default; stable prefix first (§12, finding 7).
* **KernelBench (2502.10517).** Iterating on compiler, correctness and
  profiler feedback beat fresh sampling in five of six cases at the same
  budget. Implication: retry on the evidence.
* **Improving Parallel Program Performance with LLM Optimizers via
  Agent-System Interfaces (2410.15625).** A small language plus explained
  feedback: 80% first-try success against 0% for raw C++. Implication:
  narrow tools that explain their errors.
* **Measuring AI Ability to Complete Long Tasks (2503.14499).** The task
  length at which agents succeed half the time doubles about every seven
  months; at 80% reliability it is four to six times shorter; repeating a
  failed action caused 12 of 31 failures for one model. Implication: the
  repeated-call note.
* **GDPval (2510.04374).** Expert grading of real work; most losses were
  formatting and instruction-following. Implication: the review checks for
  such corrections.
* **Search-o1 (2501.05366).** Condenses retrieved documents against the
  current reasoning before using them; raw insertion hurt a coding score
  (24.1 against 33.0), condensing restored it. Implication: summaries
  from helpers.
* **ReAct (2210.03629).** Interleaves reasoning and actions; loops on
  repeated actions with greedy decoding; small prompted models did worst.
  Implication: the repeated-call note.
* **Language Agent Tree Search, LATS (2310.04406).** Tree search over
  attempts: 1.7 points over Reflexion at about 173,000 tokens a task.
  Implication: do not add tree search.

### A.5 Prompt optimisation, evaluation and essays

* **GEPA (2507.19457).** Evolves prompts from reflection on traces, keeping
  a frontier of candidates each best on some task. +9.6 average against
  +3.7 for reinforcement learning with far fewer rollouts; most of the
  budget goes to validation. Implication: accept a change only if it wins
  somewhere and loses nowhere.
* **SePO (2606.04465).** A frontier model rewrites another model's system
  prompt from batches of failures. +4.5 over a manual prompt at $2 to $38
  a task; TextGrad scored below the manual prompt on three of five tasks.
  Implication: keep user-written prompts.
* **PROMST (2402.08702).** Hand-written error templates fire mechanically
  and feed a prompt writer. GPT-3.5 0.13 to 0.32 on agent tasks; prompts tuned
  for one model did not transfer. Implication: mechanical failure signatures.
* **Prompt Optimization with Human Feedback (2405.17346).** A bandit over
  pairs shown to a human; needs embeddings and a neural model. Implication:
  the user's accept or reject is a useful signal; nothing else.
* **Tournament of Prompts (2506.00178).** Elo ratings from debates judged
  by a strong model; weak judges erased the gains (5 to 7 points). Implication:
  no self-judging with a small model.
* **Trace (2406.16218).** Treats a workflow as a graph the optimiser edits
  from feedback. Implication: the review should see the trace, which it does.
* **Agent-as-a-Judge (2410.10934).** Grades agents by checking each
  requirement of a task. 88 to 90% agreement with a human majority against
  60 to 84% for a plain model judge; locating and reading files gave the
  reliability; a memory module hurt. Implication: checklists a program
  can grade.
* **EVE-Agent (2605.22905).** Keeps a piece of evidence only if it changes
  the solver's accuracy with it against without. Trains weights. Implication:
  with-and-without is the acceptance test.
* **Reflexion (2303.11366).** A short reflection after a failed attempt,
  capped at one to three entries. HumanEval 80% to 91% with GPT-4; on MBPP
  it fell 80.1 to 77.1 because 16.3% of self-written tests passed wrong
  code. Implication: never let a model-written test be the check.
* **Symbolic Learning Enables Self-Evolving Agents (2406.18532).** Treats
  prompts, tools and pipeline as weights; gains of a point or two; relies
  on rollback. Implication: everything learned must be revertible.
* **Adaptive Self-improvement for ML Library Development (2502.02534).**
  Builds an experience pool of verified solutions, deduplicated, shortest
  kept, hardest retrieved first. Claude 3.5 Sonnet 0.346 to 0.885 on 26
  tasks. Implication: prefer worked examples that needed retries; keep the
  shortest verified one.
* **Self-Evolving Curriculum (2505.14970).** A curriculum for training;
  easy-to-hard ordering was often worse than random. Implication: none for
  a personal agent.
* **Anthropic, "When AI Builds Itself" (2026).** Essay: humans still choose
  the problems and write the rubrics. Implication: the user writes the
  bench tasks .
* **X. Tu, "The What & When of Self-Evolving Agents" (2026).** A taxonomy
  of what evolves and how long it persists. Names the failure modes: memory
  without a write, read and evaluation policy "becomes another noisy tool";
  "stale skills can be worse than no skills". Implication: a lifecycle for
  every entry.
* **Weco, "AIDE²" (2026).** An outer agent rewrote an inner agent's code
  for 100 steps over eight days, keeping a change only if private held-out
  scores rose. Seven changes kept, about nine of ten rejected; one accepted
  change compressed the prompt 16 times; no runaway improvement. Implication:
  without a private score most proposals are regressions.
* **RSI-Bench.** A proposed benchmark with six axes; nothing evaluated yet.
  Implication: the three-way verdict with a confidence interval.

### A.6 Tools and interfaces

* **DRAFT, "From Exploration to Mastery" (2410.08197).** Rewrites tool
  documentation from trial-and-error use of the tool. Completion rose 12
  to 17 points across GPT-4o, GPT-4o-mini and Llama-3-70B; documentation
  written with one model helped the others; best after three or four rounds.
  Implication: `tooldocs`.
* **MCP-Zero (2506.01056).** The model requests tools by describing what it
  needs instead of receiving a list. 98% fewer tokens on APIBank across
  nearly 3,000 tools. Implication: confirms the search, describe and
  call bridge.
* **Alita (2505.20286).** Abstract only: a minimal agent that writes MCP
  tools for itself; 75.15% pass@1 on GAIA. Implication: none for a personal
  agent.
* **MetaAgent (2508.00271).** Abstract only: distils tool-use experience
  into short texts added to later prompts. Implication: none for a personal
  agent beyond what memory already does.

### A.7 The survey

* **Self-Improvements in Modern Agentic Systems: A Survey (2607.13104).**
  Formalises an agent as a model plus its scaffolding (prompts, memory,
  tools, control logic) and self-improvement as a lasting change to
  either. Its evaluation chapter asks for learning curves under a fixed
  budget, held-out transfer, regression rates, cost including human effort,
  and a judge independent of the one used for learning. Its discussion
  chapter gives three design rules: explore fast at the scaffold level and
  consolidate slowly; treat the critic as governed infrastructure separate
  from what it judges; and gate every lasting change through layered checks
  with rollback. Implication: the bench's measures, the fixed and hidden
  checks, rollback.

# Appendix B. Hermes Agent: facts and file references

All at commit `d0288be5b3` (2026-09-26). Paths are relative to the
repository root.

| Fact | Where |
| --- | --- |
| Review trigger: user turns since the last `memory` call and tool rounds since the last `skill_manage` call, threshold 10; the fork shares prompt, tools and session id, is capped at 16 iterations and does not persist. | `agent/background_review.py` |
| "Be ACTIVE — most sessions produce at least one skill update, even if small. A pass that does nothing is a missed learning opportunity, not a neutral outcome." and "'Nothing to save.' is a real option but should NOT be the default." | `_SKILL_REVIEW_PROMPT`, `_COMBINED_REVIEW_PROMPT` in the same file |
| The lesson-layer rules (procedure first; a pitfall is a rule plus one clause of why; no incident narration; one lesson once; do not duplicate always-loaded context; fix in place) and the "Do NOT capture" list. | `_LESSON_LAYER_BLOCK`, `_DO_NOT_CAPTURE_BLOCK` |
| Routing of facts to `USER.md` or `MEMORY.md`, after the double-write incident (#30220). | `_MEMORY_ROUTING_BLOCK` |
| Protected skills: bundled, hub-installed, external, pinned, user-owned; the reviewer edits only `created_by: agent` skills. | the same prompts; `tools/skill_usage.py` |
| Memory: two files, entries separated by `\n§\n`, budgets 2,200 and 1,375 characters, atomic batch of add, replace and remove, checked on the final state under a file lock, with a threat scan. | `tools/memory_tool_store.py` |
| Skill usage ledger: `use_count`, `view_count`, `activity_count`, `last_used_at`, provenance, state (active, stale, archived), pinned; no outcome field. | `tools/skill_usage.py` |
| Curator: idle two hours, at most weekly; stale after 14 days, archived after 30; never deletes; model-driven consolidation off by default; its prompt says not to use usage counts as evidence. | `agent/curator.py` |
| Focused manual review, `/refine [instructions]`. | `spawn_background_review_thread`, `focus` argument |
| Verification nudge before declaring code done, at most three per turn. | `agent/verify_hooks.py` |
| Tests of the review: toolset restriction, cache parity, focus. | `tests/agent/test_background_review*.py`, `test_refine_focus.py` |
| Evaluations: 69 entries, none of learning quality; the memory one is a plugin plumbing probe. | `evals/`, `evals/memory/honcho_current_query.py` |
| Session search returns stored messages, no model summarisation, despite the README. | `tools/session_search_tool.py:8` |
| README claim: "the only agent with a built-in learning loop". | `README.md:19` |
