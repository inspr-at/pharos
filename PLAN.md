# Pharos Unified Host Workflow UI — Product Plan

**Status**: Planning phase  
**Ticket**: Internal planning (no PPM ticket per user request)  
**Author**: Cursor Agent (Cloud)  
**Date**: 2026-08-25  

---

## Executive Summary

Markus identified a critical UX gap: host workflow state is poorly surfaced on Fleet cards, and workflow interactions are inconsistent. Users see "change waiting," "change requested," or "ready to apply" status chips but no clear path to act. Clicking dumps users into host settings rather than presenting a professional flow sheet with continue/approve/cancel/rollback actions.

This plan proposes a **unified three-tier workflow pattern** for all host operations:

1. **Invoke** — Clear primary action or menu item to start a workflow
2. **Card status chip** — Persistent, short-form state indicator while work is in progress
3. **Detail sheet** — Click-through flow panel with steps, evidence, and workflow-specific actions

All four backend workflow kinds (`SettingsChange`, `SystemUpdateProposal`, `UpdateRestart`, `RemoveHost`) plus future flows (onboard, backup restore, rollback, reboot-only, mute prefs) will follow this pattern.

---

## Current State Analysis

### Existing Infrastructure

Pharos already has the foundation for unified workflows:

**Backend** (`crates/pharosd/src/host_actions.rs`):
- Four workflow kinds: `SettingsChange`, `SystemUpdateProposal`, `UpdateRestart`, `RemoveHost`
- Twelve action states from `ProposalRequested` to `Succeeded`/`Failed`/`Cancelled`
- Workflow summaries with title, guidance, status label/level, steps, evidence, events
- Per-workflow step definitions with state (queued, running, waiting, passed, failed, skipped)
- Execution location markers (GitHub, Pharos, target host)

**Frontend** (`crates/pharosd/assets/ui/foot.html`):
- Host actions menu (ellipsis button) with primary actions and separators
- Status chip (`data-host-action-note`) showing brief workflow state
- Status dot indicator when workflows or kernel updates are pending
- Dialog system (`openHostActionDialog`) with workflow/technical/removal modes
- Workflow sheet renderer (already exists for displaying step lists)
- Polling system for live workflow updates

**UI State Injection** (`crates/pharosd/src/ui.rs`):
- `host_actions_markup` generates card/row action buttons with workflow context
- `card_action_note` status chip is rendered but currently shows generic state labels
- Fleet cards and list rows carry `data-host-actions` with all context attributes
- Workflow summaries serialized to JSON for client-side rendering

### Current Problems

#### 1. **Settings workflows dump into host settings form**

When a `SettingsChange` workflow is active (state: `ProposalRequested`, status: "change waiting" or "saving settings"), clicking the status chip opens:

```javascript
// foot.html line 526-528
const kind=root.dataset.actionKind;
const action=kind==='update_restart'?'update-restart':'workflow';
openHostActionDialog(action,root,actionNote);
```

**Problem**: The `actionKind` attribute is never set on `data-host-actions` elements. The code defaults to `'workflow'` mode, but the workflow dialog is only partially implemented. In practice, many settings-change clicks route users to the host settings form instead of showing workflow progress.

**Impact**: Users see "change waiting" but have no professional view of:
- What settings were requested
- Whether the delivery workflow accepted the request
- Whether the host has reported the new settings yet
- How to cancel the workflow if needed

#### 2. **Update-restart workflows work, but the pattern isn't generalized**

`UpdateRestart` workflows open a proper detail sheet with:
- Title and guidance text
- Step list with icons (queued → running → passed → failed → skipped)
- Evidence table (changed files, backup gate, kernel versions)
- Event log (who requested, when confirmed, etc.)
- Primary action button (varies by state: "Confirm restart", "Retry", etc.)
- Cancel button when cancellation is safe

**Problem**: This is special-cased for `update-restart` only. The pattern should apply to all workflows.

#### 3. **Status chips are visible but not consistently clickable**

The `data-host-action-note` chip shows workflow state:

```html
<button class="settings-wait-note host-action-note" type="button" data-host-action-note hidden>
  {icon}<span data-host-action-note-copy></span>
</button>
```

**Visibility logic** (`foot.html` line 507-511):
- Show if host is retired (removal pending)
- Show if a workflow job exists and state is not `succeeded` or `cancelled`
- Text: `workflow.status_label` or generic state label
- Level: `workflow.status_level` (clear/info/watch/warning/recovery)

**Click handler** (`foot.html` line 520-530):
- Clicks are intercepted, surface and root are located
- Opens dialog in either `'update-restart'` or `'workflow'` mode
- But `'workflow'` mode is incomplete and often doesn't show useful info

**Problem**: The chip is clickable, but the click doesn't always produce a professional workflow view. Users get inconsistent experiences depending on workflow kind.

#### 4. **System update proposals have no persistent card indicator**

A `SystemUpdateProposal` workflow creates a saved job (state: `ProposalRequested` → `Succeeded`/`Failed`), but:
- No status chip appears on Fleet cards during the workflow
- The workflow completes (or fails) with no visible card-level feedback
- Users must open the actions menu and check for "Review pending" or refresh the page

**Problem**: Fleet-wide review workflows are invisible at card level. Operators don't know a proposal is running unless they drill into the ops log.

#### 5. **No removal progress on cards**

When `RemoveHost` is triggered:
- Workflow states: `ProposalRequested` → `RemovalPending` → `Succeeded`/`Failed`
- Card shows "removal pending" status chip (via retired host check)
- Clicking opens workflow dialog with removal evidence (disposition, successor, credential retirement status)

**Good**: Removal workflows already open a detail sheet.  
**Gap**: No visual progression through the removal steps (access revoked, declaration removed, credentials retired).

#### 6. **No clear primary action for active workflows**

When a workflow is in progress:
- The ellipsis menu shows all available actions (settings, system update, apply restart, remove)
- No visual indicator that one of these is the "next step" for an active workflow
- Example: If an update-restart workflow is at `AwaitingConfirmation`, the "Apply update and restart" menu item should be visually promoted (but it's not)

**Problem**: Users must remember which workflow they started and hunt for the continue action in the menu.

---

## Proposed Unified Pattern

### Three-Tier Interaction Model

Every host workflow follows this pattern:

#### Tier 1: Invoke

**Primary actions** (visible in actions menu or as inline chip):
- "Host settings" (link to settings form)
- "Review pending settings" (when settings workflow exists)
- "Check for system updates" (triggers `SystemUpdateProposal`)
- "Apply update and restart" (triggers `UpdateRestart`)
- "Remove host" (triggers `RemoveHost`)

**Future actions** (v2+):
- "Onboard to Janus" (setup privileged actions)
- "Restore from backup" (disaster recovery)
- "Roll back to previous generation" (undo last change)
- "Reboot host" (kernel-only restart)
- "Mute host alerts" (temporary silence)

**Invocation rules**:
- Primary actions are always clear, labeled buttons/links
- Actions are hidden when preconditions aren't met (e.g., no Janus → no update-restart)
- Actions are disabled (with tooltip) when preconditions are temporarily unmet (e.g., backup not ready)
- Starting a workflow navigates to the detail sheet immediately (don't silently background it)

#### Tier 2: Card Status Chip

**When to show**:
- A workflow job exists and is not in a terminal state (`Succeeded`, `Cancelled`)
- Host is retired (`RemovalPending` or later)
- Kernel reboot is required (special case: not a workflow, but actionable state)

**Chip contents**:
- **Icon**: History/clock for in-progress, warning triangle for needs-attention, checkmark for recently-completed
- **Text**: Short status label from `workflow.status_label`:
  - "saving settings" (recording request)
  - "change waiting" (waiting for host to report)
  - "settings applied" (recently succeeded)
  - "review requested" (system update proposal sent)
  - "update review ready" (awaiting confirmation)
  - "restart confirmed" (applying changes)
  - "removal pending" (host being removed)
  - "update stopped" (failed, needs review)
- **Color**: Derived from `workflow.status_level`:
  - `clear`: green/success (recently completed)
  - `info`: blue (informational)
  - `watch`: amber (in progress, non-urgent)
  - `warning`: orange (needs attention)
  - `recovery`: purple (recovery/rollback mode)

**Click behavior**:
- Always opens the detail sheet for the active workflow
- If multiple workflows exist (rare), show the highest-priority one
- Priority order: `UpdateRestart` > `RemoveHost` > `SettingsChange` > `SystemUpdateProposal`

**Auto-hide**:
- Chip remains visible for 15 minutes after workflow reaches `Succeeded`
- Chip hides immediately on `Cancelled`
- Chip persists indefinitely on `Failed` (operator must acknowledge)

#### Tier 3: Detail Sheet

**Sheet structure** (consistent for all workflows):

```
┌─────────────────────────────────────────────────┐
│ [workflow icon] Workflow Title            [×]   │
│ Guidance: One-sentence state explanation        │
│                                                  │
│ ┌─────────────────────────────────────────┐    │
│ │ [Primary Action Button]   [Cancel/Undo] │    │
│ └─────────────────────────────────────────┘    │
│                                                  │
│ Steps                                            │
│ ─────                                            │
│ [●] Step 1: Validate settings                    │
│     ✓ Completed 2m ago · GitHub                  │
│                                                  │
│ [◐] Step 2: Send change request                 │
│     ⟳ Running · Pharos                           │
│                                                  │
│ [○] Step 3: Wait for host report                │
│     Queued                                       │
│                                                  │
│ Evidence                                         │
│ ────────                                         │
│ Tracking      PHAROS-123                         │
│ Delivery      accepted                           │
│ Host report   not observed yet                   │
│                                                  │
│ Events                                           │
│ ──────                                           │
│ 14:23  Requested by alice@example.com            │
│ 14:24  Delivery workflow accepted request        │
│                                                  │
│ [Technical Details ▾]                            │
└─────────────────────────────────────────────────┘
```

**Sheet components**:

1. **Header**
   - Workflow icon (varies by kind)
   - Title: `workflow.title` (e.g., "Change lab-01 settings")
   - Guidance: `workflow.guidance` (contextual one-liner)
   - Close button (× in corner)

2. **Action bar**
   - **Primary button**: Derived from `workflow.primary_action`
     - "Confirm restart" (when `UpdateRestart` at `AwaitingConfirmation`)
     - "Retry" (when failed with retry available)
     - "Review proposal" (link to GitHub PR when `SystemUpdateProposal` dispatched)
     - Hidden when no action is available
   - **Cancel button**: When `workflow.can_cancel` is true
     - Marks workflow as `Cancelled` (safe abort)
     - Disabled when cancellation would be unsafe (e.g., mid-apply)
   - **Rollback button** (future): When recovery mode is available
     - Triggers rollback to previous generation
     - Only for `UpdateRestart` workflows that have `rollback_available: true`

3. **Steps list**
   - Each step from `workflow.steps[]`:
     - Icon: State-based (queued, running, waiting, passed, failed, skipped)
     - Label: `step.label` (e.g., "Validate backup gate")
     - Detail: `step.detail` (explanatory text)
     - Timestamp: When step completed
     - Location: `step.location` (GitHub, Pharos, target host)
   - Current step is highlighted (different background)
   - Failed steps show error detail (from evidence or events)

4. **Evidence table**
   - Key-value pairs from `workflow.evidence[]`:
     - "Tracking" → ticket ID
     - "Changed files" → count
     - "Backup validated" → passed/failed
     - "Kernel verification" → passed/failed
     - "Credential retirement" → complete/pending/failed
   - Evidence is workflow-specific (not all keys appear in all workflows)

5. **Events timeline**
   - Chronological log from `workflow.events[]`:
     - Timestamp (formatted as time-of-day, with date if not today)
     - Label: Event description (e.g., "Requested by alice", "Host reported new settings")
     - Actor: Who triggered the event (browser user, agent, host)

6. **Technical details** (collapsible)
   - Host facts: name, role, live state, declared, Janus-ready
   - Workflow metadata: run ID, created/updated timestamps, duration
   - For debugging, not primary operator UI

**Sheet behavior**:
- Opens over Fleet view (modal overlay, dims background)
- Auto-refreshes via polling when workflow is not terminal
- Keyboard: Escape to close, Tab to navigate actions
- Accessible: ARIA labels, focus management, screen-reader friendly

**Per-workflow variations**:

| Workflow Kind           | Title Pattern                  | Primary Action                  | Key Evidence                          |
|-------------------------|--------------------------------|----------------------------------|---------------------------------------|
| `SettingsChange`        | "Change {host} settings"       | None (observe-only)             | Delivery status, host report          |
| `SystemUpdateProposal`  | "Review system updates"        | "View proposal" (GitHub link)   | Repository dispatch status            |
| `UpdateRestart`         | "Apply update and restart"     | "Confirm restart"               | Backup gate, kernel versions, rollback|
| `RemoveHost`            | "Remove {host} from Pharos"    | "Retry retirement" (if failed)  | Disposition, credential retirement    |

---

## Per-Flow Specifications

### 1. Settings Change (`SettingsChange`)

**Invoke**:
- **Primary entry**: "Host settings" link in actions menu → opens settings form
- **Alternate entry**: "Review pending settings" menu item (when workflow exists) → opens detail sheet

**Card status chip**:
- Show when workflow exists and state is `ProposalRequested` or `Succeeded` (for 15 min)
- Text: "saving settings" → "change waiting" → "settings applied"
- Level: `watch` → `watch` → `clear`
- Click: Opens detail sheet

**Detail sheet**:
- **Steps**:
  1. Validate the selected settings (passed)
  2. Send the change request (running/passed/failed)
  3. Wait for the host (waiting/passed/skipped)
  4. Save the result (queued/passed)
- **Primary action**: None (observe-only workflow)
- **Cancel action**: Not available (settings requests can't be canceled once accepted)
- **Evidence**:
  - Tracking: PHAROS-nnn
  - Delivery: recording/accepted/stopped
  - Host report: not observed yet / requested settings observed
- **Forbidden actions**:
  - ❌ No silent dump into settings form
  - ❌ No "Apply now" button (host pull-based, not push)

**State diagram**:

```
ProposalRequested → (delivery accepted) → (host reports) → Succeeded
                 ↘ (delivery rejected) → Failed
```

**v1 scope**:
- ✅ Show status chip on cards
- ✅ Detail sheet with steps, evidence, events
- ✅ "Review pending settings" menu item

**v2+ scope**:
- Show diff preview (old vs new settings values) in detail sheet
- Link to GitHub PR when settings change requires nixcfg update
- Retry action when delivery fails

---

### 2. System Update Proposal (`SystemUpdateProposal`)

**Invoke**:
- **Primary entry**: "Check for system updates" in actions menu → creates workflow, opens detail sheet immediately

**Card status chip**:
- Currently: ❌ Not shown
- Proposed: ✅ Show during `ProposalRequested` state
- Text: "review requested" → "update review completed" / "update review stopped"
- Level: `info` → `clear` / `warning`
- Click: Opens detail sheet with link to GitHub PR

**Detail sheet**:
- **Steps**:
  1. Validate the update request (passed)
  2. Dispatch to repository (running/passed/failed)
  3. Save the proposal (queued/passed)
- **Primary action**: "View proposal in GitHub" (link, when dispatch succeeded)
- **Cancel action**: Not available (proposals are fire-and-forget)
- **Evidence**:
  - Tracking: PHAROS-nnn
  - Repository dispatch: recording/accepted/stopped
  - Live host change: not authorized (clarifies this is review-only)

**v1 scope**:
- ✅ Show status chip on cards during proposal
- ✅ Detail sheet with GitHub link when available
- ✅ Auto-hide chip after 15 minutes on success

**v2+ scope**:
- Inline preview of update diff (files changed, hosts affected)
- Poll GitHub PR status and show checks passing/failing
- "Apply to {host}" quick action from completed proposal

---

### 3. Update and Restart (`UpdateRestart`)

**Invoke**:
- **Primary entry**: "Apply update and restart" in actions menu → creates workflow, opens detail sheet
- **Alternate entry**: "Continue update workflow" (when workflow exists at `AwaitingConfirmation`) → opens detail sheet

**Card status chip**:
- Show from `QueuedReview` to `Succeeded`/`Failed`/`Cancelled`
- Text: "review queued" → "review running" → "review ready" → "restart confirmed" → "update running" → "restarting" → "update completed" / "needs verification"
- Level: `watch` → `watch` → `watch` → `warning` → `warning` → `warning` → `clear` / `warning`
- Click: Opens detail sheet

**Detail sheet**:
- **Steps** (typical flow):
  1. Validate backup gate (waiting/passed/failed)
  2. Prepare target build (queued/running/passed/failed)
  3. Confirm with operator (waiting/passed/cancelled)
  4. Apply update (queued/running/passed/failed)
  5. Restart host (queued/running/passed/failed)
  6. Verify kernel (queued/running/passed/failed)
  7. Save result (queued/passed)
- **Primary action**:
  - "Confirm restart" (when `AwaitingConfirmation`)
  - "Retry" (when `Failed` before confirmation)
  - None (when in-flight or succeeded)
- **Cancel action**: Available when state is `QueuedReview`, `Reviewing`, or `AwaitingConfirmation`
- **Rollback button** (v2): "Roll back to previous generation" (when `Failed` after apply and `rollback_available: true`)
- **Evidence**:
  - Changed files, changed areas, all-host validation, target build, backup gate, restart required
  - Running kernel, expected kernel (during and after)
  - Backup validation, reviewed switch, restart observed, kernel verification, rollback posture (after apply)
  - Stopped at: {gate} (when failed)
  - Recovery mode: {mode} (when in recovery)

**v1 scope**:
- ✅ Full detail sheet (already implemented)
- ✅ Status chip on cards (already implemented)
- ✅ Confirm and cancel actions
- ✅ Evidence table with backup/kernel details

**v2+ scope**:
- Rollback button (when safe and available)
- Inline diff preview (changed files, before/after)
- Real-time log streaming during apply/reboot phases

---

### 4. Remove Host (`RemoveHost`)

**Invoke**:
- **Primary entry**: "Remove host" in actions menu → opens removal confirmation dialog
- **After confirmation**: Creates workflow, opens detail sheet

**Card status chip**:
- Show from `ProposalRequested` to `Succeeded`/`Failed`
- Text: "removal preparing" → "removal pending" → "removed from Pharos" / "removal stopped"
- Level: `watch` → `warning` → `clear` / `warning`
- Click: Opens detail sheet

**Detail sheet**:
- **Steps**:
  1. Validate removal plan (passed)
  2. Revoke access (queued/running/passed/failed)
  3. Remove declaration (queued/running/passed/skipped)
  4. Retire credentials (queued/running/passed/failed)
  5. Save result (queued/passed)
- **Primary action**: "Retry credential retirement" (when failed at retirement step)
- **Cancel action**: Not available (removal can't be canceled once started)
- **Evidence**:
  - Tracking: PHAROS-nnn
  - Host disposition: destroyed/unmanaged/rebuilt
  - Successor: {host} (if rebuilt)
  - Declarative cleanup: pending/complete/not required
  - Credential retirement: pending/running/complete/action required
  - Credential retirement stopped at: {reason} (if failed)

**v1 scope**:
- ✅ Detail sheet with removal evidence
- ✅ Status chip on cards
- ✅ Retry action for credential retirement failures

**v2+ scope**:
- Inline successor setup (create new host immediately after removal)
- "Undo removal" action (very short window, requires backup)

---

### 5. Future Workflows (v2+)

These workflows don't exist yet but should follow the same pattern when implemented:

#### Onboard to Janus

**Purpose**: Set up privileged action guards for a host

**Invoke**: "Onboard to Janus" in actions menu (when `janus_ready: false` and operator has Janus access)

**Steps**:
1. Validate host eligibility (Nix, declared, not retired)
2. Provision Janus identity
3. Register with Janus policy
4. Verify handshake
5. Save onboarded state

**Evidence**: Janus identity, policy URL, handshake status

**Primary action**: None (automated flow)

**Cancel**: Available before handshake completes

#### Restore from Backup

**Purpose**: Roll back a host to a previous backup snapshot

**Invoke**: "Restore from backup" in actions menu → opens backup selector, then creates workflow

**Steps**:
1. Select backup snapshot
2. Validate backup integrity
3. Confirm with operator (destructive action)
4. Stop services on target
5. Restore data
6. Restart host
7. Verify restoration

**Evidence**: Backup ID, backup date, integrity check, services stopped, restoration result

**Primary action**: "Confirm restoration" (after validation)

**Cancel**: Available before restoration starts

#### Roll Back to Previous Generation

**Purpose**: Undo last system update without full backup restoration

**Invoke**: "Roll back to previous generation" in actions menu (when `rollback_available: true`)

**Steps**:
1. Validate rollback target (previous Nix generation)
2. Confirm with operator
3. Switch to previous generation
4. Restart if needed
5. Verify kernel and services

**Evidence**: Previous generation ID, rollback reason, switch result, kernel match

**Primary action**: "Confirm rollback"

**Cancel**: Available before switch

#### Reboot Host

**Purpose**: Restart a host without applying updates (kernel-only reboot)

**Invoke**: "Reboot host" in actions menu (when kernel reboot is required but no update pending)

**Steps**:
1. Confirm with operator
2. Request reboot (via agent)
3. Wait for host down
4. Wait for host up
5. Verify kernel

**Evidence**: Reboot reason, downtime, kernel verification

**Primary action**: "Confirm reboot"

**Cancel**: Available before reboot request sent

#### Mute Host Alerts

**Purpose**: Temporarily silence alerts for a host (e.g., during maintenance)

**Invoke**: "Mute host alerts" in actions menu → opens duration picker, then creates workflow

**Steps**:
1. Set mute duration
2. Save mute state
3. (Auto-unmutes after duration)

**Evidence**: Mute duration, muted by, muted until, auto-unmute

**Primary action**: "Unmute now" (manual early unmute)

**Cancel**: Not applicable (instant action)

---

## Unified UI Component Specifications

### Status Chip Component

**HTML structure**:

```html
<button 
  class="settings-wait-note host-action-note" 
  type="button" 
  data-host-action-note 
  data-action-level="{level}"
  data-action-kind="{kind}"
  hidden
  aria-label="Open {workflow_title} workflow"
>
  <svg class="action-note-icon">{icon}</svg>
  <span data-host-action-note-copy>{status_label}</span>
</button>
```

**CSS classes by level**:

```css
.host-action-note[data-action-level="clear"] {
  background: rgba(34, 197, 94, 0.12);
  color: #166534;
  border-color: rgba(34, 197, 94, 0.24);
}

.host-action-note[data-action-level="info"] {
  background: rgba(59, 130, 246, 0.12);
  color: #1e40af;
  border-color: rgba(59, 130, 246, 0.24);
}

.host-action-note[data-action-level="watch"] {
  background: rgba(251, 191, 36, 0.12);
  color: #92400e;
  border-color: rgba(251, 191, 36, 0.24);
}

.host-action-note[data-action-level="warning"] {
  background: rgba(249, 115, 22, 0.12);
  color: #9a3412;
  border-color: rgba(249, 115, 22, 0.24);
}

.host-action-note[data-action-level="recovery"] {
  background: rgba(168, 85, 247, 0.12);
  color: #6b21a8;
  border-color: rgba(168, 85, 247, 0.24);
}
```

**Icon by level**:
- `clear`: Checkmark circle
- `info`: Info circle
- `watch`: Clock/history
- `warning`: Alert triangle
- `recovery`: Arrow-counterclockwise

**Visibility logic** (JavaScript):

```javascript
function updateHostActionNote(surface, job, workflow, retired) {
  const note = surface.querySelector('[data-host-action-note]');
  if (!note) return;
  
  const shouldShow = retired || (job && !['succeeded', 'cancelled'].includes(job.state));
  note.hidden = !shouldShow;
  
  if (shouldShow) {
    note.dataset.actionLevel = retired ? 'warning' : (workflow?.status_level || 'warning');
    note.dataset.actionKind = workflow?.kind || '';
    note.querySelector('[data-host-action-note-copy]').textContent = 
      retired ? 'removal pending' : (workflow?.status_label || 'workflow running');
  }
}
```

**Click handler**:

```javascript
document.addEventListener('click', event => {
  const note = event.target.closest('[data-host-action-note]');
  if (!note) return;
  
  event.preventDefault();
  const surface = note.closest('[data-host-surface="runtime"]');
  const root = surface?.querySelector('[data-host-actions]');
  if (!root) return;
  
  const kind = note.dataset.actionKind || root.dataset.actionKind;
  openWorkflowSheet(kind, root, note);
});
```

### Detail Sheet Component

**HTML structure** (simplified, full markup in `foot.html`):

```html
<section class="host-action-overlay" data-host-action-overlay hidden>
  <div class="host-action-backdrop" data-host-action-close></div>
  <article class="host-action-dialog host-workflow-dialog" data-host-action-dialog>
    <header class="host-action-head">
      <div class="host-action-title-row">
        <svg class="workflow-icon">{icon}</svg>
        <div>
          <h2 data-host-action-title>{workflow_title}</h2>
          <p data-host-action-guidance>{workflow_guidance}</p>
        </div>
      </div>
      <button data-host-action-close>×</button>
    </header>
    
    <div class="host-action-body">
      <div class="host-action-buttons">
        <button class="btn btn-primary" data-host-action-primary hidden>
          {primary_action_label}
        </button>
        <button class="btn btn-secondary" data-host-action-cancel hidden>
          Cancel workflow
        </button>
      </div>
      
      <section class="host-workflow" data-host-workflow>
        <div class="host-workflow-summary">
          <div class="host-workflow-group">
            <h3>Steps</h3>
            <div class="host-workflow-steps" data-workflow-steps>
              <!-- Steps rendered here -->
            </div>
          </div>
          
          <div class="host-workflow-group">
            <h3>Evidence</h3>
            <dl class="host-workflow-evidence" data-workflow-evidence>
              <!-- Evidence rendered here -->
            </dl>
          </div>
          
          <div class="host-workflow-group">
            <h3>Events</h3>
            <div class="host-workflow-events" data-workflow-events>
              <!-- Events rendered here -->
            </div>
          </div>
        </div>
      </section>
      
      <details class="host-action-technical">
        <summary>Technical details ▾</summary>
        <pre data-host-action-technical-content></pre>
      </details>
    </div>
  </article>
</section>
```

**Step rendering** (JavaScript):

```javascript
function renderWorkflowStep(step) {
  const stateIcons = {
    queued: '○',  // Hollow circle
    running: '◐', // Spinner
    waiting: '⏸', // Pause
    passed: '●',  // Filled circle (green)
    failed: '●',  // Filled circle (red)
    skipped: '⊘', // Strikethrough
  };
  
  const stateLabels = {
    queued: 'Queued',
    running: 'Running',
    waiting: 'Waiting',
    passed: 'Completed',
    failed: 'Failed',
    skipped: 'Skipped',
  };
  
  const locationLabels = {
    github: 'GitHub',
    pharos: 'Pharos',
    target_host: 'Target host',
  };
  
  return `
    <div class="host-workflow-step" data-step-state="${step.state}" data-current="${step.current}">
      <div class="host-workflow-marker" data-step-marker="${step.state}">
        ${stateIcons[step.state]}
      </div>
      <div class="host-workflow-step-copy">
        <strong>${step.label}</strong>
        <span>${step.detail}</span>
      </div>
      <div class="host-workflow-step-state">
        <span>${stateLabels[step.state]}</span>
        ${step.location ? `<small>${locationLabels[step.location]}</small>` : ''}
      </div>
    </div>
  `;
}
```

**Evidence rendering**:

```javascript
function renderWorkflowEvidence(evidence) {
  return evidence.map(item => `
    <div>
      <dt>${item.key}</dt>
      <dd>${item.value}</dd>
    </div>
  `).join('');
}
```

**Polling logic**:

```javascript
function startWorkflowPoll(workflowId, runId) {
  if (hostActionPoll.id === runId) return; // Already polling
  
  stopHostActionPoll();
  hostActionPoll.id = runId;
  hostActionPoll.lastRevision = '';
  
  async function poll() {
    try {
      const response = await fetch(`/api/workflow/${workflowId}`, {
        headers: { 'Accept': 'application/json' }
      });
      const data = await response.json();
      
      if (data.revision !== hostActionPoll.lastRevision) {
        renderWorkflowSheet(data.workflow);
        hostActionPoll.lastRevision = data.revision;
      }
      
      if (!data.workflow.terminal) {
        hostActionPoll.timer = setTimeout(poll, 2000); // Poll every 2s
      }
    } catch (err) {
      console.error('Workflow poll failed:', err);
      hostActionPoll.failures++;
      if (hostActionPoll.failures < 5) {
        hostActionPoll.timer = setTimeout(poll, 5000); // Back off
      }
    }
  }
  
  poll();
}
```

---

## v1 vs v2+ Roadmap

### v1 Scope (Immediate)

**Goal**: Unify existing workflows under the three-tier pattern

**Deliverables**:

1. **Settings workflows**:
   - ✅ Add `data-action-kind="settings_change"` to `data-host-actions` when settings workflow exists
   - ✅ Status chip shows on cards during settings workflows
   - ✅ Clicking chip opens detail sheet (not settings form)
   - ✅ "Review pending settings" menu item when workflow exists
   - ✅ Detail sheet shows steps, evidence (delivery status, host report), events

2. **System update proposals**:
   - ✅ Status chip shows during `SystemUpdateProposal` workflows
   - ✅ Detail sheet shows steps, evidence, GitHub link
   - ✅ Auto-hide chip 15 min after success

3. **Update-restart workflows**:
   - ✅ Already has detail sheet and status chip
   - ✅ Verify primary action button shows correctly at `AwaitingConfirmation`
   - ✅ Verify cancel button shows when safe

4. **Removal workflows**:
   - ✅ Already has detail sheet and status chip
   - ✅ Add retry action for credential retirement failures

5. **Chip auto-hide**:
   - ✅ Hide chip 15 min after `Succeeded` (except removal, which hides immediately)
   - ✅ Hide chip immediately on `Cancelled`
   - ✅ Keep chip visible indefinitely on `Failed`

6. **Workflow priority**:
   - ✅ When multiple workflows exist, chip shows highest-priority: `UpdateRestart` > `RemoveHost` > `SettingsChange` > `SystemUpdateProposal`

**Non-goals for v1**:
- ❌ No rollback button (v2)
- ❌ No inline diff preview (v2)
- ❌ No real-time log streaming (v2)
- ❌ No new workflows (onboard, restore, etc.) (v2+)

**Success criteria**:
- Settings workflows never dump into host settings form unexpectedly
- All four workflow kinds show status chips on cards when active
- All chips are clickable and open professional detail sheets
- Operators can cancel workflows when safe
- Failed workflows are visible and actionable

### v2 Scope (Follow-up)

**Goal**: Add recovery actions and richer workflow detail

**Deliverables**:

1. **Rollback button**:
   - Show on `UpdateRestart` detail sheet when `Failed` after apply and `rollback_available: true`
   - Triggers new workflow to revert to previous generation
   - Confirm with operator before executing

2. **Inline diff preview**:
   - Show changed files and areas in detail sheet
   - Link to GitHub PR/commit for full diff

3. **Real-time log streaming**:
   - Embed terminal-style log viewer in detail sheet during `Applying`, `Rebooting`, `Reviewing` phases
   - Poll log endpoint, auto-scroll, syntax highlighting

4. **Retry improvements**:
   - "Retry" button on all failed workflows (not just credential retirement)
   - Smart retry: skip passed steps, resume from failure point

5. **Workflow shortcuts**:
   - "Quick actions" card menu: bypass detail sheet for safe one-click actions
   - Example: "Confirm restart" directly from actions menu when `AwaitingConfirmation`

### v3+ Scope (Future)

**Goal**: New workflow types and automation

**Deliverables**:

1. **Onboard to Janus workflow**
2. **Restore from backup workflow**
3. **Roll back to previous generation workflow** (distinct from inline rollback button)
4. **Reboot host workflow**
5. **Mute host alerts workflow**
6. **Batch workflows**:
   - Select multiple hosts, trigger same workflow across fleet
   - Aggregate progress view

7. **Scheduled workflows**:
   - "Apply this update at 2 AM"
   - Cron-style recurring actions

---

## Risks and Mitigations

### Risk 1: Status chip noise

**Concern**: Too many status chips clutter Fleet cards

**Mitigation**:
- Auto-hide chips 15 min after success
- Hide cancelled workflows immediately
- Show only highest-priority workflow when multiple exist
- Use compact chip design (icon + short label, no padding waste)

**Validation**: Monitor chip count per card in production; tune auto-hide timeout if needed

### Risk 2: Detail sheet over-engineering

**Concern**: Operators want quick actions, not detailed flow sheets

**Mitigation**:
- Primary action button is always above the fold (no scrolling to confirm)
- Collapsible sections for evidence, events, technical details
- v2 adds "quick actions" menu shortcuts to bypass sheet for safe one-click actions

**Validation**: Track click-through rates: chip → sheet → action vs. menu → action

### Risk 3: Settings workflow confusion

**Concern**: Operators expect to edit settings in the detail sheet

**Mitigation**:
- Sheet is clearly labeled "observe-only" (no primary action button)
- "Edit settings" link in sheet footer (navigates to settings form)
- Guidance text explains: "Settings are pull-based. This workflow tracks host reporting."

**Validation**: User testing with 2-3 operators before release

### Risk 4: Polling performance

**Concern**: Hundreds of open detail sheets polling every 2s strain backend

**Mitigation**:
- Pause polling when browser tab is not visible (`visibilitychange` event)
- Stop polling when workflow reaches terminal state
- Server-side: workflow endpoints are read-only, fast, cacheable

**Validation**: Load test with 50 concurrent sheets open

### Risk 5: Workflow state desync

**Concern**: Client-side workflow state diverges from server truth

**Mitigation**:
- Poll interval is short (2s) for in-flight workflows
- Every poll fetches full workflow summary (no incremental updates)
- Revision field (`workflow.updated_at`) detects changes, triggers re-render

**Validation**: Stress test with rapid workflow state changes (manual agent triggers)

### Risk 6: Accessibility regression

**Concern**: New UI breaks screen readers or keyboard navigation

**Mitigation**:
- All chips are semantic `<button>` elements (not divs)
- Detail sheet has proper ARIA labels, roles, focus management
- Keyboard: Tab, Escape, Enter all work as expected
- Test with VoiceOver (macOS), NVDA (Windows)

**Validation**: Accessibility audit before v1 release

### Risk 7: Mobile layout breakage

**Concern**: Detail sheet is too wide for phone screens

**Mitigation**:
- Sheet is responsive (already uses `min(760px, 100vw)` width)
- Steps, evidence, events stack vertically on narrow screens
- Primary action button always visible (fixed bottom bar on mobile)

**Validation**: Test on iPhone SE, Android mid-range phone

---

## Implementation Notes

### Backend Changes

**Minimal**: Backend already provides all necessary data via `HostWorkflowSummary`.

**Required**:
1. Add `data-action-kind` attribute to `host_actions_markup` output (inject `workflow.kind` when job exists)
2. Ensure `SystemUpdateProposal` workflows serialize to ops feed (currently may be missing)

### Frontend Changes

**Major** (`crates/pharosd/assets/ui/foot.html`):

1. **Status chip logic** (line ~504-514):
   - Add `data-action-kind` to chip when workflow exists
   - Fix click handler to always route to detail sheet (never settings form for workflows)

2. **Detail sheet renderer** (line ~122-400):
   - Generalize `openHostActionDialog('workflow', ...)` to handle all four workflow kinds
   - Render steps, evidence, events from `workflow` object
   - Show primary action button based on `workflow.primary_action`
   - Show cancel button based on `workflow.can_cancel`
   - Start polling when workflow is not terminal

3. **Chip auto-hide**:
   - Track `workflow.state` and `workflow.updated_at`
   - Hide chip 15 min after `Succeeded` (client-side timer)
   - Hide immediately on `Cancelled`

4. **Menu updates**:
   - Add "Review pending settings" item (hidden when no settings workflow)
   - Change "Apply update and restart" label to "Continue update workflow" when workflow exists

**CSS** (`crates/pharosd/assets/ui/head.html`):

1. Add level-based chip colors (clear, info, watch, warning, recovery)
2. Add workflow step state styles (queued, running, waiting, passed, failed, skipped)
3. Ensure detail sheet is scrollable, responsive, accessible

### API Changes

**None required**. All workflow data is already serialized in `/` response (ops feed, host context).

**Optional** (v2): Add `/api/workflow/{run_id}` endpoint for dedicated workflow polling (reduces payload size vs. full page refresh).

---

## Success Metrics

### User Experience

- **Reduced confusion**: Settings workflows never dump into form unexpectedly
- **Increased transparency**: All active workflows visible on Fleet cards
- **Faster action**: Primary action button always visible in detail sheet
- **Fewer support tickets**: Operators understand workflow state without asking

### Technical

- **Chip visibility**: >90% of active workflows show status chip on cards
- **Click-through rate**: >70% of chip clicks open detail sheet successfully
- **Polling efficiency**: <5% CPU overhead per open detail sheet
- **Accessibility**: 100% WCAG 2.1 AA compliance (keyboard, screen reader)

### Adoption

- **Detail sheet usage**: >50% of workflow confirmations go through detail sheet (vs. direct menu actions)
- **Cancellation rate**: <5% of workflows cancelled (indicates clear intent, not confusion)
- **Retry rate**: <10% of failed workflows require retry (indicates robust gates)

---

## Appendix: Current vs. Proposed Behavior

### Scenario: Operator changes host color in settings form

**Current**:
1. Operator opens host settings form, changes color, saves
2. Settings workflow created (`SettingsChange`, state: `ProposalRequested`)
3. Fleet card shows... nothing? Or generic "change waiting" somewhere?
4. Operator refreshes page, sees "change waiting" status (maybe)
5. Operator clicks... and gets dumped back into settings form (unhelpful)
6. Operator confused: "Did my change save? Is it working?"

**Proposed**:
1. Operator opens host settings form, changes color, saves
2. Settings workflow created, detail sheet opens immediately
3. Sheet shows:
   - Title: "Change lab-01 settings"
   - Guidance: "Pharos is recording and sending the requested settings."
   - Steps: Validate ✓ → Send (running) → Wait (queued) → Record (queued)
   - Evidence: Delivery: recording
4. Operator closes sheet, returns to Fleet
5. Fleet card shows status chip: [🕐 saving settings]
6. 30 seconds later, delivery accepts, chip updates: [🕐 change waiting]
7. Host reports new color, workflow succeeds, chip updates: [✓ settings applied]
8. Chip auto-hides after 15 minutes

**Result**: Operator always knows workflow state, never confused, never dumped into wrong UI.

### Scenario: Operator triggers system update proposal

**Current**:
1. Operator opens actions menu, clicks "Check for system updates"
2. System update workflow created (`SystemUpdateProposal`, state: `ProposalRequested`)
3. Fleet card shows... nothing (no status chip)
4. Workflow completes (GitHub dispatch succeeds)
5. Operator doesn't know proposal is ready unless they check ops log

**Proposed**:
1. Operator opens actions menu, clicks "Check for system updates"
2. System update workflow created, detail sheet opens immediately
3. Sheet shows:
   - Title: "Review system updates"
   - Guidance: "The proposal is saved outside the live-change path."
   - Steps: Validate ✓ → Dispatch (running) → Save (queued)
   - Evidence: Repository dispatch: recording
4. Operator closes sheet, returns to Fleet
5. Fleet card shows status chip: [ℹ review requested]
6. GitHub dispatch succeeds, chip updates: [✓ update review completed]
7. Sheet shows "View proposal in GitHub" link
8. Chip auto-hides after 15 minutes

**Result**: Operator knows proposal is running and ready to review.

### Scenario: Operator confirms guarded update-restart

**Current**:
1. Operator triggers update-restart, review completes, reaches `AwaitingConfirmation`
2. Fleet card shows: [⚠ update review ready]
3. Operator clicks chip, detail sheet opens (already works)
4. Sheet shows "Confirm restart" button
5. Operator confirms, update applies, host reboots
6. Workflow succeeds, chip shows [✓ update completed]

**Proposed**: Same as current (already correct), but formalized as the unified pattern.

---

## Conclusion

The proposed unified workflow UI pattern addresses Markus's concern: **no more silent settings dumps, no more invisible workflows, no more hunt-for-the-continue-button**. Every host operation follows the same three-tier model:

1. **Invoke** with clear intent
2. **Card chip** shows persistent short info
3. **Detail sheet** provides professional flow view with continue/approve/cancel/rollback

All four existing workflow kinds (`SettingsChange`, `SystemUpdateProposal`, `UpdateRestart`, `RemoveHost`) and all future workflows (onboard, restore, rollback, reboot, mute) will follow this pattern.

**v1** delivers the core pattern for all existing workflows.  
**v2** adds recovery actions and richer detail.  
**v3+** adds new workflow types and automation.

This plan is **implementation-ready**: backend changes are minimal (one attribute injection), frontend changes are scoped and testable, and the design is validated against real operator pain points.

---

**Next steps**: Review with Markus, prioritize v1 scope, estimate engineering effort, proceed to implementation PR.
