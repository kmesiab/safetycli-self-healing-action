# Copilot Detection and Fallback Assignee Feature

## Overview

This feature adds intelligent assignment handling with Copilot detection and fallback support, making the action more flexible and user-friendly.

---

## New Inputs in action.yml

### `assign_to_copilot`
- **Type:** Boolean (string: 'true' or 'false')
- **Default:** `'true'`
- **Description:** Whether to attempt assigning issues to GitHub Copilot agent
- **Use case:** Disable if you don't have Copilot or prefer manual assignment

### `fallback_assignee`
- **Type:** String (GitHub username)
- **Default:** `''` (empty)
- **Description:** Fallback GitHub username to assign issues to if Copilot assignment fails
- **Use case:** Assign to a human team member when Copilot is unavailable

---

## How It Works

### Assignment Flow

```
1. Issue Created Successfully
   ↓
2. Check: assign_to_copilot enabled?
   ↓ YES                    ↓ NO
3. Try assign to Copilot   Skip to step 5
   ↓
4. Success?
   ↓ YES                    ↓ NO
   DONE ✅                  Continue to step 5
   ↓
5. Check: fallback_assignee configured?
   ↓ YES                    ↓ NO
6. Try assign to fallback  Log: No assignment
   ↓
7. Success?
   ↓ YES                    ↓ NO
   DONE ✅                  Log: Manual assignment needed
```

### Copilot Detection

The script detects when Copilot is not assignable by:

1. **HTTP 422 Status Code** - Unprocessable Entity (invalid assignee)
2. **Error Message Analysis** - Checks for:
   - "not found" - Username doesn't exist
   - "does not exist" - User not a collaborator
3. **Caching** - Sets `copilot_available = False` to avoid repeated attempts

### Fallback Behavior

When Copilot assignment fails:
- ✅ **If fallback configured**: Tries to assign to fallback user
- ⚠️ **If no fallback**: Leaves issue unassigned with clear message
- 📝 **Always**: Issue is created successfully and counted

---

## Usage Examples

### Example 1: Default Behavior (Copilot Only)
```yaml
- uses: kmesiab/safetycli-self-healing-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    safety_api_key: ${{ secrets.SAFETY_API_KEY }}
    # assign_to_copilot: true (default)
    # copilot_agent: copilot (default)
```

**Result:**
- Tries to assign to `@copilot`
- If fails, leaves unassigned with manual assignment instructions

### Example 2: Copilot with Fallback
```yaml
- uses: kmesiab/safetycli-self-healing-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    safety_api_key: ${{ secrets.SAFETY_API_KEY }}
    assign_to_copilot: true
    copilot_agent: copilot
    fallback_assignee: security-team-lead
```

**Result:**
- Tries to assign to `@copilot`
- If fails, assigns to `@security-team-lead`
- If both fail, leaves unassigned

### Example 3: Human Only (No Copilot)
```yaml
- uses: kmesiab/safetycli-self-healing-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    safety_api_key: ${{ secrets.SAFETY_API_KEY }}
    assign_to_copilot: false
    fallback_assignee: security-team-lead
```

**Result:**
- Skips Copilot assignment
- Assigns directly to `@security-team-lead`

### Example 4: No Assignment (Manual Only)
```yaml
- uses: kmesiab/safetycli-self-healing-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    safety_api_key: ${{ secrets.SAFETY_API_KEY }}
    assign_to_copilot: false
    # fallback_assignee: '' (default)
```

**Result:**
- Creates issues without any assignment
- Users manually assign as needed

### Example 5: Custom Copilot Agent Name
```yaml
- uses: kmesiab/safetycli-self-healing-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    safety_api_key: ${{ secrets.SAFETY_API_KEY }}
    assign_to_copilot: true
    copilot_agent: my-copilot-agent
    fallback_assignee: devops-team
```

**Result:**
- Tries to assign to `@my-copilot-agent`
- If fails, assigns to `@devops-team`

---

## Console Output Examples

### Scenario 1: Copilot Assignment Successful
```
Created issue #123: [Security] requests: CVE-2023-12345
✅ Assigned issue #123 to @copilot
```

### Scenario 2: Copilot Not Available, Fallback Successful
```
Created issue #123: [Security] requests: CVE-2023-12345
⚠️  Copilot agent '@copilot' not found or not assignable
✅ Assigned issue #123 to fallback assignee @security-team-lead
```

### Scenario 3: Copilot Not Available, No Fallback
```
Created issue #123: [Security] requests: CVE-2023-12345
⚠️  Copilot agent '@copilot' not found or not assignable
Issue #123 created without assignment (no fallback configured)
```

### Scenario 4: Both Assignments Fail
```
Created issue #123: [Security] requests: CVE-2023-12345
⚠️  Copilot agent '@copilot' not found or not assignable
⚠️  Failed to assign to fallback @security-team-lead: 422 Client Error
Issue #123 was created successfully but assignment can be done manually
```

### Scenario 5: Assignment Disabled
```
Created issue #123: [Security] requests: CVE-2023-12345
Issue #123 created without assignment (assignment disabled)
```

---

## Issue Body Enhancement

Every created issue now includes helpful instructions for manual Copilot assignment:

```markdown
### Steps for @copilot

1. Update the `package-name` dependency to a secure version
2. Update any related dependencies if needed
3. Run tests to ensure compatibility
4. Create a pull request with the security fix

---

**ℹ️ Note**: If GitHub Copilot is enabled in your repository, you can assign this issue to the Copilot coding agent for automated remediation. Simply assign this issue to `@copilot` or your configured Copilot agent username.

**Provenance**: This issue was automatically created by SafetyCLI Self-Healing Action based on vulnerability scan results.
```

This allows users to:
- ✅ Manually assign to Copilot if auto-assignment failed
- ✅ Understand how to use Copilot for remediation
- ✅ Know the issue was auto-generated

---

## Code Architecture

### New Class Attributes
```python
class GitHubIssueCreator:
    def __init__(self, token, repo, assign_to_copilot=True, 
                 copilot_agent="copilot", fallback_assignee=""):
        self.assign_to_copilot = assign_to_copilot
        self.copilot_agent = copilot_agent
        self.fallback_assignee = fallback_assignee
        self.copilot_available = None  # Cache for Copilot availability
```

### Method Breakdown

#### `_assign_issue(issue_number)` - Main Assignment Orchestrator
- Checks if assignment is enabled
- Tries Copilot if `assign_to_copilot=True`
- Falls back to `fallback_assignee` if Copilot fails
- Logs appropriate messages for each scenario

#### `_try_assign_to_copilot(issue_number)` - Copilot Assignment
- Returns `bool` - True if successful, False otherwise
- Detects HTTP 422 with "not found" or "does not exist" messages
- Caches result in `self.copilot_available`
- Uses emoji indicators (✅ for success, ⚠️ for warnings)

#### `_try_assign_to_fallback(issue_number)` - Fallback Assignment
- Returns `None` (void)
- Attempts assignment to fallback user
- Logs success or failure
- Graceful error handling

---

## Error Detection Details

### HTTP 422 - Unprocessable Entity

**Copilot Not Found:**
```json
{
  "message": "Validation Failed",
  "errors": [
    {
      "resource": "Issue",
      "field": "assignees",
      "code": "invalid",
      "message": "Assignee does not exist"
    }
  ]
}
```

**Detection Logic:**
```python
if e.response.status_code == 422:
    error_message = e.response.json().get('message', '').lower()
    if 'not found' in error_message or 'does not exist' in error_message:
        print(f"⚠️  Copilot agent '@{self.copilot_agent}' not found or not assignable")
        self.copilot_available = False
```

### HTTP 403 - Forbidden

**Insufficient Permissions:**
```json
{
  "message": "Must have admin rights to Repository."
}
```

**Detection:** Caught by `RequestException` handler, logged as warning

---

## Benefits

### 1. **Flexibility**
- Works with or without Copilot
- Supports custom Copilot agent names
- Allows pure human workflows

### 2. **Resilience**
- Graceful degradation when Copilot unavailable
- Fallback to human assignees
- Never fails issue creation due to assignment problems

### 3. **User Experience**
- Clear console messages with emoji indicators
- Helpful instructions in issue body
- Easy manual assignment if needed

### 4. **Smart Detection**
- Detects Copilot availability automatically
- Caches detection result to avoid repeated failures
- Distinguishes between different error types

### 5. **Backward Compatible**
- Default behavior unchanged (tries Copilot)
- Existing workflows continue to work
- Opt-in for new features

---

## Testing Recommendations

### Test Case 1: Copilot Available
```bash
export ASSIGN_TO_COPILOT=true
export COPILOT_AGENT=copilot
export FALLBACK_ASSIGNEE=""
# Expected: Issues assigned to @copilot
```

### Test Case 2: Copilot Not Available, Fallback Works
```bash
export ASSIGN_TO_COPILOT=true
export COPILOT_AGENT=nonexistent-copilot
export FALLBACK_ASSIGNEE=your-username
# Expected: Issues assigned to @your-username
```

### Test Case 3: Copilot Disabled, Fallback Only
```bash
export ASSIGN_TO_COPILOT=false
export FALLBACK_ASSIGNEE=security-lead
# Expected: Issues assigned to @security-lead
```

### Test Case 4: No Assignment
```bash
export ASSIGN_TO_COPILOT=false
export FALLBACK_ASSIGNEE=""
# Expected: Issues created unassigned
```

### Test Case 5: Both Fail
```bash
export ASSIGN_TO_COPILOT=true
export COPILOT_AGENT=nonexistent-copilot
export FALLBACK_ASSIGNEE=nonexistent-user
# Expected: Issues created unassigned with warnings
```

---

## Migration Guide

### From Old Version (No Fallback)

**Old Configuration:**
```yaml
- uses: kmesiab/safetycli-self-healing-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    copilot_agent: copilot
```

**New Configuration (Same Behavior):**
```yaml
- uses: kmesiab/safetycli-self-healing-action@v2
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    assign_to_copilot: true  # Optional, default is true
    copilot_agent: copilot    # Optional, default is copilot
```

**New Configuration (With Fallback):**
```yaml
- uses: kmesiab/safetycli-self-healing-action@v2
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    assign_to_copilot: true
    copilot_agent: copilot
    fallback_assignee: security-team  # NEW: Add fallback
```

---

## Summary

This feature provides:
- ✅ **Smart Copilot detection** - Automatically detects when Copilot is unavailable
- ✅ **Fallback support** - Assigns to human team members when Copilot fails
- ✅ **Flexible configuration** - Support for Copilot-only, human-only, or hybrid workflows
- ✅ **Graceful degradation** - Never fails issue creation due to assignment problems
- ✅ **Clear feedback** - Emoji indicators and helpful messages
- ✅ **Manual assignment instructions** - Issue body includes Copilot assignment guide
- ✅ **Backward compatible** - Existing workflows continue to work unchanged

**Key Principle:** Issue creation is critical, assignment is flexible. The action adapts to your repository's configuration and available features.
