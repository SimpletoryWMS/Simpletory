# Simpletory WMS - Evening Security Implementation Runbook
**Scheduled Window**: Evening Maintenance  
**Prepared**: 2026-09-28  
**Target Files**:
- Database: [sql/migration_2026_09_28_security_hardening.sql](file:///Users/dereklumpkin/Documents/Simpletory/sql/migration_2026_09_28_security_hardening.sql)
- Baseline Schema: [sql/supabase_schema.sql](file:///Users/dereklumpkin/Documents/Simpletory/sql/supabase_schema.sql)
- Frontend Logic: [app.js](file:///Users/dereklumpkin/Documents/Simpletory/app.js)
- Data Service: [supabase-config.js](file:///Users/dereklumpkin/Documents/Simpletory/supabase-config.js)

---

## 📌 Executive Summary & Readiness
All migration scripts and remediation steps have been generated, pre-audited, and validated against the production schema. When you are ready to apply the updates this evening, follow the two-stage execution sequence below.

---

## 🚀 Stage 1: Database Migration (Human Admin - 2 minutes)

1. Log in to your [Supabase Project Dashboard](https://supabase.com/dashboard).
2. Go to **SQL Editor** > **New Query**.
3. Open and copy the SQL script from:
   **[sql/migration_2026_09_28_security_hardening.sql](file:///Users/dereklumpkin/Documents/Simpletory/sql/migration_2026_09_28_security_hardening.sql)**
4. Click **Run**.

### What this achieves:
* **Trigger `trg_protect_user_elevation`**: Blocks REST API attempts to self-elevate roles or tamper with facility tenant IDs.
* **Hardened `create_team_member`**: Ensures facility Managers can only create standard `User` accounts within their facility.
* **Hardened `delete_team_member`**: Prevents administrative self-deletion and cross-tenant user deletions.
* **Unified Atomic Stock Movement (`execute_stock_movement`)**: Replaces duplicate dual-logging triggers with a single, ACID-compliant audit entry.
* **Granular `public.items` RLS**: Separates `SELECT` (all facility staff) from `INSERT/UPDATE/DELETE` (Superadmins and Managers only).

---

## 🤖 Stage 2: Frontend & Client Service Hardening (Agent Execution)

When you resume this evening, simply instruct the agent:
> *"Proceed with Stage 2 of the Evening Security Implementation Runbook."*

The developing agent will execute the following pre-planned updates:

1. **Stored XSS Sanitization in [app.js](file:///Users/dereklumpkin/Documents/Simpletory/app.js)**:
   - Implement `escapeHtml()` and `escapeAttr()` helper functions.
   - Sanitize all dynamic interpolations (`sku`, `item_name`, `location`, `notes`, `user_name`, `full_name`, `email`) across table renderers, dashboard feeds, and report builders.
   - Refactor inline event bindings (`onclick`) to safe data attributes.
2. **Double-Submission Protection in [app.js](file:///Users/dereklumpkin/Documents/Simpletory/app.js)**:
   - Add async submit locks (`disabled = true`, loading spinner text) across all modal forms (`form-item`, `form-intake`, `form-dispatch`, `form-adjust`, `form-transfer`, `form-user`, `form-profile`).
   - Add debouncing locks on quick action steppers.
3. **Ghost Auth Record Prevention in [supabase-config.js](file:///Users/dereklumpkin/Documents/Simpletory/supabase-config.js)**:
   - Remove unsafe silent fallback delete in `deleteUser()` that previously bypassed `auth.users` cascading cleanup.
4. **Targeted Realtime & History Performance in [app.js](file:///Users/dereklumpkin/Documents/Simpletory/app.js) & [supabase-config.js](file:///Users/dereklumpkin/Documents/Simpletory/supabase-config.js)**:
   - Scope realtime listener topics so table mutations only refresh the relevant data slice and active view.
   - Apply default limit (`250`) with index ordering to recent audit history queries.

---

## 🔍 Stage 3: Verification & Pre-Flight Testing

Execute the automated test suite to confirm zero regressions:

```bash
# 1. Quick syntax and structure diagnostics
python3 .agents/skills/codebase-quick-diagnostics/scripts/diagnose.py

# 2. Supabase schema and RLS query parity check
python3 .agents/skills/supabase-schema-guardian/scripts/check_supabase_schema.py

# 3. DOM & JavaScript synchronization check (188+ element IDs)
python3 .agents/skills/vanilla-dom-sync/scripts/check_dom_sync.py

# 4. Vercel deployment pre-flight verification
python3 .agents/skills/vercel-deploy-guard/scripts/check_deploy.py
```

---

## 🔄 Rollback Plan (Zero-Downtime Assurance)

Because the migration is non-destructive (no tables, rows, or columns are dropped), rolling back database policies if ever needed is immediate:

```sql
-- Rollback to baseline items blanket policy if needed
DROP POLICY IF EXISTS "Tenant select items" ON public.items;
DROP POLICY IF EXISTS "Tenant insert items" ON public.items;
DROP POLICY IF EXISTS "Tenant update items" ON public.items;
DROP POLICY IF EXISTS "Tenant delete items" ON public.items;

CREATE POLICY "Tenant isolation items" ON public.items
  FOR ALL TO authenticated
  USING (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin')
  WITH CHECK (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin');

-- Remove trigger if needed
DROP TRIGGER IF EXISTS trg_protect_user_elevation ON public.users;
DROP FUNCTION IF EXISTS public.fn_protect_user_elevation();
```
