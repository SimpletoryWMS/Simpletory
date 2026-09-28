-- ============================================================================
-- SIMPLETORY WMS - PRODUCTION SECURITY HARDENING & KERNEL RBAC MIGRATION
-- Migration Date: 2026-09-28
-- Target: Supabase PostgreSQL (GoTrue & PostgREST Compatible)
-- 
-- SUMMARY OF HARDENING:
-- 1. Adds BEFORE UPDATE trigger on public.users to prevent self-role elevation
--    and unauthorized facility switching via direct REST API calls.
-- 2. Hardens public.create_team_member RPC to prevent vertical privilege escalation
--    (Managers can only create standard 'User' roles in their assigned facility).
-- 3. Hardens public.delete_team_member RPC to prevent self-deletion and enforce facility boundaries.
-- 4. Replaces duplicate audit triggers with a unified atomic stock movement RPC
--    (public.execute_stock_movement) ensuring a single, ACID-compliant audit entry.
-- 5. Splits public.items RLS policies into explicit SELECT (facility-wide) and
--    INSERT/UPDATE/DELETE (Manager & Superadmin only) permissions.
--
-- SAFETY & DATA INTEGRITY:
-- - Non-destructive: No tables or columns are dropped.
-- - Existing data in public.users, items, inventory, tenants, and history is preserved.
-- - Fully backward compatible with active user sessions and frontend flows.
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Public Users Elevation & Tenant Tampering Protection Trigger
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_protect_user_elevation()
RETURNS TRIGGER AS $$
DECLARE
    v_caller_role TEXT;
    v_caller_tenant TEXT;
BEGIN
    -- Allow internal service_role / background processes unrestricted access
    IF current_user = 'service_role' OR auth.role() = 'service_role' THEN
        RETURN NEW;
    END IF;

    -- Retrieve cryptographic role and tenant of current authenticated caller
    v_caller_role := public.get_auth_role();
    v_caller_tenant := public.get_auth_tenant_id();

    -- Rule A: Only Superadmin can change user roles
    IF (NEW.role IS DISTINCT FROM OLD.role) THEN
        IF v_caller_role <> 'Superadmin' THEN
            RAISE EXCEPTION 'Security Exception (403): Only Superadmins are authorized to modify user roles.';
        END IF;
    END IF;

    -- Rule B: Only Superadmin can change facility / tenant assignments
    IF (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id) THEN
        IF v_caller_role <> 'Superadmin' THEN
            RAISE EXCEPTION 'Security Exception (403): Only Superadmins are authorized to modify user facility assignments.';
        END IF;
    END IF;

    -- Rule C: Only Superadmin or Manager can modify account status (Active / Suspended)
    IF (NEW.status IS DISTINCT FROM OLD.status) THEN
        IF v_caller_role NOT IN ('Superadmin', 'Manager') THEN
            RAISE EXCEPTION 'Security Exception (403): Standard users cannot modify account status.';
        END IF;
        -- If caller is Manager, ensure target user belongs to caller's facility and is not Superadmin
        IF v_caller_role = 'Manager' THEN
            IF OLD.tenant_id <> v_caller_tenant OR OLD.role IN ('Superadmin', 'Manager') THEN
                RAISE EXCEPTION 'Security Exception (403): Managers can only modify status for standard users in their own facility.';
            END IF;
        END IF;
    END IF;

    -- Rule D: Non-owners cannot update other users' profile records
    -- (Owners matching auth.uid() or email can safely update full_name, email, password_hash, last_login_at)
    IF (OLD.id::text <> auth.uid()::text AND (auth.jwt()->>'email' IS NULL OR OLD.email <> auth.jwt()->>'email')) THEN
        IF v_caller_role NOT IN ('Superadmin', 'Manager') THEN
            RAISE EXCEPTION 'Security Exception (403): Users can only modify their own profile.';
        END IF;
        -- Managers cannot modify records of users outside their facility or Superadmins
        IF v_caller_role = 'Manager' AND (OLD.tenant_id <> v_caller_tenant OR OLD.role = 'Superadmin') THEN
            RAISE EXCEPTION 'Security Exception (403): Managers cannot edit profiles of Superadmins or users outside their assigned facility.';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth, pg_temp;

DROP TRIGGER IF EXISTS trg_protect_user_elevation ON public.users;
CREATE TRIGGER trg_protect_user_elevation
BEFORE UPDATE ON public.users
FOR EACH ROW EXECUTE FUNCTION public.fn_protect_user_elevation();

-- ----------------------------------------------------------------------------
-- 2. Hardened Team Provisioning Function (public.create_team_member)
-- ----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

CREATE OR REPLACE FUNCTION public.create_team_member(
    p_username TEXT,
    p_email TEXT,
    p_password TEXT,
    p_full_name TEXT,
    p_role TEXT,
    p_tenant_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth, extensions, pg_temp
AS $$
DECLARE
    v_caller_role TEXT;
    v_caller_tenant TEXT;
    v_new_uid UUID := gen_random_uuid();
    v_encrypted_pw TEXT;
    v_clean_email TEXT := LOWER(TRIM(p_email));
    v_clean_username TEXT := TRIM(p_username);
    v_target_role TEXT := TRIM(p_role);
    v_target_tenant TEXT := TRIM(p_tenant_id);
BEGIN
    -- 1. Validate Target Role
    IF v_target_role NOT IN ('Superadmin', 'Manager', 'User') THEN
        RETURN jsonb_build_object('success', false, 'error', 'Invalid role. Permitted roles: Superadmin, Manager, User.');
    END IF;

    -- 2. Validate Tenant Exists & Is Active
    IF NOT EXISTS (SELECT 1 FROM public.tenants WHERE id = v_target_tenant AND is_active = true) THEN
        RETURN jsonb_build_object('success', false, 'error', 'Invalid facility: The specified tenant is inactive or does not exist.');
    END IF;

    -- 3. Caller Authorization Check
    SELECT role, tenant_id INTO v_caller_role, v_caller_tenant 
    FROM public.users 
    WHERE id::text = auth.uid()::text OR email = auth.jwt()->>'email'
    LIMIT 1;

    IF v_caller_role NOT IN ('Superadmin', 'Manager') THEN
        RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Only Managers and Superadmins can create team members.');
    END IF;

    -- 4. Vertical Privilege Escalation Protection:
    -- Managers can ONLY create standard 'User' accounts and ONLY within their assigned facility
    IF v_caller_role = 'Manager' THEN
        IF v_target_tenant <> v_caller_tenant THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Managers can only add team members to their assigned facility.');
        END IF;
        IF v_target_role <> 'User' THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Managers can only create standard User accounts.');
        END IF;
    END IF;

    -- 5. Validate Uniqueness
    IF EXISTS (SELECT 1 FROM public.users WHERE tenant_id = v_target_tenant AND LOWER(username) = LOWER(v_clean_username)) THEN
        RETURN jsonb_build_object('success', false, 'error', 'Username is already taken in this facility.');
    END IF;

    IF EXISTS (SELECT 1 FROM public.users WHERE LOWER(email) = v_clean_email) THEN
        RETURN jsonb_build_object('success', false, 'error', 'Email address is already registered in the system.');
    END IF;

    -- 6. Create auth.users Record (Auto-Confirmed Email with GoTrue Compliance)
    v_encrypted_pw := extensions.crypt(p_password, extensions.gen_salt('bf'));

    INSERT INTO auth.users (
        id, instance_id, aud, role, email, encrypted_password, email_confirmed_at,
        confirmation_token, recovery_token, email_change_token_new, email_change,
        phone_change, phone_change_token, email_change_token_current, email_change_confirm_status,
        reauthentication_token, is_sso_user, is_super_admin,
        raw_app_meta_data, raw_user_meta_data, created_at, updated_at
    ) VALUES (
        v_new_uid,
        '00000000-0000-0000-0000-000000000000',
        'authenticated',
        'authenticated',
        v_clean_email,
        v_encrypted_pw,
        NOW(),
        '', '', '', '', '', '', '', 0, '', false, false,
        jsonb_build_object('provider', 'email', 'providers', array['email']),
        jsonb_build_object('username', v_clean_username, 'full_name', p_full_name, 'role', v_target_role, 'tenant_id', v_target_tenant),
        NOW(),
        NOW()
    );

    -- 7. Create auth.identities Record
    INSERT INTO auth.identities (
        id, user_id, identity_data, provider, provider_id, last_sign_in_at, created_at, updated_at
    ) VALUES (
        v_new_uid,
        v_new_uid,
        jsonb_build_object('sub', v_new_uid::text, 'email', v_clean_email, 'email_verified', true),
        'email',
        v_clean_email,
        NOW(),
        NOW(),
        NOW()
    );

    -- 8. Create public.users Record
    INSERT INTO public.users (id, tenant_id, username, email, full_name, role, status, created_at)
    VALUES (v_new_uid::text, v_target_tenant, v_clean_username, v_clean_email, p_full_name, v_target_role, 'Active', NOW());

    RETURN jsonb_build_object('success', true, 'user_id', v_new_uid);
END;
$$;

-- ----------------------------------------------------------------------------
-- 3. Hardened Team Member Deletion Function (public.delete_team_member)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.delete_team_member(p_user_id TEXT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth, pg_temp
AS $$
DECLARE
    v_caller_role TEXT;
    v_caller_tenant TEXT;
    v_target_tenant TEXT;
    v_target_role TEXT;
    v_target_uuid UUID;
BEGIN
    -- Prevent self-deletion
    IF p_user_id = auth.uid()::text THEN
        RETURN jsonb_build_object('success', false, 'error', 'Action Denied: You cannot delete your own active administrative account.');
    END IF;

    -- Caller Authorization Check
    SELECT role, tenant_id INTO v_caller_role, v_caller_tenant 
    FROM public.users 
    WHERE id::text = auth.uid()::text OR email = auth.jwt()->>'email'
    LIMIT 1;

    IF v_caller_role NOT IN ('Superadmin', 'Manager') THEN
        RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Only Managers and Superadmins can remove team members.');
    END IF;

    -- Target User Lookup
    SELECT tenant_id, role INTO v_target_tenant, v_target_role
    FROM public.users
    WHERE id::text = p_user_id;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Target team member record not found.');
    END IF;

    -- Manager Scope Guard
    IF v_caller_role = 'Manager' THEN
        IF v_target_tenant <> v_caller_tenant THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Managers can only remove team members from their assigned facility.');
        END IF;
        IF v_target_role IN ('Superadmin', 'Manager') THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Managers cannot remove other Managers or Superadmins.');
        END IF;
    END IF;

    -- Convert ID to UUID for auth table cleanup
    BEGIN
        v_target_uuid := p_user_id::uuid;
    EXCEPTION WHEN OTHERS THEN
        v_target_uuid := NULL;
    END;

    -- Clean up auth identities and users
    IF v_target_uuid IS NOT NULL THEN
        DELETE FROM auth.identities WHERE user_id = v_target_uuid;
        DELETE FROM auth.users WHERE id = v_target_uuid;
    END IF;

    -- Clean up public users table
    DELETE FROM public.users WHERE id::text = p_user_id;

    RETURN jsonb_build_object('success', true);
END;
$$;

GRANT EXECUTE ON FUNCTION public.create_team_member(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.delete_team_member(TEXT) TO authenticated;

-- ----------------------------------------------------------------------------
-- 4. Unified Atomic Stock Movement Stored Procedure (Single-Entry Audit Log)
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_audit_inventory ON public.inventory;
DROP FUNCTION IF EXISTS public.fn_audit_inventory_changes();

CREATE OR REPLACE FUNCTION public.execute_stock_movement(
    p_item_id TEXT,
    p_location TEXT,
    p_action_type TEXT,
    p_quantity_change NUMERIC,
    p_notes TEXT DEFAULT NULL,
    p_tenant_id TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth, pg_temp
AS $$
DECLARE
    v_caller_role TEXT;
    v_caller_tenant TEXT;
    v_target_tenant TEXT;
    v_caller_name TEXT;
    v_sku TEXT;
    v_item_name TEXT;
    v_reorder_point NUMERIC(12, 2);
    v_prev_qty NUMERIC(12, 2) := 0.00;
    v_new_qty NUMERIC(12, 2) := 0.00;
    v_calc_change NUMERIC(12, 2) := 0.00;
    v_status TEXT;
    v_inv_id TEXT;
    v_hist_id TEXT;
    v_loc TEXT := UPPER(TRIM(p_location));
    v_action TEXT := UPPER(TRIM(p_action_type));
    v_clean_notes TEXT;
BEGIN
    -- 1. Identify Caller & Facility Context
    v_caller_role := public.get_auth_role();
    v_caller_tenant := public.get_auth_tenant_id();
    v_target_tenant := COALESCE(NULLIF(TRIM(p_tenant_id), ''), v_caller_tenant);

    -- Multi-facility authorization guard: Only Superadmins can operate across arbitrary facilities
    IF v_caller_role <> 'Superadmin' AND v_target_tenant <> v_caller_tenant THEN
        RETURN jsonb_build_object('success', false, 'error', 'Permission denied: Cannot perform stock operations outside your assigned facility.');
    END IF;

    SELECT full_name INTO v_caller_name 
    FROM public.users 
    WHERE id::text = auth.uid()::text OR email = auth.jwt()->>'email'
    LIMIT 1;

    v_caller_name := COALESCE(v_caller_name, auth.jwt()->'user_metadata'->>'full_name', 'Warehouse Staff');

    -- 2. Lookup Item in Target Facility (or Global Catalog for Superadmin)
    SELECT sku, name, COALESCE(reorder_point, 0.00)
    INTO v_sku, v_item_name, v_reorder_point
    FROM public.items 
    WHERE id = p_item_id AND (tenant_id = v_target_tenant OR v_caller_role = 'Superadmin');

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Catalog item not found in your facility.');
    END IF;

    -- 3. Row-Lock Existing Inventory for Atomic Consistency
    SELECT id, quantity INTO v_inv_id, v_prev_qty
    FROM public.inventory
    WHERE tenant_id = v_target_tenant AND item_id = p_item_id AND location = v_loc
    FOR UPDATE;

    v_prev_qty := COALESCE(v_prev_qty, 0.00);

    -- 4. Calculate New Stock
    IF v_action = 'ADD' THEN
        v_new_qty := v_prev_qty + ABS(p_quantity_change);
    ELSIF v_action = 'SUBTRACT' THEN
        v_new_qty := GREATEST(0.00, v_prev_qty - ABS(p_quantity_change));
    ELSIF v_action = 'ADJUST' THEN
        v_new_qty := GREATEST(0.00, p_quantity_change);
    ELSE
        RETURN jsonb_build_object('success', false, 'error', 'Invalid action type. Permitted: ADD, SUBTRACT, ADJUST.');
    END IF;

    v_calc_change := v_new_qty - v_prev_qty;

    -- 5. Determine Stock Status
    IF v_new_qty <= 0 THEN
        v_status := 'Out of Stock';
    ELSIF v_new_qty <= v_reorder_point THEN
        v_status := 'Low Stock';
    ELSE
        v_status := 'Available';
    END IF;

    IF v_inv_id IS NULL THEN
        v_inv_id := 'inv-' || floor(extract(epoch from clock_timestamp()) * 1000)::text || '-' || substr(md5(random()::text), 1, 4);
    END IF;

    -- 6. Atomic Upsert to public.inventory
    INSERT INTO public.inventory (id, tenant_id, item_id, location, quantity, status, updated_at)
    VALUES (v_inv_id, v_target_tenant, p_item_id, v_loc, v_new_qty, v_status, NOW())
    ON CONFLICT (tenant_id, item_id, location) 
    DO UPDATE SET 
        quantity = EXCLUDED.quantity,
        status = EXCLUDED.status,
        updated_at = NOW();

    -- 7. Atomic Insert to public.inventory_history (Single authoritative audit log)
    v_hist_id := 'hist-' || floor(extract(epoch from clock_timestamp()) * 1000)::text || '-' || substr(md5(random()::text), 1, 4);
    v_clean_notes := COALESCE(NULLIF(TRIM(p_notes), ''), v_action || ' operation executed');

    INSERT INTO public.inventory_history (
        id, tenant_id, item_id, sku, item_name, action_type,
        qty_change, previous_qty, new_qty, location, user_name, notes, created_at
    ) VALUES (
        v_hist_id, v_target_tenant, p_item_id, v_sku, v_item_name, v_action,
        v_calc_change, v_prev_qty, v_new_qty, v_loc, v_caller_name, v_clean_notes, NOW()
    );

    RETURN jsonb_build_object(
        'success', true,
        'inventory', jsonb_build_object('id', v_inv_id, 'tenant_id', v_target_tenant, 'item_id', p_item_id, 'location', v_loc, 'quantity', v_new_qty, 'status', v_status),
        'history', jsonb_build_object('id', v_hist_id, 'sku', v_sku, 'item_name', v_item_name, 'action_type', v_action, 'qty_change', v_calc_change, 'previous_qty', v_prev_qty, 'new_qty', v_new_qty, 'location', v_loc, 'user_name', v_caller_name, 'notes', v_clean_notes)
    );
END;
$$;

GRANT EXECUTE ON FUNCTION public.execute_stock_movement(TEXT, TEXT, TEXT, NUMERIC, TEXT, TEXT) TO authenticated;

-- ----------------------------------------------------------------------------
-- 5. Granular Catalog Master RLS Policies (public.items)
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Tenant isolation items" ON public.items;
DROP POLICY IF EXISTS "Tenant select items" ON public.items;
DROP POLICY IF EXISTS "Tenant insert items" ON public.items;
DROP POLICY IF EXISTS "Tenant update items" ON public.items;
DROP POLICY IF EXISTS "Tenant delete items" ON public.items;

-- 5.1 SELECT: All authenticated users within their facility (or Superadmin across all) can read
CREATE POLICY "Tenant select items" ON public.items
  FOR SELECT TO authenticated
  USING (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin');

-- 5.2 INSERT: Only Superadmins and Managers can add catalog items
CREATE POLICY "Tenant insert items" ON public.items
  FOR INSERT TO authenticated
  WITH CHECK (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() = 'Manager')
  );

-- 5.3 UPDATE: Only Superadmins and Managers can update catalog items
CREATE POLICY "Tenant update items" ON public.items
  FOR UPDATE TO authenticated
  USING (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() = 'Manager')
  )
  WITH CHECK (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() = 'Manager')
  );

-- 5.4 DELETE: Only Superadmins and Managers can delete catalog items
CREATE POLICY "Tenant delete items" ON public.items
  FOR DELETE TO authenticated
  USING (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() = 'Manager')
  );

COMMIT;
