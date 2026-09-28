-- ============================================================================
-- SIMPLETORY WMS - 4-TIER RBAC UPGRADE (ADMIN ROLE MIGRATION)
-- Migration Date: 2026-09-28
-- Target: Supabase PostgreSQL (GoTrue & PostgREST Compatible)
-- 
-- SUMMARY OF ROLE HIERARCHY:
-- 1. Superadmin: Global multi-tenant admin. Can create all roles (including Superadmin),
--    switch facilities, configure database credentials, and manage all records.
-- 2. Admin (NEW): Facility Administrator. Has full operational parity with Manager,
--    PLUS can create/manage Admin, Manager, and User roles within their facility.
--    STRICT CONSTRAINT: Admins CANNOT create, elevate to, edit, or delete Superadmins.
-- 3. Manager: Operational lead. Can create/manage only standard 'User' roles in their facility.
-- 4. User: Standard warehouse staff (inventory operations, read-only on team).
--
-- SAFETY & DATA INTEGRITY:
-- - Non-destructive: No tables, columns, or data are dropped.
-- - Existing user accounts, inventory records, and history remain untouched.
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Hardened User Elevation & Tenant Protection Trigger
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

    -- Rule A: Role Modification Guard
    IF (NEW.role IS DISTINCT FROM OLD.role) THEN
        -- Only Superadmin or Admin can change roles
        IF v_caller_role NOT IN ('Superadmin', 'Admin') THEN
            RAISE EXCEPTION 'Security Exception (403): You are not authorized to modify user roles.';
        END IF;

        -- If caller is Admin:
        -- 1. Must be in their own facility
        -- 2. Cannot modify a Superadmin's role
        -- 3. CANNOT promote anyone to Superadmin (Only Superadmin can create/assign Superadmin)
        IF v_caller_role = 'Admin' THEN
            IF OLD.tenant_id <> v_caller_tenant THEN
                RAISE EXCEPTION 'Security Exception (403): Admins can only manage user roles within their assigned facility.';
            END IF;
            IF OLD.role = 'Superadmin' THEN
                RAISE EXCEPTION 'Security Exception (403): Admins cannot modify Superadmin accounts.';
            END IF;
            IF NEW.role = 'Superadmin' THEN
                RAISE EXCEPTION 'Security Exception (403): Unauthorized. Only a Superadmin can assign the Superadmin role.';
            END IF;
        END IF;
    END IF;

    -- Rule B: Facility / Tenant Assignment Guard (Superadmin Only)
    IF (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id) THEN
        IF v_caller_role <> 'Superadmin' THEN
            RAISE EXCEPTION 'Security Exception (403): Only Superadmins are authorized to modify user facility assignments.';
        END IF;
    END IF;

    -- Rule C: Status Modification Guard (Active / Suspended)
    IF (NEW.status IS DISTINCT FROM OLD.status) THEN
        IF v_caller_role NOT IN ('Superadmin', 'Admin', 'Manager') THEN
            RAISE EXCEPTION 'Security Exception (403): Standard users cannot modify account status.';
        END IF;

        IF v_caller_role = 'Admin' THEN
            IF OLD.tenant_id <> v_caller_tenant OR OLD.role = 'Superadmin' THEN
                RAISE EXCEPTION 'Security Exception (403): Admins can only modify status for team members in their own facility and cannot modify Superadmins.';
            END IF;
        END IF;

        IF v_caller_role = 'Manager' THEN
            IF OLD.tenant_id <> v_caller_tenant OR OLD.role IN ('Superadmin', 'Admin', 'Manager') THEN
                RAISE EXCEPTION 'Security Exception (403): Managers can only modify status for standard users in their own facility.';
            END IF;
        END IF;
    END IF;

    -- Rule D: Profile Editing Guard
    IF (OLD.id::text <> auth.uid()::text AND (auth.jwt()->>'email' IS NULL OR OLD.email <> auth.jwt()->>'email')) THEN
        IF v_caller_role NOT IN ('Superadmin', 'Admin', 'Manager') THEN
            RAISE EXCEPTION 'Security Exception (403): Users can only modify their own profile.';
        END IF;

        IF v_caller_role = 'Admin' AND (OLD.tenant_id <> v_caller_tenant OR OLD.role = 'Superadmin') THEN
            RAISE EXCEPTION 'Security Exception (403): Admins cannot edit profiles of Superadmins or users outside their assigned facility.';
        END IF;

        IF v_caller_role = 'Manager' AND (OLD.tenant_id <> v_caller_tenant OR OLD.role IN ('Superadmin', 'Admin', 'Manager')) THEN
            RAISE EXCEPTION 'Security Exception (403): Managers cannot edit profiles of Admins, Superadmins, or users outside their assigned facility.';
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
    IF v_target_role NOT IN ('Superadmin', 'Admin', 'Manager', 'User') THEN
        RETURN jsonb_build_object('success', false, 'error', 'Invalid role. Permitted roles: Superadmin, Admin, Manager, User.');
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

    IF v_caller_role NOT IN ('Superadmin', 'Admin', 'Manager') THEN
        RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Only Managers, Admins, and Superadmins can create team members.');
    END IF;

    -- 4. Scope & Role Creation Rules:
    -- Admin: Can create Admin, Manager, and User in their own facility. CANNOT create Superadmin.
    IF v_caller_role = 'Admin' THEN
        IF v_target_tenant <> v_caller_tenant THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Admins can only add team members to their assigned facility.');
        END IF;
        IF v_target_role = 'Superadmin' THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Only a Superadmin can create or assign the Superadmin role.');
        END IF;
    END IF;

    -- Manager: Can ONLY create standard 'User' accounts and ONLY within their assigned facility
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
        RETURN jsonb_build_object('success', false, 'error', 'Action Denied: You cannot delete your own active account.');
    END IF;

    -- Caller Authorization Check
    SELECT role, tenant_id INTO v_caller_role, v_caller_tenant 
    FROM public.users 
    WHERE id::text = auth.uid()::text OR email = auth.jwt()->>'email'
    LIMIT 1;

    IF v_caller_role NOT IN ('Superadmin', 'Admin', 'Manager') THEN
        RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Only Managers, Admins, and Superadmins can remove team members.');
    END IF;

    -- Target User Lookup
    SELECT tenant_id, role INTO v_target_tenant, v_target_role
    FROM public.users
    WHERE id::text = p_user_id;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Target team member record not found.');
    END IF;

    -- Admin Scope Guard
    IF v_caller_role = 'Admin' THEN
        IF v_target_tenant <> v_caller_tenant THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Admins can only remove team members from their assigned facility.');
        END IF;
        IF v_target_role = 'Superadmin' THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Admins cannot remove Superadmin accounts.');
        END IF;
    END IF;

    -- Manager Scope Guard
    IF v_caller_role = 'Manager' THEN
        IF v_target_tenant <> v_caller_tenant THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Managers can only remove team members from their assigned facility.');
        END IF;
        IF v_target_role IN ('Superadmin', 'Admin', 'Manager') THEN
            RETURN jsonb_build_object('success', false, 'error', 'Unauthorized: Managers cannot remove Admins, Managers, or Superadmins.');
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
-- 4. Granular Catalog Master RLS Policies (public.items)
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Tenant isolation items" ON public.items;
DROP POLICY IF EXISTS "Tenant select items" ON public.items;
DROP POLICY IF EXISTS "Tenant insert items" ON public.items;
DROP POLICY IF EXISTS "Tenant update items" ON public.items;
DROP POLICY IF EXISTS "Tenant delete items" ON public.items;

-- 4.1 SELECT: All authenticated users within their facility (or Superadmin across all) can read
CREATE POLICY "Tenant select items" ON public.items
  FOR SELECT TO authenticated
  USING (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin');

-- 4.2 INSERT: Superadmins, Admins, and Managers can add catalog items
CREATE POLICY "Tenant insert items" ON public.items
  FOR INSERT TO authenticated
  WITH CHECK (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() IN ('Admin', 'Manager'))
  );

-- 4.3 UPDATE: Superadmins, Admins, and Managers can update catalog items
CREATE POLICY "Tenant update items" ON public.items
  FOR UPDATE TO authenticated
  USING (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() IN ('Admin', 'Manager'))
  )
  WITH CHECK (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() IN ('Admin', 'Manager'))
  );

-- 4.4 DELETE: Superadmins, Admins, and Managers can delete catalog items
CREATE POLICY "Tenant delete items" ON public.items
  FOR DELETE TO authenticated
  USING (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() IN ('Admin', 'Manager'))
  );

COMMIT;
