-- ============================================================================
-- SIMPLETORY ENTERPRISE MULTI-TENANT WMS - COMPLETE PRODUCTION SCHEMA
-- ============================================================================
-- Features:
-- 1. Native Supabase Auth Integration & Cryptographic JWT Verification
-- 2. Strict Kernel-Level Row Level Security (RLS) with Tenant Isolation
-- 3. Automated Database Audit Trigger for Stock Tracking
-- 4. Realtime Subscriptions & Performance Indexes
-- 5. Automated Server-Side User Provisioning Function
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 0. Cleanup Legacy Auth Triggers & Repair GoTrue auth.users Schema
-- ----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (
        SELECT tgname 
        FROM pg_trigger 
        WHERE tgrelid = 'auth.users'::regclass 
          AND NOT tgisinternal
    ) LOOP
        EXECUTE 'DROP TRIGGER IF EXISTS ' || quote_ident(r.tgname) || ' ON auth.users CASCADE;';
    END LOOP;
END $$;

DROP FUNCTION IF EXISTS public.handle_new_auth_user() CASCADE;

-- GoTrue Go-driver compatibility: Fix NULL string columns in auth.users
UPDATE auth.users
SET 
    instance_id = COALESCE(instance_id, '00000000-0000-0000-0000-000000000000'),
    aud = COALESCE(aud, 'authenticated'),
    role = COALESCE(role, 'authenticated'),
    confirmation_token = COALESCE(confirmation_token, ''),
    recovery_token = COALESCE(recovery_token, ''),
    email_change_token_new = COALESCE(email_change_token_new, ''),
    email_change = COALESCE(email_change, ''),
    phone_change = COALESCE(phone_change, ''),
    phone_change_token = COALESCE(phone_change_token, ''),
    email_change_token_current = COALESCE(email_change_token_current, ''),
    email_change_confirm_status = COALESCE(email_change_confirm_status, 0),
    reauthentication_token = COALESCE(reauthentication_token, ''),
    is_sso_user = COALESCE(is_sso_user, false),
    is_super_admin = COALESCE(is_super_admin, false),
    is_anonymous = COALESCE(is_anonymous, false),
    raw_app_meta_data = COALESCE(raw_app_meta_data, '{"provider":"email","providers":["email"]}'::jsonb),
    raw_user_meta_data = COALESCE(raw_user_meta_data, '{}'::jsonb),
    email_confirmed_at = COALESCE(email_confirmed_at, NOW()),
    created_at = COALESCE(created_at, NOW()),
    updated_at = NOW()
WHERE 
    confirmation_token IS NULL
    OR recovery_token IS NULL
    OR email_change_token_new IS NULL
    OR email_change IS NULL
    OR phone_change IS NULL
    OR phone_change_token IS NULL
    OR email_change_token_current IS NULL
    OR email_change_confirm_status IS NULL
    OR reauthentication_token IS NULL
    OR is_sso_user IS NULL
    OR is_super_admin IS NULL
    OR is_anonymous IS NULL
    OR raw_app_meta_data IS NULL
    OR raw_user_meta_data IS NULL
    OR aud IS NULL
    OR role IS NULL
    OR instance_id IS NULL;

-- ----------------------------------------------------------------------------
-- 1. Core Tables
-- ----------------------------------------------------------------------------

-- 1. Tenants / Facilities Table
CREATE TABLE IF NOT EXISTS public.tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Users & RBAC Table (Linked with Supabase Auth)
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    email TEXT,
    password_hash TEXT,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'User', -- 'Superadmin', 'Manager', 'User'
    status TEXT NOT NULL DEFAULT 'Active', -- 'Active', 'Suspended'
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_tenant_username UNIQUE (tenant_id, username)
);

-- 3. Items Master Table (with sub_category)
CREATE TABLE IF NOT EXISTS public.items (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    sku TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT DEFAULT 'General',
    sub_category TEXT DEFAULT 'Standard',
    uom TEXT NOT NULL DEFAULT 'EA',
    unit_cost NUMERIC(12, 2) DEFAULT 0.00,
    reorder_point NUMERIC(12, 2) DEFAULT 0.00,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_tenant_sku UNIQUE (tenant_id, sku)
);

-- 4. Inventory Overview Table (On-Hand Stock by Location)
CREATE TABLE IF NOT EXISTS public.inventory (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    item_id TEXT NOT NULL REFERENCES public.items(id) ON DELETE CASCADE,
    location TEXT NOT NULL DEFAULT 'MAIN-FLOOR',
    quantity NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    status TEXT NOT NULL DEFAULT 'Available',
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_tenant_item_location UNIQUE (tenant_id, item_id, location)
);

-- 5. Inventory Change History / Audit Log Table
CREATE TABLE IF NOT EXISTS public.inventory_history (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    item_id TEXT NOT NULL REFERENCES public.items(id) ON DELETE CASCADE,
    sku TEXT NOT NULL,
    item_name TEXT NOT NULL,
    action_type TEXT NOT NULL, -- 'ADD', 'SUBTRACT', 'ADJUST', 'TRANSFER', 'DELETE'
    qty_change NUMERIC(12, 2) NOT NULL,
    previous_qty NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    new_qty NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    location TEXT NOT NULL,
    user_name TEXT NOT NULL DEFAULT 'System / Admin',
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ----------------------------------------------------------------------------
-- 2. Unified Atomic Stock Movement Stored Procedure (Single-Entry Audit Log)
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_audit_inventory ON public.inventory;
DROP FUNCTION IF EXISTS public.fn_audit_inventory_changes();

CREATE OR REPLACE FUNCTION public.execute_stock_movement(
    p_item_id TEXT,
    p_location TEXT,
    p_action_type TEXT,
    p_quantity_change NUMERIC,
    p_notes TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth, pg_temp
AS $$
DECLARE
    v_caller_role TEXT;
    v_caller_tenant TEXT;
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
    -- 1. Identify Caller & Facility
    v_caller_role := public.get_auth_role();
    v_caller_tenant := public.get_auth_tenant_id();

    SELECT full_name INTO v_caller_name 
    FROM public.users 
    WHERE id::text = auth.uid()::text OR email = auth.jwt()->>'email'
    LIMIT 1;

    v_caller_name := COALESCE(v_caller_name, auth.jwt()->'user_metadata'->>'full_name', 'Warehouse Staff');

    -- 2. Lookup Item in Caller's Tenant (or Superadmin scope)
    SELECT sku, name, COALESCE(reorder_point, 0.00)
    INTO v_sku, v_item_name, v_reorder_point
    FROM public.items 
    WHERE id = p_item_id AND (tenant_id = v_caller_tenant OR v_caller_role = 'Superadmin');

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Catalog item not found in your facility.');
    END IF;

    -- 3. Row-Lock Existing Inventory for Atomic Consistency
    SELECT id, quantity INTO v_inv_id, v_prev_qty
    FROM public.inventory
    WHERE tenant_id = v_caller_tenant AND item_id = p_item_id AND location = v_loc
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
    VALUES (v_inv_id, v_caller_tenant, p_item_id, v_loc, v_new_qty, v_status, NOW())
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
        v_hist_id, v_caller_tenant, p_item_id, v_sku, v_item_name, v_action,
        v_calc_change, v_prev_qty, v_new_qty, v_loc, v_caller_name, v_clean_notes, NOW()
    );

    RETURN jsonb_build_object(
        'success', true,
        'inventory', jsonb_build_object('id', v_inv_id, 'tenant_id', v_caller_tenant, 'item_id', p_item_id, 'location', v_loc, 'quantity', v_new_qty, 'status', v_status),
        'history', jsonb_build_object('id', v_hist_id, 'sku', v_sku, 'item_name', v_item_name, 'action_type', v_action, 'qty_change', v_calc_change, 'previous_qty', v_prev_qty, 'new_qty', v_new_qty, 'location', v_loc, 'user_name', v_caller_name, 'notes', v_clean_notes)
    );
END;
$$;

GRANT EXECUTE ON FUNCTION public.execute_stock_movement(TEXT, TEXT, TEXT, NUMERIC, TEXT) TO authenticated;

-- ----------------------------------------------------------------------------
-- 3. Helper Functions for Cryptographic JWT & RLS Tenant Evaluation
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.get_auth_tenant_id()
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_tenant TEXT;
BEGIN
    SELECT tenant_id INTO v_tenant 
    FROM public.users 
    WHERE id::text = auth.uid()::text OR email = auth.jwt()->>'email'
    LIMIT 1;
    RETURN COALESCE(v_tenant, auth.jwt()->'user_metadata'->>'tenant_id');
END;
$$;

CREATE OR REPLACE FUNCTION public.get_auth_role()
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_role TEXT;
BEGIN
    SELECT role INTO v_role 
    FROM public.users 
    WHERE id::text = auth.uid()::text OR email = auth.jwt()->>'email'
    LIMIT 1;
    RETURN COALESCE(v_role, auth.jwt()->'user_metadata'->>'role', 'User');
END;
$$;

-- Username to Email resolver for public login
CREATE OR REPLACE FUNCTION public.get_email_for_login(p_identifier TEXT)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_email TEXT;
BEGIN
    SELECT email INTO v_email 
    FROM public.users 
    WHERE (LOWER(username) = LOWER(TRIM(p_identifier)) OR LOWER(email) = LOWER(TRIM(p_identifier)))
      AND status = 'Active'
    LIMIT 1;
    RETURN v_email;
END;
$$;

GRANT USAGE ON SCHEMA public TO postgres, anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO postgres, anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO postgres, anon, authenticated, service_role;
GRANT ALL ON ALL ROUTINES IN SCHEMA public TO postgres, anon, authenticated, service_role;

GRANT EXECUTE ON FUNCTION public.get_auth_tenant_id() TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_auth_role() TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_email_for_login(TEXT) TO anon, authenticated;

-- ----------------------------------------------------------------------------
-- 4. Kernel-Level Row Level Security (RLS) - Strict Tenant Isolation
-- ----------------------------------------------------------------------------
ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- 1. Tenants Table Policies
DROP POLICY IF EXISTS "Public access tenants" ON public.tenants;
DROP POLICY IF EXISTS "Authenticated tenants access" ON public.tenants;
CREATE POLICY "Authenticated tenants access" ON public.tenants
  FOR ALL TO authenticated
  USING (public.get_auth_role() = 'Superadmin' OR id = public.get_auth_tenant_id())
  WITH CHECK (public.get_auth_role() = 'Superadmin');

-- 2. Items Table Policies (Granular Separation)
DROP POLICY IF EXISTS "Tenant isolation items" ON public.items;
DROP POLICY IF EXISTS "Tenant select items" ON public.items;
DROP POLICY IF EXISTS "Tenant insert items" ON public.items;
DROP POLICY IF EXISTS "Tenant update items" ON public.items;
DROP POLICY IF EXISTS "Tenant delete items" ON public.items;

CREATE POLICY "Tenant select items" ON public.items
  FOR SELECT TO authenticated
  USING (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin');

CREATE POLICY "Tenant insert items" ON public.items
  FOR INSERT TO authenticated
  WITH CHECK (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() IN ('Admin', 'Manager'))
  );

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

CREATE POLICY "Tenant delete items" ON public.items
  FOR DELETE TO authenticated
  USING (
    public.get_auth_role() = 'Superadmin' 
    OR (tenant_id = public.get_auth_tenant_id() AND public.get_auth_role() IN ('Admin', 'Manager'))
  );

-- 3. Inventory Table Policies
DROP POLICY IF EXISTS "Tenant isolation inventory" ON public.inventory;
CREATE POLICY "Tenant isolation inventory" ON public.inventory
  FOR ALL TO authenticated
  USING (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin')
  WITH CHECK (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin');

-- 4. Inventory History Table Policies
DROP POLICY IF EXISTS "Tenant isolation inventory_history" ON public.inventory_history;
CREATE POLICY "Tenant isolation inventory_history" ON public.inventory_history
  FOR ALL TO authenticated
  USING (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin')
  WITH CHECK (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin');

-- 5. Users Table Policies (Recursion-Safe)
DROP POLICY IF EXISTS "Tenant isolation users" ON public.users;
CREATE POLICY "Tenant isolation users" ON public.users
  FOR ALL TO authenticated
  USING (
    id::text = auth.uid()::text 
    OR email = auth.jwt()->>'email'
    OR (auth.jwt()->'user_metadata'->>'role') = 'Superadmin'
    OR tenant_id = public.get_auth_tenant_id()
  )
  WITH CHECK (
    id::text = auth.uid()::text 
    OR email = auth.jwt()->>'email'
    OR (auth.jwt()->'user_metadata'->>'role') = 'Superadmin'
    OR tenant_id = public.get_auth_tenant_id()
  );

-- Elevation Protection Trigger on public.users
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

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_items_tenant ON public.items(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inventory_tenant ON public.inventory(tenant_id);
CREATE INDEX IF NOT EXISTS idx_history_tenant ON public.inventory_history(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON public.users(tenant_id);

-- ----------------------------------------------------------------------------
-- 5. Team Provisioning & In-App User Creation Function
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
-- 6. Realtime Subscriptions
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'tenants') THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.tenants;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'items') THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.items;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'inventory') THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.inventory;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'inventory_history') THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.inventory_history;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'users') THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.users;
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- 7. Initial Seed Tenants & Catalog (No Default Users)
-- ----------------------------------------------------------------------------
INSERT INTO public.tenants (id, name, is_active)
VALUES 
  ('org-primary', 'Main Enterprise Warehouse', true),
  ('org-east', 'East Coast Distribution Center', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.items (id, tenant_id, sku, name, category, sub_category, uom, unit_cost, reorder_point)
VALUES 
  ('itm-1', 'org-primary', 'SKU-1001', 'Standard Heavy Duty Pallet Box', 'Packaging', 'Corrugated', 'EA', 14.50, 20),
  ('itm-2', 'org-primary', 'SKU-1002', 'Industrial Stretch Film Roll 80GA', 'Packaging', 'Plastic Wrap', 'RL', 22.00, 15),
  ('itm-3', 'org-primary', 'SKU-2001', 'Heavy Duty Steel Bracket 4-Hole', 'Hardware', 'Brackets', 'EA', 3.75, 50),
  ('itm-4', 'org-primary', 'SKU-3001', 'Premium Utility Knife Blades (Pack of 50)', 'Tools', 'Blades', 'PK', 8.90, 10),
  ('itm-5', 'org-primary', 'SKU-4001', 'Poly Bubble Mailers #0 (6x10)', 'Packaging', 'Envelopes', 'CS', 32.40, 25),
  ('itm-6', 'org-primary', 'SKU-5001', 'Direct Thermal Shipping Labels 4x6', 'Supplies', 'Labels', 'RL', 11.25, 30)
ON CONFLICT (tenant_id, sku) DO NOTHING;

INSERT INTO public.inventory (id, tenant_id, item_id, location, quantity, status)
VALUES
  ('inv-1', 'org-primary', 'itm-1', 'A-01-01', 120, 'Available'),
  ('inv-2', 'org-primary', 'itm-2', 'A-01-02', 45, 'Available'),
  ('inv-3', 'org-primary', 'itm-3', 'B-02-01', 300, 'Available'),
  ('inv-4', 'org-primary', 'itm-4', 'B-02-02', 8, 'Low Stock'),
  ('inv-5', 'org-primary', 'itm-5', 'C-01-01', 64, 'Available'),
  ('inv-6', 'org-primary', 'itm-6', 'C-02-01', 5, 'Low Stock')
ON CONFLICT (tenant_id, item_id, location) DO NOTHING;
