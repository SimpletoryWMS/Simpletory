-- ============================================================================
-- SIMPLETORY WMS - PRODUCTION SECURITY & STABILITY AUDIT MIGRATION
-- Migration Date: 2026-09-30
-- Target: Supabase PostgreSQL (GoTrue & PostgREST Compatible)
--
-- SUMMARY OF HARDENING:
-- 1. Privilege Escalation Prevention (Finding 1):
--    - Trigger fn_protect_user_elevation extended to execute BEFORE INSERT OR UPDATE.
--    - Enforces default 'User' role on all direct/unverified client inserts.
--    - get_auth_role() hardened to eliminate reliance on client user_metadata.
--    - public.users RLS policy sanitized to remove user_metadata bypass.
-- 2. Immutable Audit History Ledger & Direct Rest Protection (Finding 2):
--    - public.inventory_history converted to an append-only immutable ledger.
--    - Direct UPDATE and DELETE strictly revoked on inventory_history.
-- 3. Audit Trail Preservation on Catalog SKU Deletion (Finding 3):
--    - foreign key constraint on inventory_history.item_id changed to ON DELETE SET NULL.
--    - Deleting an item removes catalog and active inventory balances, while
--      permanently preserving historical transaction logs in inventory_history.
-- 4. Atomic Stock Transfers & Subtraction Guard (Finding 4):
--    - New stored procedure public.execute_stock_transfer() executed in a single ACID transaction.
--    - Subtraction logic in execute_stock_movement hardened to reject insufficient stock.
-- 5. Hardened Login Resolver (Finding 6):
--    - public.get_email_for_login() sanitized and scoped to active accounts.
--
-- SAFETY & DATA INTEGRITY:
-- - 100% Non-destructive: No tables or data are dropped.
-- - Existing inventory, users, items, and historical records are preserved.
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Privilege Escalation Protection (Trigger & Function Hardening)
-- ----------------------------------------------------------------------------

-- 1.1 Secure get_auth_role() (Strictly server-authoritative)
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

    -- Return verified database role or default to 'User' (do NOT trust client user_metadata for admin)
    RETURN COALESCE(v_role, 'User');
END;
$$;

GRANT EXECUTE ON FUNCTION public.get_auth_role() TO anon, authenticated;

-- 1.2 Enhanced Elevation & Tenant Protection Trigger (BEFORE INSERT OR UPDATE)
CREATE OR REPLACE FUNCTION public.fn_protect_user_elevation()
RETURNS TRIGGER AS $$
DECLARE
    v_caller_role TEXT;
    v_caller_tenant TEXT;
BEGIN
    -- Allow internal service_role / background admin processes unrestricted access
    IF current_user = 'service_role' OR auth.role() = 'service_role' THEN
        RETURN NEW;
    END IF;

    -- Retrieve cryptographic role and tenant of current authenticated caller
    v_caller_role := public.get_auth_role();
    v_caller_tenant := public.get_auth_tenant_id();

    -- A. INSERT GUARD (Prevents self-registration with elevated roles)
    IF TG_OP = 'INSERT' THEN
        -- Only Superadmin, Admin, or Manager can insert with specified roles
        IF v_caller_role = 'Superadmin' THEN
            -- Superadmin can create any role in any tenant
            RETURN NEW;
        ELSIF v_caller_role = 'Admin' THEN
            IF NEW.role = 'Superadmin' THEN
                RAISE EXCEPTION 'Security Exception (403): Admins cannot create Superadmin accounts.';
            END IF;
            IF NEW.tenant_id <> v_caller_tenant THEN
                RAISE EXCEPTION 'Security Exception (403): Admins can only create users in their assigned facility.';
            END IF;
        ELSIF v_caller_role = 'Manager' THEN
            IF NEW.role <> 'User' THEN
                RAISE EXCEPTION 'Security Exception (403): Managers can only create standard User accounts.';
            END IF;
            IF NEW.tenant_id <> v_caller_tenant THEN
                RAISE EXCEPTION 'Security Exception (403): Managers can only create users in their assigned facility.';
            END IF;
        ELSE
            -- Any other caller / direct REST insert is strictly forced to 'User' role
            NEW.role := 'User';
            IF NEW.tenant_id IS NULL OR NEW.tenant_id = '' THEN
                NEW.tenant_id := 'tenant-default';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    -- B. UPDATE GUARD (Prevents privilege elevation or unauthorized profile changes)
    IF TG_OP = 'UPDATE' THEN
        -- Rule 1: Role Modification Guard
        IF (NEW.role IS DISTINCT FROM OLD.role) THEN
            IF v_caller_role NOT IN ('Superadmin', 'Admin') THEN
                RAISE EXCEPTION 'Security Exception (403): You are not authorized to modify user roles.';
            END IF;

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

        -- Rule 2: Facility / Tenant Assignment Guard (Superadmin Only)
        IF (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id) THEN
            IF v_caller_role <> 'Superadmin' THEN
                RAISE EXCEPTION 'Security Exception (403): Only Superadmins are authorized to modify user facility assignments.';
            END IF;
        END IF;

        -- Rule 3: Status Modification Guard (Active / Suspended)
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

        -- Rule 4: Profile Editing Guard
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
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth, pg_temp;

DROP TRIGGER IF EXISTS trg_protect_user_elevation ON public.users;
CREATE TRIGGER trg_protect_user_elevation
BEFORE INSERT OR UPDATE ON public.users
FOR EACH ROW EXECUTE FUNCTION public.fn_protect_user_elevation();

-- 1.3 Clean up Users RLS Policy (Remove client metadata bypass)
DROP POLICY IF EXISTS "Tenant isolation users" ON public.users;
CREATE POLICY "Tenant isolation users" ON public.users
  FOR ALL TO authenticated
  USING (
    id::text = auth.uid()::text 
    OR email = auth.jwt()->>'email'
    OR public.get_auth_role() = 'Superadmin'
    OR tenant_id = public.get_auth_tenant_id()
  )
  WITH CHECK (
    id::text = auth.uid()::text 
    OR email = auth.jwt()->>'email'
    OR public.get_auth_role() = 'Superadmin'
    OR tenant_id = public.get_auth_tenant_id()
  );

-- ----------------------------------------------------------------------------
-- 2. Audit Trail Preservation on SKU Deletion (Preserve History)
-- ----------------------------------------------------------------------------
-- Drop cascade constraint and set to ON DELETE SET NULL on inventory_history
ALTER TABLE public.inventory_history DROP CONSTRAINT IF EXISTS inventory_history_item_id_fkey;
ALTER TABLE public.inventory_history ALTER COLUMN item_id DROP NOT NULL;
ALTER TABLE public.inventory_history ADD CONSTRAINT inventory_history_item_id_fkey 
    FOREIGN KEY (item_id) REFERENCES public.items(id) ON DELETE SET NULL;

-- ----------------------------------------------------------------------------
-- 3. Immutable Append-Only Ledger for Audit History (No UPDATE/DELETE)
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Tenant isolation inventory_history" ON public.inventory_history;
DROP POLICY IF EXISTS "Tenant select inventory_history" ON public.inventory_history;
DROP POLICY IF EXISTS "Tenant insert inventory_history" ON public.inventory_history;

-- 3.1 SELECT: Authenticated users can view history within their facility (or Superadmin all)
CREATE POLICY "Tenant select inventory_history" ON public.inventory_history
  FOR SELECT TO authenticated
  USING (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin');

-- 3.2 INSERT: Authenticated users / stored procedures can append audit records
CREATE POLICY "Tenant insert inventory_history" ON public.inventory_history
  FOR INSERT TO authenticated
  WITH CHECK (tenant_id = public.get_auth_tenant_id() OR public.get_auth_role() = 'Superadmin');

-- Note: No UPDATE or DELETE policy is defined. PostgreSQL RLS strictly denies all UPDATE and DELETE requests on inventory_history.

-- ----------------------------------------------------------------------------
-- 4. Subtraction Guard in execute_stock_movement (No Phantom Stock)
-- ----------------------------------------------------------------------------
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

    v_caller_name := COALESCE(v_caller_name, 'Warehouse Staff');

    -- 2. Lookup Item in Caller's Tenant (or Superadmin scope)
    SELECT sku, name, COALESCE(reorder_point, 0.00), tenant_id
    INTO v_sku, v_item_name, v_reorder_point, v_caller_tenant
    FROM public.items 
    WHERE id = p_item_id AND (tenant_id = v_caller_tenant OR v_caller_role = 'Superadmin');

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Catalog item not found in your facility.');
    END IF;

    -- 3. Lookup Current Inventory in Location (Row Lock for ACID atomicity)
    SELECT id, quantity INTO v_inv_id, v_prev_qty
    FROM public.inventory
    WHERE tenant_id = v_caller_tenant AND item_id = p_item_id AND location = v_loc
    FOR UPDATE;

    v_prev_qty := COALESCE(v_prev_qty, 0.00);

    -- 4. Calculate New Balance with Insufficient Stock Guard
    IF v_action = 'ADD' THEN
        v_new_qty := v_prev_qty + ABS(p_quantity_change);
    ELSIF v_action = 'SUBTRACT' THEN
        IF v_prev_qty < ABS(p_quantity_change) THEN
            RETURN jsonb_build_object(
                'success', false, 
                'error', format('Insufficient stock at location %s: Available %s, requested dispatch %s.', v_loc, v_prev_qty, ABS(p_quantity_change))
            );
        END IF;
        v_new_qty := v_prev_qty - ABS(p_quantity_change);
    ELSIF v_action = 'ADJUST' THEN
        v_new_qty := GREATEST(0.00, p_quantity_change);
    ELSE
        RETURN jsonb_build_object('success', false, 'error', format('Invalid action type "%s". Permitted: ADD, SUBTRACT, ADJUST.', p_action_type));
    END IF;

    v_calc_change := v_new_qty - v_prev_qty;

    -- 5. Determine Stock Status
    IF v_new_qty <= 0.00 THEN
        v_status := 'Out of Stock';
    ELSIF v_new_qty <= v_reorder_point THEN
        v_status := 'Low Stock';
    ELSE
        v_status := 'Available';
    END IF;

    -- 6. Upsert Inventory Balance
    IF v_inv_id IS NOT NULL THEN
        UPDATE public.inventory
        SET quantity = v_new_qty,
            status = v_status,
            updated_at = NOW()
        WHERE id = v_inv_id;
    ELSE
        v_inv_id := 'inv-' || floor(extract(epoch from now()) * 1000)::text || '-' || substr(md5(random()::text), 1, 4);
        INSERT INTO public.inventory (id, tenant_id, item_id, location, quantity, status, updated_at)
        VALUES (v_inv_id, v_caller_tenant, p_item_id, v_loc, v_new_qty, v_status, NOW());
    END IF;

    -- 7. Insert Single Authoritative Audit History Record
    v_hist_id := 'hist-' || floor(extract(epoch from now()) * 1000)::text || '-' || substr(md5(random()::text), 1, 4);
    v_clean_notes := COALESCE(TRIM(p_notes), v_action || ' operation completed');

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
-- 5. Atomic Stock Transfer Stored Procedure (Single ACID Transaction)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.execute_stock_transfer(
    p_item_id TEXT,
    p_from_location TEXT,
    p_to_location TEXT,
    p_quantity NUMERIC,
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
    v_from_loc TEXT := UPPER(TRIM(p_from_location));
    v_to_loc TEXT := UPPER(TRIM(p_to_location));
    v_qty NUMERIC(12, 2) := ABS(p_quantity);
    
    v_from_inv_id TEXT;
    v_from_prev_qty NUMERIC(12, 2) := 0.00;
    v_from_new_qty NUMERIC(12, 2) := 0.00;
    v_from_status TEXT;

    v_to_inv_id TEXT;
    v_to_prev_qty NUMERIC(12, 2) := 0.00;
    v_to_new_qty NUMERIC(12, 2) := 0.00;
    v_to_status TEXT;

    v_hist_out_id TEXT;
    v_hist_in_id TEXT;
    v_clean_notes TEXT;
BEGIN
    IF v_qty <= 0 THEN
        RETURN jsonb_build_object('success', false, 'error', 'Transfer quantity must be greater than zero.');
    END IF;

    IF v_from_loc = v_to_loc THEN
        RETURN jsonb_build_object('success', false, 'error', 'Source and destination locations cannot be identical.');
    END IF;

    -- 1. Identify Caller & Facility
    v_caller_role := public.get_auth_role();
    v_caller_tenant := public.get_auth_tenant_id();

    SELECT full_name INTO v_caller_name 
    FROM public.users 
    WHERE id::text = auth.uid()::text OR email = auth.jwt()->>'email'
    LIMIT 1;

    v_caller_name := COALESCE(v_caller_name, 'Warehouse Staff');

    -- 2. Lookup Catalog Item
    SELECT sku, name, COALESCE(reorder_point, 0.00), tenant_id
    INTO v_sku, v_item_name, v_reorder_point, v_caller_tenant
    FROM public.items 
    WHERE id = p_item_id AND (tenant_id = v_caller_tenant OR v_caller_role = 'Superadmin');

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Catalog item not found in your facility.');
    END IF;

    -- 3. Lock & Verify Source Location Inventory
    SELECT id, quantity INTO v_from_inv_id, v_from_prev_qty
    FROM public.inventory
    WHERE tenant_id = v_caller_tenant AND item_id = p_item_id AND location = v_from_loc
    FOR UPDATE;

    v_from_prev_qty := COALESCE(v_from_prev_qty, 0.00);

    IF v_from_prev_qty < v_qty THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', format('Insufficient stock at source location %s: Available %s, requested transfer %s.', v_from_loc, v_from_prev_qty, v_qty)
        );
    END IF;

    v_from_new_qty := v_from_prev_qty - v_qty;
    v_from_status := CASE WHEN v_from_new_qty <= 0 THEN 'Out of Stock' WHEN v_from_new_qty <= v_reorder_point THEN 'Low Stock' ELSE 'Available' END;

    -- 4. Lock & Update Destination Location Inventory
    SELECT id, quantity INTO v_to_inv_id, v_to_prev_qty
    FROM public.inventory
    WHERE tenant_id = v_caller_tenant AND item_id = p_item_id AND location = v_to_loc
    FOR UPDATE;

    v_to_prev_qty := COALESCE(v_to_prev_qty, 0.00);
    v_to_new_qty := v_to_prev_qty + v_qty;
    v_to_status := CASE WHEN v_to_new_qty <= 0 THEN 'Out of Stock' WHEN v_to_new_qty <= v_reorder_point THEN 'Low Stock' ELSE 'Available' END;

    -- 5. Apply Updates to Source & Destination
    UPDATE public.inventory
    SET quantity = v_from_new_qty, status = v_from_status, updated_at = NOW()
    WHERE id = v_from_inv_id;

    IF v_to_inv_id IS NOT NULL THEN
        UPDATE public.inventory
        SET quantity = v_to_new_qty, status = v_to_status, updated_at = NOW()
        WHERE id = v_to_inv_id;
    ELSE
        v_to_inv_id := 'inv-' || floor(extract(epoch from now()) * 1000)::text || '-' || substr(md5(random()::text), 1, 4);
        INSERT INTO public.inventory (id, tenant_id, item_id, location, quantity, status, updated_at)
        VALUES (v_to_inv_id, v_caller_tenant, p_item_id, v_to_loc, v_to_new_qty, v_to_status, NOW());
    END IF;

    -- 6. Insert Historical Audit Trail for Transfer
    v_clean_notes := COALESCE(TRIM(p_notes), 'Stock transfer: ' || v_from_loc || ' -> ' || v_to_loc);
    v_hist_out_id := 'hist-' || floor(extract(epoch from now()) * 1000)::text || '-' || substr(md5(random()::text), 1, 4);
    v_hist_in_id := 'hist-' || (floor(extract(epoch from now()) * 1000) + 1)::text || '-' || substr(md5(random()::text), 1, 4);

    -- Transfer Out Entry
    INSERT INTO public.inventory_history (
        id, tenant_id, item_id, sku, item_name, action_type,
        qty_change, previous_qty, new_qty, location, user_name, notes, created_at
    ) VALUES (
        v_hist_out_id, v_caller_tenant, p_item_id, v_sku, v_item_name, 'TRANSFER_OUT',
        -v_qty, v_from_prev_qty, v_from_new_qty, v_from_loc, v_caller_name, v_clean_notes, NOW()
    );

    -- Transfer In Entry
    INSERT INTO public.inventory_history (
        id, tenant_id, item_id, sku, item_name, action_type,
        qty_change, previous_qty, new_qty, location, user_name, notes, created_at
    ) VALUES (
        v_hist_in_id, v_caller_tenant, p_item_id, v_sku, v_item_name, 'TRANSFER_IN',
        v_qty, v_to_prev_qty, v_to_new_qty, v_to_loc, v_caller_name, v_clean_notes, NOW()
    );

    RETURN jsonb_build_object(
        'success', true,
        'from_location', v_from_loc,
        'from_quantity', v_from_new_qty,
        'to_location', v_to_loc,
        'to_quantity', v_to_new_qty,
        'transferred_quantity', v_qty
    );
END;
$$;

GRANT EXECUTE ON FUNCTION public.execute_stock_transfer(TEXT, TEXT, TEXT, NUMERIC, TEXT) TO authenticated;

-- ----------------------------------------------------------------------------
-- 6. Hardened Identifier Resolver Function
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.get_email_for_login(p_identifier TEXT)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_email TEXT;
    v_clean TEXT := LOWER(TRIM(p_identifier));
BEGIN
    IF v_clean IS NULL OR LENGTH(v_clean) < 1 THEN
        RETURN NULL;
    END IF;

    SELECT email INTO v_email 
    FROM public.users 
    WHERE (LOWER(username) = v_clean OR LOWER(email) = v_clean)
      AND status = 'Active'
    LIMIT 1;

    RETURN v_email;
END;
$$;

GRANT EXECUTE ON FUNCTION public.get_email_for_login(TEXT) TO anon, authenticated;

COMMIT;
