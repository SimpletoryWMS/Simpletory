-- ============================================================================
-- SIMPLETORY WMS - UNIFIED ATOMIC STOCK MOVEMENT & SINGLE-ENTRY AUDIT LOG
-- Migration Date: 2026-09-28
-- Target: Supabase PostgreSQL (GoTrue & PostgREST Compatible)
--
-- PURPOSE:
-- 1. Eliminates duplicate audit records by replacing dual trigger + client logging
--    with a single, atomic, transactional database stored procedure.
-- 2. Secures stock movements with row-level locks (FOR UPDATE) to prevent race
--    conditions and concurrency conflicts.
-- 3. Attaches authentic cryptographic user identity (auth.uid() -> full_name)
--    and custom movement notes in the exact same ACID transaction.
-- ============================================================================

BEGIN;

-- 1. Drop Legacy Dual-Logging Trigger (Prevents duplicate audit records)
DROP TRIGGER IF EXISTS trg_audit_inventory ON public.inventory;
DROP FUNCTION IF EXISTS public.fn_audit_inventory_changes();

-- 2. Create Unified Atomic Stock Movement Stored Procedure
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

    -- Multi-facility authorization guard: Only Superadmins can operate on arbitrary facilities
    IF v_caller_role <> 'Superadmin' AND v_target_tenant <> v_caller_tenant THEN
        RETURN jsonb_build_object('success', false, 'error', 'Permission denied: Cannot perform stock operations outside your assigned facility.');
    END IF;

    SELECT full_name INTO v_caller_name 
    FROM public.users 
    WHERE id::text = auth.uid()::text OR email = auth.jwt()->>'email'
    LIMIT 1;

    v_caller_name := COALESCE(v_caller_name, auth.jwt()->'user_metadata'->>'full_name', 'Warehouse Staff');

    -- 2. Lookup Item in Target Tenant (or Global Catalog for Superadmin)
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

COMMIT;
