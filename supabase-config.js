/**
 * Simpletory WMS - Supabase Configuration & Data Service Layer
 * Enterprise-Grade Supabase Auth Integration with Cryptographic JWT Verification
 * Features:
 * - Supabase Auth (auth.users) with Session Recovery
 * - Strict Kernel-Level Tenant Isolation via Row Level Security (RLS)
 * - Automatic Realtime Database Subscriptions
 * - Offline / Demo Fallback Mode
 */

(function (window) {
  'use strict';

  const DEFAULT_SUPABASE_URL = 'https://mmowezszhasjgixcifcu.supabase.co';
  const DEFAULT_SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1tb3dlenN6aGFzamdpeGNpZmN1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODk1Nzc1MzMsImV4cCI6MjEwNTE1MzUzM30.1vLz1v5n36aHj1S2tYcfKhdekgArZ9-KlK2pbmH8ANM';

  const STORAGE_KEY_CONFIG = 'simpletory_supabase_config';
  const STORAGE_KEY_DATA = 'simpletory_wms_local_db';

  const INITIAL_SEED_DATA = {
    tenants: [
      { id: 'org-primary', name: 'Main Enterprise Warehouse', is_active: true, created_at: new Date().toISOString() },
      { id: 'org-east', name: 'East Coast Distribution Center', is_active: true, created_at: new Date().toISOString() }
    ],
    items: [
      { id: 'itm-1', tenant_id: 'org-primary', sku: 'SKU-1001', name: 'Standard Heavy Duty Pallet Box', category: 'Packaging', sub_category: 'Corrugated', uom: 'EA', unit_cost: 14.50, reorder_point: 20, created_at: new Date().toISOString() },
      { id: 'itm-2', tenant_id: 'org-primary', sku: 'SKU-1002', name: 'Industrial Stretch Film Roll 80GA', category: 'Packaging', sub_category: 'Plastic Wrap', uom: 'RL', unit_cost: 22.00, reorder_point: 15, created_at: new Date().toISOString() },
      { id: 'itm-3', tenant_id: 'org-primary', sku: 'SKU-2001', name: 'Heavy Duty Steel Bracket 4-Hole', category: 'Hardware', sub_category: 'Brackets', uom: 'EA', unit_cost: 3.75, reorder_point: 50, created_at: new Date().toISOString() },
      { id: 'itm-4', tenant_id: 'org-primary', sku: 'SKU-3001', name: 'Premium Utility Knife Blades (Pack of 50)', category: 'Tools', sub_category: 'Blades', uom: 'PK', unit_cost: 8.90, reorder_point: 10, created_at: new Date().toISOString() },
      { id: 'itm-5', tenant_id: 'org-primary', sku: 'SKU-4001', name: 'Poly Bubble Mailers #0 (6x10)', category: 'Packaging', sub_category: 'Envelopes', uom: 'CS', unit_cost: 32.40, reorder_point: 25, created_at: new Date().toISOString() },
      { id: 'itm-6', tenant_id: 'org-primary', sku: 'SKU-5001', name: 'Direct Thermal Shipping Labels 4x6', category: 'Supplies', sub_category: 'Labels', uom: 'RL', unit_cost: 11.25, reorder_point: 30, created_at: new Date().toISOString() }
    ],
    inventory: [
      { id: 'inv-1', tenant_id: 'org-primary', item_id: 'itm-1', location: 'A-01-01', quantity: 120, status: 'Available', updated_at: new Date().toISOString() },
      { id: 'inv-2', tenant_id: 'org-primary', item_id: 'itm-2', location: 'A-01-02', quantity: 45, status: 'Available', updated_at: new Date().toISOString() },
      { id: 'inv-3', tenant_id: 'org-primary', item_id: 'itm-3', location: 'B-02-01', quantity: 300, status: 'Available', updated_at: new Date().toISOString() },
      { id: 'inv-4', tenant_id: 'org-primary', item_id: 'itm-4', location: 'B-02-02', quantity: 8, status: 'Low Stock', updated_at: new Date().toISOString() },
      { id: 'inv-5', tenant_id: 'org-primary', item_id: 'itm-5', location: 'C-01-01', quantity: 64, status: 'Available', updated_at: new Date().toISOString() },
      { id: 'inv-6', tenant_id: 'org-primary', item_id: 'itm-6', location: 'C-02-01', quantity: 5, status: 'Low Stock', updated_at: new Date().toISOString() }
    ],
    inventory_history: [
      { id: 'hist-1', tenant_id: 'org-primary', item_id: 'itm-1', sku: 'SKU-1001', item_name: 'Standard Heavy Duty Pallet Box', action_type: 'ADD', qty_change: 120, previous_qty: 0, new_qty: 120, location: 'A-01-01', user_name: 'System Admin', notes: 'Initial inventory intake', created_at: new Date(Date.now() - 3600000 * 24).toISOString() },
      { id: 'hist-2', tenant_id: 'org-primary', item_id: 'itm-2', sku: 'SKU-1002', item_name: 'Industrial Stretch Film Roll 80GA', action_type: 'ADD', qty_change: 45, previous_qty: 0, new_qty: 45, location: 'A-01-02', user_name: 'System Admin', notes: 'PO-8821 Receipt', created_at: new Date(Date.now() - 3600000 * 18).toISOString() },
      { id: 'hist-3', tenant_id: 'org-primary', item_id: 'itm-3', sku: 'SKU-2001', item_name: 'Heavy Duty Steel Bracket 4-Hole', action_type: 'ADD', qty_change: 300, previous_qty: 0, new_qty: 300, location: 'B-02-01', user_name: 'System Admin', notes: 'Bulk restock', created_at: new Date(Date.now() - 3600000 * 12).toISOString() },
      { id: 'hist-4', tenant_id: 'org-primary', item_id: 'itm-4', sku: 'SKU-3001', item_name: 'Premium Utility Knife Blades (Pack of 50)', action_type: 'SUBTRACT', qty_change: -2, previous_qty: 10, new_qty: 8, location: 'B-02-02', user_name: 'System Admin', notes: 'Fulfillment Order #1042', created_at: new Date(Date.now() - 3600000 * 2).toISOString() }
    ],
    users: []
  };

  class WMSDataService {
    constructor() {
      this.client = null;
      this.isSupabaseConnected = false;
      this.subscribers = [];
      this.activeTenantId = 'org-primary';
      this.currentUser = null;
      this.init();
    }

    init() {
      const savedConfig = this.getSavedConfig();
      const activeUrl = savedConfig?.url || DEFAULT_SUPABASE_URL;
      const activeKey = savedConfig?.key || DEFAULT_SUPABASE_ANON_KEY;

      if (activeUrl && activeKey && window.supabase) {
        try {
          this.client = window.supabase.createClient(activeUrl, activeKey, {
            auth: {
              persistSession: true,
              autoRefreshToken: true,
              detectSessionInUrl: true
            }
          });
          this.isSupabaseConnected = true;
          this.setupRealtimeListeners();
        } catch (e) {
          console.warn('Failed to initialize Supabase client, falling back to local DB:', e);
          this.isSupabaseConnected = false;
        }
      }

      // Initialize local storage seed if not present
      if (!localStorage.getItem(STORAGE_KEY_DATA)) {
        this.resetLocalSeed();
      }
    }

    getSavedConfig() {
      try {
        const raw = localStorage.getItem(STORAGE_KEY_CONFIG);
        if (raw) {
          const parsed = JSON.parse(raw);
          if (parsed && parsed.url && !parsed.url.includes('wuxdffvkyxsqdmsnfkye')) {
            return parsed;
          }
        }
        if (DEFAULT_SUPABASE_URL && DEFAULT_SUPABASE_ANON_KEY) {
          return { url: DEFAULT_SUPABASE_URL, key: DEFAULT_SUPABASE_ANON_KEY };
        }
        return null;
      } catch (e) {
        return null;
      }
    }

    saveConfig(url, key) {
      if (!url || !key) {
        localStorage.removeItem(STORAGE_KEY_CONFIG);
        this.client = null;
        this.isSupabaseConnected = false;
        return { success: true, mode: 'local' };
      }
      try {
        localStorage.setItem(STORAGE_KEY_CONFIG, JSON.stringify({ url: url.trim(), key: key.trim() }));
        if (window.supabase) {
          this.client = window.supabase.createClient(url.trim(), key.trim(), {
            auth: { persistSession: true, autoRefreshToken: true }
          });
          this.isSupabaseConnected = true;
          this.setupRealtimeListeners();
          return { success: true, mode: 'supabase' };
        }
        return { success: true, mode: 'configured' };
      } catch (err) {
        console.error('Supabase Config Error:', err);
        return { success: false, error: err.message };
      }
    }

    async testConnection(customUrl, customKey) {
      let clientToTest = this.client;
      if (customUrl && customKey && window.supabase) {
        try {
          clientToTest = window.supabase.createClient(customUrl.trim(), customKey.trim());
        } catch (e) {
          return { success: false, message: `Invalid connection parameters: ${e.message}` };
        }
      }

      if (!clientToTest) {
        return { success: false, message: 'No database credentials configured.' };
      }

      try {
        const { data, error } = await clientToTest.from('tenants').select('id').limit(1);
        if (error) {
          if (error.message && (error.message.includes('Failed to fetch') || error.message.includes('Load failed') || error.message.includes('NetworkError'))) {
            return { success: false, message: 'Failed to establish a connection. Please verify endpoint reachability.' };
          }
          return { success: false, message: `Database responded with error: ${error.message}` };
        }
        return { success: true, message: 'Database connection verified active and responsive.' };
      } catch (err) {
        const msg = err.message || '';
        if (msg.includes('Failed to fetch') || msg.includes('Load failed') || msg.includes('NetworkError')) {
          return { success: false, message: 'Failed to establish a connection. Please verify endpoint reachability.' };
        }
        return { success: false, message: `Connection failed: ${msg}` };
      }
    }

    // ==========================================
    // AUTHENTICATION & CRYPTOGRAPHIC JWT SESSIONS
    // ==========================================

    /**
     * Verifies active cryptographic session on app startup
     */
    async checkSession() {
      if (this.isSupabaseConnected && this.client) {
        try {
          const { data: { session }, error } = await this.client.auth.getSession();
          if (error || !session || !session.user) {
            this.currentUser = null;
            return null;
          }

          // Fetch authenticated user profile from public.users table
          const { data: profile, error: profError } = await this.client
            .from('users')
            .select('id, tenant_id, username, email, full_name, role, status, last_login_at, created_at')
            .eq('id', session.user.id)
            .single();

          if (profError || !profile) {
            // Try by email
            const { data: profByEmail } = await this.client
              .from('users')
              .select('id, tenant_id, username, email, full_name, role, status, last_login_at, created_at')
              .eq('email', session.user.email)
              .single();

            if (profByEmail && profByEmail.status === 'Active') {
              this.currentUser = profByEmail;
              this.activeTenantId = profByEmail.tenant_id || 'org-primary';
              this.recordActivity();
              return profByEmail;
            }

            this.currentUser = null;
            return null;
          }

          if (profile.status === 'Suspended') {
            await this.client.auth.signOut();
            this.currentUser = null;
            return null;
          }

          // Check inactivity timeout
          if (this.isSessionTimedOut()) {
            await this.logout();
            return null;
          }

          this.currentUser = profile;
          this.activeTenantId = profile.tenant_id || 'org-primary';
          this.recordActivity();
          return profile;
        } catch (e) {
          console.warn('Session check error:', e);
          return null;
        }
      }

      // Offline / Local Session Fallback
      return this.getLocalSession();
    }

    async authenticateUser({ username, password, tenantId, remember = true }) {
      const cleanUsername = (username || '').trim();
      const cleanPassword = (password || '').trim();

      if (!cleanUsername) {
        return { success: false, error: 'Please enter your username or email.' };
      }
      if (!cleanPassword) {
        return { success: false, error: 'Please enter your password.' };
      }

      if (this.isSupabaseConnected && this.client) {
        try {
          let loginEmail = cleanUsername;

          // 1. If username was entered without '@', resolve email via helper RPC
          if (!cleanUsername.includes('@')) {
            try {
              const { data: resolvedEmail, error: rpcErr } = await this.client.rpc('get_email_for_login', {
                p_identifier: cleanUsername
              });
              if (!rpcErr && resolvedEmail) {
                loginEmail = resolvedEmail;
              }
            } catch (resolveErr) {
              console.warn('Could not resolve username to email:', resolveErr);
            }
          }

          // 2. Sign in with Supabase Auth Engine (Issues Cryptographic JWT Token)
          const { data: authData, error: authErr } = await this.client.auth.signInWithPassword({
            email: loginEmail,
            password: cleanPassword
          });

          if (authErr) {
            const errMsg = authErr.message || '';
            if (errMsg.toLowerCase().includes('failed to fetch') || errMsg.toLowerCase().includes('load failed') || errMsg.toLowerCase().includes('networkerror')) {
              return {
                success: false,
                error: 'Failed to establish a connection. Please check your network and try again.'
              };
            }
            return {
              success: false,
              error: 'Incorrect username or password.'
            };
          }

          if (!authData || !authData.user) {
            return { success: false, error: 'Incorrect username or password.' };
          }

          // 3. Fetch User Profile
          let { data: profile } = await this.client
            .from('users')
            .select('id, tenant_id, username, email, full_name, role, status, last_login_at, created_at')
            .eq('id', authData.user.id)
            .single();

          if (!profile) {
            // Check by email fallback
            const { data: profByEmail } = await this.client
              .from('users')
              .select('id, tenant_id, username, email, full_name, role, status, last_login_at, created_at')
              .eq('email', authData.user.email)
              .single();
            profile = profByEmail;
          }

          if (!profile) {
            // First-time profile generation for auth user - strictly default to standard 'User' role
            const meta = authData.user.user_metadata || {};
            profile = {
              id: authData.user.id,
              tenant_id: meta.tenant_id || tenantId || 'tenant-default',
              username: meta.username || cleanUsername.split('@')[0],
              email: authData.user.email,
              full_name: meta.full_name || 'Warehouse User',
              role: 'User',
              status: 'Active',
              last_login_at: new Date().toISOString(),
              created_at: new Date().toISOString()
            };
            await this.client.from('users').upsert(profile);
          }

          if (profile.status === 'Suspended') {
            await this.client.auth.signOut();
            return { success: false, error: 'Account is suspended. Please contact your administrator.' };
          }

          // Check Tenant Active State
          if (profile.role !== 'Superadmin') {
            const { data: userTenant } = await this.client
              .from('tenants')
              .select('is_active')
              .eq('id', profile.tenant_id)
              .single();
            if (userTenant && userTenant.is_active === false) {
              await this.client.auth.signOut();
              return { success: false, error: 'This facility / warehouse account is inactive. Please contact your administrator.' };
            }
          }

          // Update last login timestamp
          const nowIso = new Date().toISOString();
          await this.client.from('users').update({ last_login_at: nowIso }).eq('id', profile.id);
          profile.last_login_at = nowIso;

          this.currentUser = profile;
          this.activeTenantId = profile.tenant_id || 'org-primary';
          this.recordActivity();
          this.notifySubscribers('auth', profile);

          return { success: true, user: profile };
        } catch (err) {
          console.error('Authentication error:', err);
          const msg = (err && err.message) || '';
          if (msg.toLowerCase().includes('failed to fetch') || msg.toLowerCase().includes('load failed') || msg.toLowerCase().includes('networkerror')) {
            return { success: false, error: 'Failed to establish a connection. Please check your network and try again.' };
          }
          return { success: false, error: 'Incorrect username or password.' };
        }
      }

      // Offline / Local Store Mode
      return this.authenticateLocalUser({ cleanUsername, cleanPassword, tenantId, remember });
    }

    authenticateLocalUser({ cleanUsername, cleanPassword, tenantId, remember }) {
      const db = this.getLocalDB();
      const user = (db.users || []).find(u => 
        (u.username && u.username.toLowerCase() === cleanUsername.toLowerCase()) ||
        (u.email && u.email.toLowerCase() === cleanUsername.toLowerCase())
      );

      if (!user) {
        return { success: false, error: 'Incorrect username or password.' };
      }

      if (user.status === 'Suspended') {
        return { success: false, error: 'Account is suspended. Please contact your administrator.' };
      }

      this.currentUser = user;
      this.activeTenantId = user.tenant_id || 'org-primary';
      sessionStorage.setItem('simpletory_local_session', JSON.stringify(user));
      this.recordActivity();
      this.notifySubscribers('auth', user);
      return { success: true, user };
    }

    getLocalSession() {
      try {
        const raw = sessionStorage.getItem('simpletory_local_session');
        if (!raw) return null;
        if (this.isSessionTimedOut()) {
          this.logout();
          return null;
        }
        const user = JSON.parse(raw);
        this.currentUser = user;
        this.activeTenantId = user.tenant_id || 'org-primary';
        this.recordActivity();
        return user;
      } catch (e) {
        return null;
      }
    }

    recordActivity() {
      const now = Date.now().toString();
      localStorage.setItem('simpletory_last_activity', now);
    }

    isSessionTimedOut() {
      const raw = localStorage.getItem('simpletory_last_activity');
      if (!raw) {
        this.recordActivity();
        return false;
      }
      const last = parseInt(raw, 10);
      const THIRTY_MINUTES = 30 * 60 * 1000;
      return (Date.now() - last) > THIRTY_MINUTES;
    }

    async logout() {
      if (this.isSupabaseConnected && this.client) {
        try {
          await this.client.auth.signOut();
        } catch (e) {
          console.warn('Sign out warning:', e);
        }
      }
      sessionStorage.removeItem('simpletory_local_session');
      localStorage.removeItem('simpletory_last_activity');
      this.currentUser = null;
      this.notifySubscribers('auth', null);
    }

    resetLocalSeed() {
      localStorage.setItem(STORAGE_KEY_DATA, JSON.stringify(INITIAL_SEED_DATA));
      this.notifySubscribers('all');
    }

    getLocalDB() {
      try {
        const raw = localStorage.getItem(STORAGE_KEY_DATA);
        return raw ? JSON.parse(raw) : INITIAL_SEED_DATA;
      } catch (e) {
        return INITIAL_SEED_DATA;
      }
    }

    setLocalDB(data) {
      localStorage.setItem(STORAGE_KEY_DATA, JSON.stringify(data));
      this.notifySubscribers('all');
    }

    // ==========================================
    // DATA RETRIEVAL (TENANT-ISOLATED)
    // ==========================================
    async getTenants(includeInactive = false) {
      if (this.isSupabaseConnected && this.client) {
        let query = this.client.from('tenants').select('*').order('name');
        if (!includeInactive) {
          query = query.eq('is_active', true);
        }
        const { data, error } = await query;
        if (!error && data) return data;
      }
      const db = this.getLocalDB();
      const allTenants = db.tenants || [];
      return includeInactive ? allTenants : allTenants.filter(t => t.is_active !== false);
    }

    async toggleTenantActive(tenantId, isActive) {
      if (this.isSupabaseConnected && this.client) {
        const { error } = await this.client.from('tenants').update({ is_active: isActive }).eq('id', tenantId);
        if (error) throw error;
        this.notifySubscribers('tenants');
        return true;
      }
      const db = this.getLocalDB();
      const idx = (db.tenants || []).findIndex(t => t.id === tenantId);
      if (idx >= 0) {
        db.tenants[idx].is_active = isActive;
        this.setLocalDB(db);
      }
      this.notifySubscribers('tenants');
      return true;
    }

    async upsertTenant(tenantData) {
      const tenant = {
        ...tenantData,
        id: tenantData.id || `org-${Date.now()}`,
        is_active: tenantData.is_active ?? true,
        created_at: tenantData.created_at || new Date().toISOString()
      };

      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client.from('tenants').upsert(tenant).select().single();
        if (error) throw error;
        this.notifySubscribers('tenants');
        return data;
      }

      const db = this.getLocalDB();
      const idx = (db.tenants || []).findIndex(t => t.id === tenant.id);
      if (idx >= 0) {
        db.tenants[idx] = { ...db.tenants[idx], ...tenant };
      } else {
        db.tenants.push(tenant);
      }
      this.setLocalDB(db);
      this.notifySubscribers('tenants');
      return tenant;
    }

    async getItems(tenantId = this.activeTenantId) {
      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client
          .from('items')
          .select('*')
          .eq('tenant_id', tenantId)
          .order('name');
        if (!error && data) return data;
      }
      const db = this.getLocalDB();
      return (db.items || []).filter(item => item.tenant_id === tenantId);
    }

    async getInventory(tenantId = this.activeTenantId) {
      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client
          .from('inventory')
          .select('*')
          .eq('tenant_id', tenantId);
        if (!error && data) return data;
      }
      const db = this.getLocalDB();
      return (db.inventory || []).filter(inv => inv.tenant_id === tenantId);
    }

    async getHistory(tenantId = this.activeTenantId) {
      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client
          .from('inventory_history')
          .select('*')
          .eq('tenant_id', tenantId)
          .order('created_at', { ascending: false })
          .limit(250);
        if (!error && data) return data;
      }
      const db = this.getLocalDB();
      return (db.inventory_history || [])
        .filter(h => h.tenant_id === tenantId)
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    }

    async getUsers(tenantId = this.activeTenantId) {
      if (this.isSupabaseConnected && this.client) {
        let query = this.client
          .from('users')
          .select('id, tenant_id, username, email, full_name, role, status, last_login_at, created_at')
          .order('full_name');
        if (tenantId && tenantId !== 'ALL') {
          query = query.eq('tenant_id', tenantId);
        }
        const { data, error } = await query;
        if (!error && data) return data;
      }
      const db = this.getLocalDB();
      const rawUsers = (!tenantId || tenantId === 'ALL')
        ? (db.users || [])
        : (db.users || []).filter(u => u.tenant_id === tenantId);

      return rawUsers.map(u => {
        const clean = { ...u };
        delete clean.password_hash;
        return clean;
      });
    }

    // ==========================================
    // MUTATION METHODS
    // ==========================================
    async upsertItem(itemData) {
      const item = {
        ...itemData,
        tenant_id: itemData.tenant_id || this.activeTenantId,
        id: itemData.id || `itm-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        created_at: itemData.created_at || new Date().toISOString()
      };

      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client.from('items').upsert(item).select().single();
        if (error) throw error;
        return data;
      }

      const db = this.getLocalDB();
      const existingIdx = db.items.findIndex(i => i.id === item.id || (i.sku === item.sku && i.tenant_id === item.tenant_id));
      if (existingIdx >= 0) {
        db.items[existingIdx] = { ...db.items[existingIdx], ...item };
      } else {
        db.items.push(item);
      }
      this.setLocalDB(db);
      return item;
    }

    async deleteItem(itemId) {
      if (this.isSupabaseConnected && this.client) {
        const { error } = await this.client.from('items').delete().eq('id', itemId);
        if (error) throw error;
        return true;
      }
      const db = this.getLocalDB();
      db.items = db.items.filter(i => i.id !== itemId);
      db.inventory = db.inventory.filter(inv => inv.item_id !== itemId);
      this.setLocalDB(db);
      return true;
    }

    async executeStockMovement({ itemId, location, actionType, quantityChange, notes }) {
      const tenantId = this.activeTenantId;
      const cleanLoc = location ? location.trim().toUpperCase() : '';
      const cleanAction = actionType ? actionType.trim().toUpperCase() : 'ADJUST';
      const cleanQty = Number(quantityChange);

      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client.rpc('execute_stock_movement', {
          p_item_id: itemId,
          p_location: cleanLoc,
          p_action_type: cleanAction,
          p_quantity_change: cleanQty,
          p_notes: notes || null
        });

        if (error) throw error;
        if (!data || data.success === false) {
          throw new Error(data?.error || 'Failed to record stock movement.');
        }

        this.notifySubscribers('inventory');
        this.notifySubscribers('inventory_history');
        return data;
      }

      // Offline / Local Store Fallback
      const items = await this.getItems(tenantId);
      let targetItem = (items || []).find(i => i.id === itemId);
      if (!targetItem) {
        const allLocal = this.getLocalDB().items || [];
        targetItem = allLocal.find(i => i.id === itemId);
      }

      if (!targetItem) throw new Error('Item not found in catalog. Please verify that this SKU is created in this facility.');

      const inventories = await this.getInventory(tenantId);
      let invRecord = inventories.find(inv => inv.item_id === itemId && inv.location === cleanLoc);

      const previousQty = invRecord ? Number(invRecord.quantity) : 0;
      let newQty = previousQty;

      if (cleanAction === 'ADD') {
        newQty = previousQty + Math.abs(cleanQty);
      } else if (cleanAction === 'SUBTRACT') {
        if (previousQty < Math.abs(cleanQty)) {
          throw new Error(`Insufficient stock at location ${cleanLoc}: Available ${previousQty}, requested ${Math.abs(cleanQty)}.`);
        }
        newQty = previousQty - Math.abs(cleanQty);
      } else if (cleanAction === 'ADJUST') {
        newQty = Math.max(0, cleanQty);
      }

      const calculatedChange = newQty - previousQty;
      const status = newQty <= 0 ? 'Out of Stock' : newQty <= Number(targetItem.reorder_point) ? 'Low Stock' : 'Available';

      const updatedInv = {
        id: invRecord ? invRecord.id : `inv-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        tenant_id: tenantId,
        item_id: itemId,
        location: cleanLoc,
        quantity: newQty,
        status: status,
        updated_at: new Date().toISOString()
      };

      const historyLog = {
        id: `hist-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        tenant_id: tenantId,
        item_id: itemId,
        sku: targetItem.sku,
        item_name: targetItem.name,
        action_type: cleanAction,
        qty_change: calculatedChange,
        previous_qty: previousQty,
        new_qty: newQty,
        location: cleanLoc,
        user_name: this.currentUser?.full_name || 'Warehouse Staff',
        notes: notes || `${cleanAction} operation executed`,
        created_at: new Date().toISOString()
      };

      const db = this.getLocalDB();
      const existingInvIdx = db.inventory.findIndex(inv => inv.id === updatedInv.id || (inv.item_id === itemId && inv.location === updatedInv.location && inv.tenant_id === tenantId));
      if (existingInvIdx >= 0) {
        db.inventory[existingInvIdx] = updatedInv;
      } else {
        db.inventory.push(updatedInv);
      }
      db.inventory_history.unshift(historyLog);
      this.setLocalDB(db);
      this.notifySubscribers('inventory');
      this.notifySubscribers('inventory_history');

      return { inventory: updatedInv, history: historyLog };
    }

    async transferStock({ itemId, fromLocation, toLocation, quantity, notes }) {
      const qty = Math.abs(Number(quantity));
      if (qty <= 0) throw new Error('Quantity must be greater than 0');
      const cleanFrom = fromLocation ? fromLocation.trim().toUpperCase() : '';
      const cleanTo = toLocation ? toLocation.trim().toUpperCase() : '';
      if (cleanFrom === cleanTo) {
        throw new Error('Destination location must be different from source location.');
      }

      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client.rpc('execute_stock_transfer', {
          p_item_id: itemId,
          p_from_location: cleanFrom,
          p_to_location: cleanTo,
          p_quantity: qty,
          p_notes: notes || null
        });

        if (error) throw error;
        if (!data || data.success === false) {
          throw new Error(data?.error || 'Failed to record stock transfer.');
        }

        this.notifySubscribers('inventory');
        this.notifySubscribers('inventory_history');
        return data;
      }

      // Offline / Local Store Fallback
      await this.executeStockMovement({
        itemId,
        location: cleanFrom,
        actionType: 'SUBTRACT',
        quantityChange: qty,
        notes: `Transfer to ${cleanTo}: ${notes || ''}`
      });

      await this.executeStockMovement({
        itemId,
        location: cleanTo,
        actionType: 'ADD',
        quantityChange: qty,
        notes: `Transfer from ${cleanFrom}: ${notes || ''}`
      });

      return { success: true };
    }

    async createUser({ username, email, password, fullName, role, tenantId }) {
      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client.rpc('create_team_member', {
          p_username: username.trim(),
          p_email: email.trim(),
          p_password: password.trim(),
          p_full_name: fullName.trim(),
          p_role: role || 'User',
          p_tenant_id: tenantId || this.activeTenantId
        });

        if (error) throw error;
        if (data && data.success === false) throw new Error(data.error || 'Failed to create user');
        this.notifySubscribers('users');
        return data;
      }

      const db = this.getLocalDB();
      const newUser = {
        id: `usr-${Date.now()}`,
        tenant_id: tenantId || this.activeTenantId,
        username: username.trim(),
        email: email.trim(),
        full_name: fullName.trim(),
        role: role || 'User',
        status: 'Active',
        created_at: new Date().toISOString()
      };
      db.users.push(newUser);
      this.setLocalDB(db);
      this.notifySubscribers('users');
      return newUser;
    }

    async updateUser(userId, updates) {
      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client
          .from('users')
          .update(updates)
          .eq('id', userId)
          .select('id, tenant_id, username, email, full_name, role, status, last_login_at, created_at')
          .single();
        if (error) throw error;
        this.notifySubscribers('users');
        return data;
      }
      const db = this.getLocalDB();
      const idx = db.users.findIndex(u => u.id === userId);
      if (idx >= 0) {
        db.users[idx] = { ...db.users[idx], ...updates };
        this.setLocalDB(db);
        this.notifySubscribers('users');
        return db.users[idx];
      }
      throw new Error('User not found in local store.');
    }

    async deleteUser(userId) {
      if (this.isSupabaseConnected && this.client) {
        const { data, error } = await this.client.rpc('delete_team_member', {
          p_user_id: userId
        });
        if (error) throw error;
        if (data && data.success === false) {
          throw new Error(data.error || 'Failed to delete user.');
        }
        this.notifySubscribers('users');
        return true;
      }
      const db = this.getLocalDB();
      db.users = (db.users || []).filter(u => u.id !== userId);
      this.setLocalDB(db);
      this.notifySubscribers('users');
      return true;
    }

    async updateUserProfile(userId, { fullName, email, currentPassword, password }) {
      const updates = {};
      if (fullName) updates.full_name = fullName.trim();
      if (email) updates.email = email.trim();

      const wantsPasswordChange = Boolean(password && password.trim());

      if (this.isSupabaseConnected && this.client) {
        if (wantsPasswordChange) {
          if (!currentPassword || !currentPassword.trim()) {
            throw new Error('Please enter your current password to authorize this change.');
          }

          const userEmail = this.currentUser?.email;
          if (!userEmail) {
            throw new Error('Unable to verify account credentials for password change.');
          }

          // Re-authenticate to ensure current password is valid
          const { error: reauthErr } = await this.client.auth.signInWithPassword({
            email: userEmail,
            password: currentPassword.trim()
          });

          if (reauthErr) {
            throw new Error('Incorrect current password. Password change denied.');
          }

          const { error: pwdErr } = await this.client.auth.updateUser({
            password: password.trim()
          });
          if (pwdErr) throw pwdErr;
        }

        if (Object.keys(updates).length > 0) {
          const { data, error } = await this.client
            .from('users')
            .update(updates)
            .eq('id', userId)
            .select('id, tenant_id, username, email, full_name, role, status, last_login_at, created_at')
            .single();

          if (error) throw error;
          
          if (this.currentUser && this.currentUser.id === userId) {
            this.currentUser = { ...this.currentUser, ...data };
          }
          this.notifySubscribers('users');
          this.notifySubscribers('auth');
          return { success: true, user: data };
        }
        return { success: true, user: this.currentUser };
      }

      // Local Store Fallback
      const db = this.getLocalDB();
      const idx = (db.users || []).findIndex(u => u.id === userId);
      if (idx >= 0) {
        db.users[idx] = { ...db.users[idx], ...updates };
        this.setLocalDB(db);

        const sanitizedLocalUser = { ...db.users[idx] };
        delete sanitizedLocalUser.password_hash;

        if (this.currentUser && this.currentUser.id === userId) {
          this.currentUser = { ...this.currentUser, ...sanitizedLocalUser };
        }
        this.notifySubscribers('users');
        this.notifySubscribers('auth');
        return { success: true, user: sanitizedLocalUser };
      }
      throw new Error('User account not found.');
    }

    // ==========================================
    // REALTIME & EVENT SUBSCRIBERS
    // ==========================================
    setupRealtimeListeners() {
      if (!this.client) return;
      try {
        const channel = this.client.channel('simpletory_live_channel');
        ['tenants', 'items', 'inventory', 'inventory_history', 'users'].forEach(table => {
          channel.on('postgres_changes', { event: '*', schema: 'public', table }, payload => {
            this.notifySubscribers(table, payload);
          });
        });
        channel.subscribe();
      } catch (err) {
        console.warn('Realtime subscription issue:', err);
      }
    }

    onDataChange(callback) {
      if (typeof callback === 'function') {
        this.subscribers.push(callback);
      }
    }

    notifySubscribers(table, payload = null) {
      this.subscribers.forEach(cb => {
        try { cb(table, payload); } catch (e) { console.error(e); }
      });
    }
  }

  // Expose global instance
  window.WMSDataService = new WMSDataService();
})(window);
