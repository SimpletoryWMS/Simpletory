/**
 * SIMPLETORY WMS - CORE APPLICATION CONTROLLER
 * Ultra-responsive, modern frontend logic with 4-tier RBAC security (Superadmin, Admin, Manager, User),
 * automated change logging, and interactive user guides.
 */

document.addEventListener('DOMContentLoaded', () => {
  const App = {
    currentView: 'dashboard',
    currentReportType: 'movement-summary',
    items: [],
    inventory: [],
    history: [],
    users: [],
    tenants: [],
    theme: localStorage.getItem('simpletory_theme') || 'dark',

    // ==========================================
    // INITIALIZATION
    // ==========================================
    async init() {
      this.applyTheme(this.theme);
      this.bindAuth();
      this.bindNavigation();
      this.bindModals();
      this.bindForms();
      this.bindGlobalActions();
      this.bindShortcuts();
      this.bindHelpCenter();
      this.bindUserProfileMenu();
      this.initReportsModule();
      this.initIdleTimeoutTracker();

      // Listen for data mutations (realtime or local)
      window.WMSDataService.onDataChange((topic) => {
        if (topic === 'auth') {
          this.checkAuthState();
        } else {
          this.refreshAllData();
        }
      });

      await this.checkAuthState();
      this.updateSyncIndicator();
    },

    // ==========================================
    // INACTIVITY IDLE TIMEOUT ENGINE (30 MIN)
    // ==========================================
    initIdleTimeoutTracker() {
      let lastRecorded = Date.now();

      const onUserActivity = () => {
        const now = Date.now();
        // Throttle activity recording to at most once every 10 seconds
        if (now - lastRecorded > 10000) {
          lastRecorded = now;
          window.WMSDataService.recordActivity();
        }
      };

      // Listen for user interaction events across the page
      ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'].forEach(evt => {
        window.addEventListener(evt, onUserActivity, { passive: true });
      });

      // Periodic check every 15 seconds
      setInterval(() => {
        if (window.WMSDataService.currentUser && window.WMSDataService.isSessionTimedOut()) {
          this.handleSessionTimeout();
        }
      }, 15000);

      // Check when user returns to tab / wakes device
      document.addEventListener('visibilitychange', () => {
        if (!document.hidden && window.WMSDataService.currentUser && window.WMSDataService.isSessionTimedOut()) {
          this.handleSessionTimeout();
        }
      });
    },

    handleSessionTimeout() {
      window.WMSDataService.logout();
      const authAlert = document.getElementById('auth-error-alert');
      if (authAlert) {
        authAlert.textContent = 'Your session has expired due to 30 minutes of inactivity. Please sign in again.';
        authAlert.style.display = 'block';
      }
      this.showToast('Session expired after 30 minutes of inactivity.', 'warning');
      this.checkAuthState();
    },

    // ==========================================
    // SECURITY UTILITIES: XSS SANITIZATION
    // ==========================================
    escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    },

    escapeAttr(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    },

    // ==========================================
    // AUTHENTICATION CONTROLLER & SESSION STATE
    // ==========================================
    async checkAuthState() {
      const user = await window.WMSDataService.checkSession();
      const authOverlay = document.getElementById('auth-overlay') || document.querySelector('.auth-view');
      const appContainer = document.getElementById('app-container') || document.querySelector('.app-container');

      if (!user) {
        if (authOverlay) authOverlay.style.display = 'flex';
        if (appContainer) {
          appContainer.style.display = 'none';
          appContainer.style.filter = 'none';
        }
        this.currentUser = null;
        this.items = [];
        this.inventory = [];
        this.history = [];
        this.users = [];
        return false;
      } else {
        if (authOverlay) authOverlay.style.display = 'none';
        if (appContainer) {
          appContainer.style.display = 'flex';
          appContainer.style.filter = 'none';
        }
        await this.loadTenants();
        this.applyRolePermissions();
        await this.refreshAllData();
        return true;
      }
    },

    bindAuth() {
      const loginForm = document.getElementById('form-login');
      const authAlert = document.getElementById('auth-error-alert');
      const btnSubmit = document.getElementById('btn-login-submit');
      const btnTogglePwd = document.getElementById('btn-toggle-pwd');
      const pwdInput = document.getElementById('login-password');

      if (btnTogglePwd && pwdInput) {
        btnTogglePwd.addEventListener('click', () => {
          const isPwd = pwdInput.type === 'password';
          pwdInput.type = isPwd ? 'text' : 'password';
          btnTogglePwd.innerHTML = isPwd
            ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
            : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
        });
      }

      if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const username = document.getElementById('login-username').value;
          const password = pwdInput ? pwdInput.value : '';
          const remember = document.getElementById('login-remember')?.checked ?? true;

          if (btnSubmit) {
            btnSubmit.disabled = true;
            btnSubmit.innerHTML = `<span>Authenticating...</span>`;
          }
          if (authAlert) authAlert.style.display = 'none';

          try {
            const res = await window.WMSDataService.authenticateUser({
              username,
              password,
              remember
            });

            if (res.success) {
              this.showToast(`Welcome back, ${res.user.full_name}!`, 'success');
              await this.checkAuthState();
            } else {
              if (authAlert) {
                authAlert.textContent = res.error || 'Authentication failed.';
                authAlert.style.display = 'block';
              }
              this.showToast(res.error || 'Invalid credentials.', 'danger');
            }
          } catch (err) {
            if (authAlert) {
              authAlert.textContent = `Error: ${err.message}`;
              authAlert.style.display = 'block';
            }
          } finally {
            if (btnSubmit) {
              btnSubmit.disabled = false;
              btnSubmit.innerHTML = `<span>Sign In to WMS</span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>`;
            }
          }
        });
      }
    },

    bindUserProfileMenu() {
      const toggleBtn = document.getElementById('btn-user-profile-toggle');
      const menu = document.getElementById('user-dropdown-menu');
      const editProfileBtn = document.getElementById('btn-header-edit-profile');
      const signoutBtn = document.getElementById('btn-header-signout');

      if (toggleBtn && menu) {
        toggleBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const isOpen = menu.classList.toggle('show');
          toggleBtn.classList.toggle('active', isOpen);
        });

        document.addEventListener('click', (e) => {
          if (!e.target.closest('#user-profile-menu-container')) {
            menu.classList.remove('show');
            toggleBtn.classList.remove('active');
          }
        });
      }

      if (editProfileBtn) {
        editProfileBtn.addEventListener('click', (e) => {
          e.preventDefault();
          if (menu) menu.classList.remove('show');
          if (toggleBtn) toggleBtn.classList.remove('active');
          this.openProfileModal();
        });
      }

      if (signoutBtn) {
        signoutBtn.addEventListener('click', async (e) => {
          e.preventDefault();
          if (menu) menu.classList.remove('show');
          if (toggleBtn) toggleBtn.classList.remove('active');
          await window.WMSDataService.logout();
          this.showToast('You have been signed out.', 'info');
          await this.checkAuthState();
        });
      }

      // Toggle profile password visibility (Current & New)
      const btnToggleProfCurrPwd = document.getElementById('btn-toggle-profile-curr-pwd');
      const profCurrPwdInput = document.getElementById('profile-current-password');
      if (btnToggleProfCurrPwd && profCurrPwdInput) {
        btnToggleProfCurrPwd.addEventListener('click', () => {
          const isPwd = profCurrPwdInput.type === 'password';
          profCurrPwdInput.type = isPwd ? 'text' : 'password';
          btnToggleProfCurrPwd.innerHTML = isPwd
            ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
            : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
        });
      }

      const btnToggleProfPwd = document.getElementById('btn-toggle-profile-pwd');
      const profPwdInput = document.getElementById('profile-password');
      if (btnToggleProfPwd && profPwdInput) {
        btnToggleProfPwd.addEventListener('click', () => {
          const isPwd = profPwdInput.type === 'password';
          profPwdInput.type = isPwd ? 'text' : 'password';
          btnToggleProfPwd.innerHTML = isPwd
            ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
            : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
        });
      }
    },

    openProfileModal() {
      const user = window.WMSDataService.currentUser;
      if (!user) return;

      const userTenant = (this.allTenants || []).find(t => t.id === user.tenant_id);
      const facilityName = userTenant ? userTenant.name : (user.tenant_id || 'Primary Facility');

      const idInput = document.getElementById('profile-user-id');
      const nameInput = document.getElementById('profile-fullname');
      const usernameInput = document.getElementById('profile-username');
      const facilityInput = document.getElementById('profile-facility');
      const roleInput = document.getElementById('profile-role');
      const emailInput = document.getElementById('profile-email');
      const currPwdInput = document.getElementById('profile-current-password');
      const pwdInput = document.getElementById('profile-password');
      const pwdConfirmInput = document.getElementById('profile-password-confirm');
      const alertEl = document.getElementById('profile-error-alert');

      if (idInput) idInput.value = user.id || '';
      if (nameInput) nameInput.value = user.full_name || '';
      if (usernameInput) usernameInput.value = user.username || '';
      if (facilityInput) facilityInput.value = facilityName;
      if (roleInput) roleInput.value = user.role || 'User';
      if (emailInput) emailInput.value = user.email || '';
      if (currPwdInput) currPwdInput.value = '';
      if (pwdInput) pwdInput.value = '';
      if (pwdConfirmInput) pwdConfirmInput.value = '';
      if (alertEl) alertEl.style.display = 'none';

      this.openModal('modal-profile');
    },

    // ==========================================
    // THEME CONTROLLER
    // ==========================================
    applyTheme(theme) {
      this.theme = theme;
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('simpletory_theme', theme);
      const icon = document.getElementById('theme-toggle-icon');
      if (icon) {
        icon.innerHTML = theme === 'dark'
          ? `<path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>`
          : `<path d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" fill="currentColor"/>`;
      }
    },

    toggleTheme() {
      this.applyTheme(this.theme === 'dark' ? 'light' : 'dark');
    },

    // ==========================================
    // RBAC & ROLE LOCKING CONTROLLER
    // ==========================================
    applyRolePermissions() {
      const user = window.WMSDataService.currentUser;
      if (!user) return;
      const role = user.role || 'User';
      const isSuperadmin = role === 'Superadmin';
      const isAdmin = isSuperadmin || role === 'Admin';
      const isManager = isAdmin || role === 'Manager';

      // Update header badge and dropdown display
      const avatarEl = document.getElementById('header-user-avatar');
      const nameEl = document.getElementById('header-user-name');
      const roleEl = document.getElementById('header-user-role');

      const dropAvatarEl = document.getElementById('dropdown-user-avatar');
      const dropNameEl = document.getElementById('dropdown-user-name');
      const dropEmailEl = document.getElementById('dropdown-user-email');
      const dropRoleBadgeEl = document.getElementById('dropdown-user-role-badge');

      const initial = user.full_name ? user.full_name.charAt(0).toUpperCase() : 'U';
      if (avatarEl) avatarEl.textContent = initial;
      if (nameEl) nameEl.textContent = user.full_name || 'User';
      if (roleEl) roleEl.textContent = role;

      if (dropAvatarEl) dropAvatarEl.textContent = initial;
      if (dropNameEl) dropNameEl.textContent = user.full_name || 'User';
      if (dropEmailEl) dropEmailEl.textContent = user.email || `${user.username || 'user'}@simpletory.com`;
      if (dropRoleBadgeEl) {
        dropRoleBadgeEl.textContent = role;
        const badgeClass = isSuperadmin ? 'badge-danger' : (role === 'Admin' ? 'badge-primary' : (role === 'Manager' ? 'badge-warning' : 'badge-neutral'));
        dropRoleBadgeEl.className = `badge ${badgeClass} user-dropdown-role-badge`;
      }

      // 1. Settings View (Supabase Link): Locked to Superadmin only
      const navSettings = document.getElementById('nav-settings');
      if (navSettings) {
        navSettings.style.display = isSuperadmin ? 'flex' : 'none';
      }

      // 2. Tenant / Facility Picker: Locked to Superadmin only
      const tenantPicker = document.getElementById('tenant-picker-container');
      if (tenantPicker) {
        tenantPicker.style.display = isSuperadmin ? 'flex' : 'none';
      }

      // 3. Team & User Management: Locked to Superadmin, Admin, and Manager
      const navUsers = document.getElementById('nav-users');
      if (navUsers) {
        navUsers.style.display = isManager ? 'flex' : 'none';
      }

      // 4. Catalog Creation / Editing: Locked to Superadmin, Admin, and Manager
      const btnDashNew = document.getElementById('btn-dash-new-sku');
      const btnCatNew = document.getElementById('btn-catalog-add-sku');
      if (btnDashNew) btnDashNew.style.display = isManager ? 'inline-flex' : 'none';
      if (btnCatNew) btnCatNew.style.display = isManager ? 'inline-flex' : 'none';

      // Re-render items table to show/hide edit actions based on role
      this.renderItemsTable();

      // If user is on a locked view, redirect to dashboard
      if (this.currentView === 'settings' && !isSuperadmin) {
        this.switchView('dashboard');
      } else if (this.currentView === 'users' && !isManager) {
        this.switchView('dashboard');
      }
    },

    // ==========================================
    // NAVIGATION & VIEW SWITCHING
    // ==========================================
    bindNavigation() {
      const navItems = document.querySelectorAll('.nav-item');
      navItems.forEach(item => {
        item.addEventListener('click', (e) => {
          e.preventDefault();
          const targetView = item.getAttribute('data-view');
          if (targetView) this.switchView(targetView);
        });
      });

      const tenantSelect = document.getElementById('tenant-select');
      if (tenantSelect) {
        tenantSelect.addEventListener('change', async (e) => {
          window.WMSDataService.activeTenantId = e.target.value;
          this.showToast(`Switched facility to: ${e.target.selectedOptions[0].text}`, 'info');
          await this.refreshAllData();
        });
      }
    },

    switchView(viewName) {
      const user = window.WMSDataService.currentUser;
      const role = user ? user.role : 'User';
      const isSuperadmin = role === 'Superadmin';
      const isAdmin = isSuperadmin || role === 'Admin';
      const isManager = isAdmin || role === 'Manager';

      // Guard locked views
      if (viewName === 'settings' && !isSuperadmin) {
        return this.showToast('Access Denied: System settings are restricted to Superadmin.', 'danger');
      }
      if (viewName === 'users' && !isManager) {
        return this.showToast('Access Denied: Team management is restricted to Managers, Admins, and Superadmins.', 'warning');
      }

      this.currentView = viewName;
      
      // Update nav active class
      document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.toggle('active', el.getAttribute('data-view') === viewName);
      });

      // Update view containers
      document.querySelectorAll('.view-container').forEach(container => {
        container.classList.remove('active');
      });

      const targetEl = document.getElementById(`view-${viewName}`);
      if (targetEl) {
        targetEl.classList.add('active');
      }

      if (viewName === 'reports') {
        this.renderReports();
      }
    },

    // ==========================================
    // DATA LOADING & REFRESH
    // ==========================================
    async loadTenants() {
      this.tenants = await window.WMSDataService.getTenants(false);
      this.allTenants = await window.WMSDataService.getTenants(true);

      const select = document.getElementById('tenant-select');
      if (select) {
        select.innerHTML = this.tenants.map(t => `<option value="${this.escapeAttr(t.id)}">${this.escapeHtml(t.name)}</option>`).join('');
        // If current active tenant became inactive, switch to first active
        if (!this.tenants.some(t => t.id === window.WMSDataService.activeTenantId) && this.tenants.length > 0) {
          window.WMSDataService.activeTenantId = this.tenants[0].id;
        }
        select.value = window.WMSDataService.activeTenantId;
      }

      this.renderTenantsTable();
    },

    renderTenantsTable() {
      const tbody = document.getElementById('table-tenants-body');
      if (!tbody) return;

      const list = this.allTenants || this.tenants || [];
      if (list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No warehouse facilities configured.</td></tr>`;
        return;
      }

      tbody.innerHTML = list.map(t => {
        const isActive = t.is_active !== false;
        const statusBadge = isActive ? 'badge-success' : 'badge-danger';
        const statusText = isActive ? 'Active' : 'Inactive (Hidden)';
        const btnClass = isActive ? 'btn-danger' : 'btn-success';
        const btnText = isActive ? 'Deactivate' : 'Activate';

        return `
          <tr>
            <td><code style="font-family: var(--font-mono); font-weight: 600;">${this.escapeHtml(t.id)}</code></td>
            <td><strong>${this.escapeHtml(t.name)}</strong></td>
            <td><span class="badge ${statusBadge}">${statusText}</span></td>
            <td style="color: var(--text-muted); font-size: 0.8rem;">${t.created_at ? new Date(t.created_at).toLocaleDateString() : 'Initial'}</td>
            <td style="text-align: right;">
              <button class="btn ${btnClass} btn-sm" onclick="App.toggleTenant('${this.escapeAttr(t.id)}', ${!isActive})">
                ${btnText}
              </button>
            </td>
          </tr>
        `;
      }).join('');
    },

    async toggleTenant(tenantId, newStatus) {
      if (window.WMSDataService.currentUser?.role !== 'Superadmin') {
        return this.showToast('Superadmin permissions required to modify facility status.', 'danger');
      }

      try {
        await window.WMSDataService.toggleTenantActive(tenantId, newStatus);
        this.showToast(`Facility status updated to: ${newStatus ? 'Active' : 'Inactive (Auto-hidden)'}`, 'info');
        await this.loadTenants();
        await this.refreshAllData();
      } catch (err) {
        this.showToast(`Error updating facility: ${err.message}`, 'danger');
      }
    },

    async refreshAllData() {
      const tenantId = window.WMSDataService.activeTenantId;
      const currentUser = window.WMSDataService.currentUser;
      const isSuperadmin = currentUser && currentUser.role === 'Superadmin';

      [this.items, this.inventory, this.history, this.users] = await Promise.all([
        window.WMSDataService.getItems(tenantId),
        window.WMSDataService.getInventory(tenantId),
        window.WMSDataService.getHistory(tenantId),
        window.WMSDataService.getUsers(isSuperadmin ? 'ALL' : tenantId)
      ]);

      this.renderDashboard();
      this.renderInventoryTable();
      this.renderItemsTable();
      this.renderHistoryTable();
      this.renderUsersTable();
      this.renderReports();
      this.populateDropdowns();
      this.updateBadges();
    },

    updateSyncIndicator() {
      const isLive = window.WMSDataService.isSupabaseConnected;
      const dot = document.getElementById('sync-status-dot');
      const text = document.getElementById('sync-status-text');
      if (dot && text) {
        dot.className = isLive ? 'status-dot' : 'status-dot local';
        text.textContent = isLive ? 'Supabase Live' : 'Demo Local Mode';
      }
    },

    updateBadges() {
      const lowStockCount = this.inventory.filter(i => i.status === 'Low Stock' || i.status === 'Out of Stock').length;
      const badge = document.getElementById('nav-inventory-badge');
      if (badge) {
        badge.textContent = lowStockCount > 0 ? lowStockCount : this.inventory.length;
        badge.style.background = lowStockCount > 0 ? 'var(--danger)' : '';
        badge.style.color = lowStockCount > 0 ? '#fff' : '';
      }
    },

    // ==========================================
    // VIEW RENDERING: DASHBOARD
    // ==========================================
    renderDashboard() {
      const totalSkus = this.items.length;
      const totalUnits = this.inventory.reduce((acc, curr) => acc + Number(curr.quantity), 0);
      const lowStockCount = this.inventory.filter(inv => {
        const item = this.items.find(i => i.id === inv.item_id);
        return item && Number(inv.quantity) <= Number(item.reorder_point);
      }).length;

      const totalValuation = this.inventory.reduce((acc, inv) => {
        const item = this.items.find(i => i.id === inv.item_id);
        const cost = item ? Number(item.unit_cost) || 0 : 0;
        return acc + (Number(inv.quantity) * cost);
      }, 0);

      const elSkus = document.getElementById('stat-total-skus');
      const elUnits = document.getElementById('stat-total-units');
      const elLow = document.getElementById('stat-low-stock');
      const elVal = document.getElementById('stat-total-value');

      if (elSkus) elSkus.textContent = totalSkus.toLocaleString();
      if (elUnits) elUnits.textContent = totalUnits.toLocaleString();
      if (elLow) elLow.textContent = lowStockCount.toLocaleString();
      if (elVal) elVal.textContent = `$${totalValuation.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

      // Category breakdown
      const catMap = {};
      this.inventory.forEach(inv => {
        const item = this.items.find(i => i.id === inv.item_id);
        const cat = item ? item.category || 'General' : 'General';
        catMap[cat] = (catMap[cat] || 0) + Number(inv.quantity);
      });

      const catContainer = document.getElementById('dashboard-category-breakdown');
      if (catContainer) {
        const entries = Object.entries(catMap);
        if (entries.length === 0) {
          catContainer.innerHTML = `<div class="form-hint" style="text-align:center; padding: 2rem;">No inventory records found.</div>`;
        } else {
          catContainer.innerHTML = entries.map(([cat, qty]) => {
            const percent = totalUnits > 0 ? Math.round((qty / totalUnits) * 100) : 0;
            return `
              <div style="margin-bottom: 0.85rem;">
                <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 4px;">
                  <span style="font-weight: 600;">${this.escapeHtml(cat)}</span>
                  <span style="color: var(--text-muted);">${qty.toLocaleString()} units (${percent}%)</span>
                </div>
                <div style="height: 8px; background: var(--bg-input); border-radius: 4px; overflow: hidden;">
                  <div style="width: ${percent}%; height: 100%; background: var(--primary); border-radius: 4px;"></div>
                </div>
              </div>
            `;
          }).join('');
        }
      }

      // Recent Activity Feed
      const actContainer = document.getElementById('dashboard-recent-activity');
      if (actContainer) {
        const recent = this.history.slice(0, 5);
        if (recent.length === 0) {
          actContainer.innerHTML = `<div class="form-hint" style="text-align:center; padding: 2rem;">No stock movements recorded yet.</div>`;
        } else {
          actContainer.innerHTML = recent.map(h => {
            const isAdd = h.action_type === 'ADD';
            const isSub = h.action_type === 'SUBTRACT';
            const badgeClass = isAdd ? 'badge-success' : isSub ? 'badge-danger' : 'badge-info';
            const timeAgo = this.formatTimeAgo(h.created_at);
            return `
              <div style="display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 0; border-bottom: 1px solid var(--border-subtle);">
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                  <span class="badge ${badgeClass}">${this.escapeHtml(h.action_type)}</span>
                  <div>
                    <div style="font-weight: 600; font-size: 0.85rem;">${this.escapeHtml(h.item_name)} <span class="sku-tag">(${this.escapeHtml(h.sku)})</span></div>
                    <div style="font-size: 0.75rem; color: var(--text-muted);">${this.escapeHtml(h.notes || 'Movement logged')} • By ${this.escapeHtml(h.user_name)}</div>
                  </div>
                </div>
                <div style="text-align: right;">
                  <div style="font-weight: 700; font-size: 0.85rem; color: ${isAdd ? 'var(--success)' : isSub ? 'var(--danger)' : 'var(--text-primary)'};">
                    ${isAdd ? '+' : ''}${h.qty_change}
                  </div>
                  <div style="font-size: 0.7rem; color: var(--text-muted);">${timeAgo}</div>
                </div>
              </div>
            `;
          }).join('');
        }
      }
    },

    // ==========================================
    // VIEW RENDERING: INVENTORY ON HAND
    // ==========================================
    renderInventoryTable() {
      const tbody = document.getElementById('inventory-table-body');
      if (!tbody) return;

      const searchTerm = (document.getElementById('inventory-search-input')?.value || '').toLowerCase().trim();
      const catFilter = document.getElementById('inventory-category-filter')?.value || '';
      const statusFilter = document.getElementById('inventory-status-filter')?.value || '';

      const filtered = this.inventory.filter(inv => {
        const item = this.items.find(i => i.id === inv.item_id);
        if (!item) return false;

        const matchesSearch = !searchTerm || 
          item.sku.toLowerCase().includes(searchTerm) || 
          item.name.toLowerCase().includes(searchTerm) || 
          inv.location.toLowerCase().includes(searchTerm);

        const matchesCat = !catFilter || item.category === catFilter;
        const matchesStatus = !statusFilter || inv.status === statusFilter;

        return matchesSearch && matchesCat && matchesStatus;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; padding: 2rem; color: var(--text-muted);">No inventory records found matching your filters.</td></tr>`;
        return;
      }      tbody.innerHTML = filtered.map(inv => {
        const item = this.items.find(i => i.id === inv.item_id) || { sku: 'Unknown', name: 'Unknown', category: 'General', sub_category: 'Standard', uom: 'EA', unit_cost: 0 };
        const extVal = (Number(inv.quantity) * Number(item.unit_cost)).toFixed(2);
        const statusBadge = inv.status === 'Available' ? 'badge-success' : inv.status === 'Low Stock' ? 'badge-warning' : 'badge-danger';
        const safeItemId = this.escapeAttr(inv.item_id);
        const safeLocation = this.escapeAttr(inv.location);
        const safeQty = Number(inv.quantity) || 0;

        return `
          <tr>
            <td><span class="sku-tag">${this.escapeHtml(item.sku)}</span></td>
            <td style="font-weight: 600;">${this.escapeHtml(item.name)}</td>
            <td><span class="badge badge-neutral">${this.escapeHtml(item.category || 'General')}</span></td>
            <td><span class="badge badge-neutral" style="opacity: 0.85;">${this.escapeHtml(item.sub_category || 'Standard')}</span></td>
            <td><span class="location-tag">${this.escapeHtml(inv.location)}</span></td>
            <td>
              <div class="qty-stepper-cell">
                <button class="qty-stepper-btn btn-minus" title="Subtract stock (-)" onclick="App.openQuickDispatch('${safeItemId}', '${safeLocation}', ${safeQty})">−</button>
                <strong style="font-size: 0.95rem; min-width: 28px; text-align: center;">${safeQty}</strong>
                <button class="qty-stepper-btn btn-plus" title="Add stock (+)" onclick="App.openQuickIntake('${safeItemId}', '${safeLocation}')">+</button>
              </div>
            </td>
            <td><span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600;">${this.escapeHtml(item.uom)}</span></td>
            <td>$${Number(item.unit_cost).toFixed(2)}</td>
            <td><strong>$${extVal}</strong></td>
            <td><span class="badge ${statusBadge}">${this.escapeHtml(inv.status)}</span></td>
            <td>
              <div class="table-actions">
                <button class="action-btn action-btn-add" title="Quick Add (+)" onclick="App.openQuickIntake('${safeItemId}', '${safeLocation}')">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 5v14m-7-7h14"/></svg> + Add
                </button>
                <button class="action-btn action-btn-sub" title="Quick Subtract (-)" onclick="App.openQuickDispatch('${safeItemId}', '${safeLocation}', ${safeQty})">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14"/></svg> − Subtract
                </button>
                <button class="action-btn" title="Transfer Location" onclick="App.openTransferModal('${safeItemId}', '${safeLocation}', ${safeQty})">
                  ⇄ Move
                </button>
                <button class="action-btn" title="Audit Count / Adjust" onclick="App.openAdjustModal('${safeItemId}', '${safeLocation}', ${safeQty})">
                  ⚙ Adjust
                </button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    },

    // ==========================================
    // VIEW RENDERING: ITEM CATALOG
    // ==========================================
    renderItemsTable() {
      const tbody = document.getElementById('items-table-body');
      if (!tbody) return;

      const role = window.WMSDataService.currentUser?.role || this.currentUser?.role || 'User';
      const canManage = role === 'Superadmin' || role === 'Admin' || role === 'Manager';

      const searchTerm = (document.getElementById('items-search-input')?.value || '').toLowerCase().trim();
      const catFilter = document.getElementById('items-category-filter')?.value || '';

      const filtered = this.items.filter(item => {
        const matchesSearch = !searchTerm || 
          item.sku.toLowerCase().includes(searchTerm) || 
          item.name.toLowerCase().includes(searchTerm) || 
          (item.sub_category && item.sub_category.toLowerCase().includes(searchTerm));
        const matchesCat = !catFilter || item.category === catFilter;
        return matchesSearch && matchesCat;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 2rem; color: var(--text-muted);">No catalog items found.</td></tr>`;
        return;
      }

      tbody.innerHTML = filtered.map(item => {
        const safeItemId = this.escapeAttr(item.id);
        const actionsHtml = canManage ? `
          <div class="table-actions">
            <button class="action-btn" title="Edit SKU" onclick="App.openEditItemModal('${safeItemId}')">✏ Edit</button>
            <button class="action-btn" style="color: var(--danger);" title="Delete" onclick="App.handleDeleteItem('${safeItemId}')">🗑</button>
          </div>
        ` : `<span class="badge badge-neutral">Read Only</span>`;

        return `
          <tr>
            <td><span class="sku-tag">${this.escapeHtml(item.sku)}</span></td>
            <td style="font-weight: 600;">${this.escapeHtml(item.name)}</td>
            <td><span class="badge badge-neutral">${this.escapeHtml(item.category || 'General')}</span></td>
            <td><span class="badge badge-neutral" style="opacity: 0.85;">${this.escapeHtml(item.sub_category || 'Standard')}</span></td>
            <td>${this.escapeHtml(item.uom)}</td>
            <td>$${Number(item.unit_cost || 0).toFixed(2)}</td>
            <td><span style="font-weight: 600; color: var(--warning);">${item.reorder_point || 0}</span></td>
            <td>${actionsHtml}</td>
          </tr>
        `;
      }).join('');
    },

    // ==========================================
    // VIEW RENDERING: AUDIT HISTORY
    // ==========================================
    renderHistoryTable() {
      const tbody = document.getElementById('history-table-body');
      if (!tbody) return;

      const searchTerm = (document.getElementById('history-search-input')?.value || '').toLowerCase().trim();
      const actionFilter = document.getElementById('history-action-filter')?.value || '';

      const filtered = this.history.filter(h => {
        const matchesSearch = !searchTerm ||
          h.sku.toLowerCase().includes(searchTerm) ||
          h.item_name.toLowerCase().includes(searchTerm) ||
          h.location.toLowerCase().includes(searchTerm) ||
          (h.notes && h.notes.toLowerCase().includes(searchTerm)) ||
          h.user_name.toLowerCase().includes(searchTerm);

        const matchesAction = !actionFilter || h.action_type === actionFilter;
        return matchesSearch && matchesAction;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; padding: 2rem; color: var(--text-muted);">No transaction logs recorded.</td></tr>`;
        return;
      }

      tbody.innerHTML = filtered.map(h => {
        const isAdd = h.action_type === 'ADD';
        const isSub = h.action_type === 'SUBTRACT';
        const badgeClass = isAdd ? 'badge-success' : isSub ? 'badge-danger' : 'badge-info';
        const formattedDate = new Date(h.created_at).toLocaleString();

        return `
          <tr>
            <td style="font-size: 0.78rem; color: var(--text-secondary);">${formattedDate}</td>
            <td><span class="sku-tag">${this.escapeHtml(h.sku)}</span></td>
            <td style="font-weight: 600;">${this.escapeHtml(h.item_name)}</td>
            <td><span class="badge ${badgeClass}">${this.escapeHtml(h.action_type)}</span></td>
            <td>
              <strong style="color: ${isAdd ? 'var(--success)' : isSub ? 'var(--danger)' : 'var(--text-primary)'};">
                ${isAdd ? '+' : ''}${h.qty_change}
              </strong>
            </td>
            <td>${h.previous_qty}</td>
            <td>${h.new_qty}</td>
            <td><span class="location-tag">${this.escapeHtml(h.location)}</span></td>
            <td style="font-weight: 500;">${this.escapeHtml(h.user_name)}</td>
            <td style="font-size: 0.8rem; color: var(--text-secondary); max-width: 200px;">${this.escapeHtml(h.notes || '-')}</td>
          </tr>
        `;
      }).join('');
    },

    // ==========================================
    // VIEW RENDERING: USERS & ROLES
    // ==========================================
    renderUsersTable() {
      const tbody = document.getElementById('users-table-body');
      if (!tbody) return;

      const allTenantsList = this.allTenants || this.tenants || [];
      const currentUser = window.WMSDataService.currentUser;
      const callerRole = currentUser?.role || 'User';
      const isCallerSuperadmin = callerRole === 'Superadmin';

      tbody.innerHTML = this.users.map(u => {
        const roleBadge = u.role === 'Superadmin' ? 'badge-danger' : (u.role === 'Admin' ? 'badge-primary' : (u.role === 'Manager' ? 'badge-warning' : 'badge-info'));
        const tenantObj = allTenantsList.find(t => t.id === u.tenant_id);
        const tenantName = tenantObj ? tenantObj.name : (u.tenant_id || 'Primary Facility');
        const safeUserId = this.escapeAttr(u.id);

        const lastLogin = u.last_login_at 
          ? `<span title="${new Date(u.last_login_at).toLocaleString()}">${new Date(u.last_login_at).toLocaleDateString()} ${new Date(u.last_login_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>` 
          : `<span style="color: var(--text-muted); font-size: 0.78rem;">Never</span>`;

        let canManageUser = false;
        if (isCallerSuperadmin) {
          canManageUser = true;
        } else if (callerRole === 'Admin') {
          canManageUser = (u.tenant_id === currentUser?.tenant_id) && u.role !== 'Superadmin';
        } else if (callerRole === 'Manager') {
          canManageUser = (u.tenant_id === currentUser?.tenant_id) && u.role === 'User';
        }

        const actionsHtml = canManageUser ? `
          <div class="table-actions">
            <button class="action-btn" onclick="App.openEditUserModal('${safeUserId}')">✏ Edit</button>
            <button class="action-btn" style="color: var(--danger);" onclick="App.handleDeleteUser('${safeUserId}')">🗑</button>
          </div>
        ` : `<span class="badge badge-neutral">Read Only</span>`;

        return `
          <tr>
            <td>
              <div style="display: flex; align-items: center; gap: 0.65rem;">
                <div class="user-avatar" style="width:26px; height:26px; font-size:0.7rem;">${this.escapeHtml((u.full_name || 'U').charAt(0))}</div>
                <strong style="font-size: 0.85rem;">${this.escapeHtml(u.full_name || 'User')}</strong>
              </div>
            </td>
            <td><code style="font-family: var(--font-mono);">${this.escapeHtml(u.username)}</code></td>
            <td style="color: var(--text-secondary);">${this.escapeHtml(u.email || '-')}</td>
            <td><span class="badge badge-neutral">${this.escapeHtml(tenantName)}</span></td>
            <td><span class="badge ${roleBadge}">${this.escapeHtml(u.role)}</span></td>
            <td><span class="badge ${u.status === 'Active' ? 'badge-success' : 'badge-neutral'}">${this.escapeHtml(u.status || 'Active')}</span></td>
            <td style="font-size: 0.8rem; color: var(--text-secondary); white-space: nowrap;">${lastLogin}</td>
            <td>${actionsHtml}</td>
          </tr>
        `;
      }).join('');
    },

    // ==========================================
    // REPORTS & ANALYTICS ENGINE
    // ==========================================
    initReportsModule() {
      // Set initial 30 days preset
      this.setReportDatePreset('30d');

      // Tab switcher
      const reportTabs = document.querySelectorAll('.report-tab-btn');
      reportTabs.forEach(tab => {
        tab.addEventListener('click', (e) => {
          e.preventDefault();
          reportTabs.forEach(t => t.classList.remove('active'));
          tab.classList.add('active');
          this.currentReportType = tab.getAttribute('data-report') || 'movement-summary';

          const dateControls = document.getElementById('report-date-controls');
          const actionFilter = document.getElementById('report-action-filter');
          
          if (this.currentReportType === 'on-hand') {
            if (dateControls) dateControls.style.opacity = '0.35';
            if (dateControls) dateControls.style.pointerEvents = 'none';
            if (actionFilter) actionFilter.style.display = 'none';
          } else if (this.currentReportType === 'audit-detail') {
            if (dateControls) dateControls.style.opacity = '1';
            if (dateControls) dateControls.style.pointerEvents = 'auto';
            if (actionFilter) actionFilter.style.display = 'inline-block';
          } else {
            if (dateControls) dateControls.style.opacity = '1';
            if (dateControls) dateControls.style.pointerEvents = 'auto';
            if (actionFilter) actionFilter.style.display = 'none';
          }

          this.renderReports();
        });
      });

      // Preset buttons
      const presetBtns = document.querySelectorAll('.report-preset-btn');
      presetBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          presetBtns.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          const preset = btn.getAttribute('data-preset');
          this.setReportDatePreset(preset);
          this.renderReports();
        });
      });

      // Filter change listeners
      ['report-date-from', 'report-date-to', 'report-category-filter', 'report-action-filter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('change', () => this.renderReports());
      });

      const searchInput = document.getElementById('report-search-input');
      if (searchInput) {
        searchInput.addEventListener('input', () => this.renderReports());
      }

      const btnRun = document.getElementById('btn-refresh-report');
      if (btnRun) {
        btnRun.addEventListener('click', () => {
          this.renderReports();
          this.showToast('Report updated with current filters.', 'info');
        });
      }

      const btnExport = document.getElementById('btn-export-csv');
      if (btnExport) {
        btnExport.addEventListener('click', () => this.exportCurrentReport());
      }

      const btnPrint = document.getElementById('btn-print-report');
      if (btnPrint) {
        btnPrint.addEventListener('click', () => window.print());
      }
    },

    setReportDatePreset(preset) {
      const now = new Date();
      const pad = (n) => String(n).padStart(2, '0');
      const toIsoDate = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;

      const fromInput = document.getElementById('report-date-from');
      const toInput = document.getElementById('report-date-to');
      if (!fromInput || !toInput) return;

      toInput.value = toIsoDate(now);

      if (preset === 'today') {
        fromInput.value = toIsoDate(now);
      } else if (preset === '7d') {
        const d = new Date(now);
        d.setDate(d.getDate() - 7);
        fromInput.value = toIsoDate(d);
      } else if (preset === '30d') {
        const d = new Date(now);
        d.setDate(d.getDate() - 30);
        fromInput.value = toIsoDate(d);
      } else if (preset === 'month') {
        const d = new Date(now.getFullYear(), now.getMonth(), 1);
        fromInput.value = toIsoDate(d);
      } else if (preset === 'all') {
        fromInput.value = '2020-01-01';
      }
    },

    getReportDateRange() {
      const fromVal = document.getElementById('report-date-from')?.value;
      const toVal = document.getElementById('report-date-to')?.value;

      let fromDate = null;
      let toDate = null;

      if (fromVal) {
        fromDate = new Date(fromVal + 'T00:00:00');
      }
      if (toVal) {
        toDate = new Date(toVal + 'T23:59:59.999');
      }

      return { fromDate, toDate, fromVal, toVal };
    },

    getFilteredHistoryForReports() {
      const { fromDate, toDate } = this.getReportDateRange();

      return this.history.filter(h => {
        if (!h.created_at) return true;
        const itemDate = new Date(h.created_at);
        if (fromDate && itemDate < fromDate) return false;
        if (toDate && itemDate > toDate) return false;
        return true;
      });
    },

    renderReports() {
      const type = this.currentReportType || 'movement-summary';
      const searchTerm = (document.getElementById('report-search-input')?.value || '').toLowerCase().trim();
      const categoryFilter = document.getElementById('report-category-filter')?.value || 'ALL';
      const actionFilter = document.getElementById('report-action-filter')?.value || 'ALL';
      const { fromVal, toVal } = this.getReportDateRange();

      const timeLabel = document.getElementById('report-timeframe-label');
      if (timeLabel) {
        if (type === 'on-hand') {
          timeLabel.textContent = 'Timeframe: Real-time Live Snapshot';
        } else if (fromVal && toVal) {
          timeLabel.textContent = `Timeframe: ${fromVal} to ${toVal}`;
        } else if (fromVal) {
          timeLabel.textContent = `Timeframe: Since ${fromVal}`;
        } else if (toVal) {
          timeLabel.textContent = `Timeframe: Up to ${toVal}`;
        } else {
          timeLabel.textContent = 'Timeframe: All Recorded Time';
        }
      }

      const filteredHistory = this.getFilteredHistoryForReports();

      switch (type) {
        case 'movement-summary':
          this.renderStockMovementReport(filteredHistory, searchTerm, categoryFilter);
          break;
        case 'received':
          this.renderStockReceivedReport(filteredHistory, searchTerm, categoryFilter);
          break;
        case 'dispatched':
          this.renderStockDispatchedReport(filteredHistory, searchTerm, categoryFilter);
          break;
        case 'on-hand':
          this.renderOnHandReport(searchTerm, categoryFilter);
          break;
        case 'audit-detail':
          this.renderMovementDetailReport(filteredHistory, searchTerm, categoryFilter, actionFilter);
          break;
        default:
          this.renderStockMovementReport(filteredHistory, searchTerm, categoryFilter);
      }
    },

    renderStockMovementReport(filteredHistory, searchTerm, categoryFilter) {
      const titleEl = document.getElementById('report-title-label');
      const countEl = document.getElementById('report-count-badge');
      const thead = document.getElementById('report-table-head');
      const tbody = document.getElementById('report-table-body');
      const tfoot = document.getElementById('report-table-foot');
      const kpiContainer = document.getElementById('report-kpi-cards');

      if (titleEl) titleEl.textContent = 'Stock Movement Report (By Item)';

      thead.innerHTML = `
        <tr>
          <th>SKU</th>
          <th>Item Name</th>
          <th>Category</th>
          <th style="text-align: right;">Inbound (+)</th>
          <th style="text-align: right;">Outbound (-)</th>
          <th style="text-align: right;">Adjust (±)</th>
          <th style="text-align: right;">Net Movement</th>
          <th style="text-align: right;">On Hand</th>
          <th>UOM</th>
          <th style="text-align: right;">Unit Cost</th>
          <th style="text-align: right;">Net Value ($)</th>
          <th style="text-align: center;">Movements</th>
        </tr>
      `;

      const itemsList = this.items.filter(item => {
        const matchesCategory = categoryFilter === 'ALL' || (item.category || 'General') === categoryFilter;
        const matchesSearch = !searchTerm ||
          (item.sku && item.sku.toLowerCase().includes(searchTerm)) ||
          (item.name && item.name.toLowerCase().includes(searchTerm)) ||
          (item.category && item.category.toLowerCase().includes(searchTerm));
        return matchesCategory && matchesSearch;
      });

      let totalInbound = 0;
      let totalOutbound = 0;
      let totalAdjust = 0;
      let totalNet = 0;
      let totalOnHand = 0;
      let totalNetVal = 0;
      let totalMoves = 0;
      let activeItemsCount = 0;

      const rowsData = itemsList.map(item => {
        const itemHistory = filteredHistory.filter(h => h.sku === item.sku || h.item_name === item.name);
        
        let inbound = 0;
        let outbound = 0;
        let adjust = 0;

        itemHistory.forEach(h => {
          const qty = Math.abs(Number(h.qty_change) || 0);
          if (h.action_type === 'ADD' || (h.qty_change > 0 && h.action_type !== 'ADJUST')) {
            inbound += qty;
          } else if (h.action_type === 'SUBTRACT' || (h.qty_change < 0 && h.action_type !== 'ADJUST')) {
            outbound += qty;
          } else if (h.action_type === 'ADJUST') {
            adjust += Number(h.qty_change) || 0;
          }
        });

        const net = inbound - outbound + adjust;
        const moves = itemHistory.length;
        const onHand = this.inventory
          .filter(inv => inv.item_id === item.id)
          .reduce((sum, inv) => sum + Number(inv.quantity || 0), 0);
        const unitCost = Number(item.unit_cost || 0);
        const netValue = net * unitCost;

        if (moves > 0) activeItemsCount++;

        totalInbound += inbound;
        totalOutbound += outbound;
        totalAdjust += adjust;
        totalNet += net;
        totalOnHand += onHand;
        totalNetVal += netValue;
        totalMoves += moves;

        return {
          item,
          inbound,
          outbound,
          adjust,
          net,
          onHand,
          unitCost,
          netValue,
          moves
        };
      });

      if (countEl) countEl.textContent = `${rowsData.length} SKUs`;

      if (kpiContainer) {
        kpiContainer.innerHTML = `
          <div class="stat-card">
            <div class="stat-label">Total Inbound Received</div>
            <div class="stat-value" style="color: var(--success);">+${totalInbound}</div>
            <div class="stat-meta">Units received across all SKUs</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Outbound Dispatched</div>
            <div class="stat-value" style="color: var(--danger);">-${totalOutbound}</div>
            <div class="stat-meta">Units dispatched / picked</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Net Movement Delta</div>
            <div class="stat-value" style="color: ${totalNet >= 0 ? 'var(--success)' : 'var(--danger)'};">${totalNet >= 0 ? '+' : ''}${totalNet}</div>
            <div class="stat-meta">Net inventory physical change</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Active Moving SKUs</div>
            <div class="stat-value">${activeItemsCount} / ${this.items.length}</div>
            <div class="stat-meta">Catalog items with activity</div>
          </div>
        `;
      }

      if (rowsData.length === 0) {
        tbody.innerHTML = `<tr><td colspan="12" style="text-align: center; padding: 2rem; color: var(--text-muted);">No catalog items match current filters.</td></tr>`;
        tfoot.innerHTML = '';
        return;
      }

      tbody.innerHTML = rowsData.map(r => `
        <tr>
          <td><span class="sku-tag">${this.escapeHtml(r.item.sku)}</span></td>
          <td style="font-weight: 600;">${this.escapeHtml(r.item.name)}</td>
          <td><span class="badge badge-neutral">${this.escapeHtml(r.item.category || 'General')}</span></td>
          <td style="text-align: right; color: var(--success); font-weight: 600;">${r.inbound > 0 ? '+' + r.inbound : '0'}</td>
          <td style="text-align: right; color: var(--danger); font-weight: 600;">${r.outbound > 0 ? '-' + r.outbound : '0'}</td>
          <td style="text-align: right; color: ${r.adjust >= 0 ? 'var(--text-primary)' : 'var(--danger)'}; font-weight: 500;">${r.adjust > 0 ? '+' + r.adjust : r.adjust}</td>
          <td style="text-align: right; font-weight: 700; color: ${r.net >= 0 ? 'var(--success)' : 'var(--danger)'};">${r.net >= 0 ? '+' : ''}${r.net}</td>
          <td style="text-align: right; font-weight: 600;">${r.onHand}</td>
          <td style="font-size: 0.8rem; color: var(--text-secondary);">${this.escapeHtml(r.item.uom || 'EA')}</td>
          <td style="text-align: right; font-size: 0.82rem;">$${r.unitCost.toFixed(2)}</td>
          <td style="text-align: right; font-weight: 600; color: ${r.netValue >= 0 ? 'var(--success)' : 'var(--danger)'};">$${r.netValue.toFixed(2)}</td>
          <td style="text-align: center;"><span class="badge badge-info">${r.moves}</span></td>
        </tr>
      `).join('');

      tfoot.innerHTML = `
        <tr>
          <td colspan="3">SUMMARY TOTALS (${rowsData.length} SKUs)</td>
          <td style="text-align: right; color: var(--success);">+${totalInbound}</td>
          <td style="text-align: right; color: var(--danger);">-${totalOutbound}</td>
          <td style="text-align: right;">${totalAdjust >= 0 ? '+' : ''}${totalAdjust}</td>
          <td style="text-align: right; color: ${totalNet >= 0 ? 'var(--success)' : 'var(--danger)'};">${totalNet >= 0 ? '+' : ''}${totalNet}</td>
          <td style="text-align: right;">${totalOnHand}</td>
          <td>-</td>
          <td style="text-align: right;">-</td>
          <td style="text-align: right; color: ${totalNetVal >= 0 ? 'var(--success)' : 'var(--danger)'};">$${totalNetVal.toFixed(2)}</td>
          <td style="text-align: center;">${totalMoves}</td>
        </tr>
      `;
    },

    renderStockReceivedReport(filteredHistory, searchTerm, categoryFilter) {
      const titleEl = document.getElementById('report-title-label');
      const countEl = document.getElementById('report-count-badge');
      const thead = document.getElementById('report-table-head');
      const tbody = document.getElementById('report-table-body');
      const tfoot = document.getElementById('report-table-foot');
      const kpiContainer = document.getElementById('report-kpi-cards');

      if (titleEl) titleEl.textContent = 'Stock Received (Inbound) Report';

      thead.innerHTML = `
        <tr>
          <th>Date & Time</th>
          <th>SKU</th>
          <th>Item Name</th>
          <th>Category</th>
          <th>Destination Location</th>
          <th style="text-align: right;">Qty Received</th>
          <th>UOM</th>
          <th style="text-align: right;">Unit Cost</th>
          <th style="text-align: right;">Total Valuation</th>
          <th>Received By</th>
          <th>PO / Notes</th>
        </tr>
      `;

      const receivedLogs = filteredHistory.filter(h => {
        const isReceived = h.action_type === 'ADD' || (Number(h.qty_change) > 0 && h.action_type !== 'ADJUST');
        if (!isReceived) return false;

        const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
        const matchesCategory = categoryFilter === 'ALL' || (item.category || 'General') === categoryFilter;
        const matchesSearch = !searchTerm ||
          (h.sku && h.sku.toLowerCase().includes(searchTerm)) ||
          (h.item_name && h.item_name.toLowerCase().includes(searchTerm)) ||
          (h.location && h.location.toLowerCase().includes(searchTerm)) ||
          (h.user_name && h.user_name.toLowerCase().includes(searchTerm)) ||
          (h.notes && h.notes.toLowerCase().includes(searchTerm));

        return matchesCategory && matchesSearch;
      });

      let totalUnits = 0;
      let totalValuation = 0;
      const uniqueSkus = new Set();

      const rowsData = receivedLogs.map(h => {
        const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
        const qty = Math.abs(Number(h.qty_change) || 0);
        const unitCost = Number(item.unit_cost || 0);
        const extVal = qty * unitCost;

        totalUnits += qty;
        totalValuation += extVal;
        if (h.sku) uniqueSkus.add(h.sku);

        return {
          h,
          item,
          qty,
          unitCost,
          extVal
        };
      });

      if (countEl) countEl.textContent = `${rowsData.length} receipts`;

      if (kpiContainer) {
        kpiContainer.innerHTML = `
          <div class="stat-card">
            <div class="stat-label">Total Inbound Receipts</div>
            <div class="stat-value" style="color: var(--success);">${rowsData.length}</div>
            <div class="stat-meta">Receiving transactions logged</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Units Received</div>
            <div class="stat-value" style="color: var(--success);">+${totalUnits}</div>
            <div class="stat-meta">Physical intake quantity</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Received Valuation</div>
            <div class="stat-value" style="color: var(--accent);">$${totalValuation.toFixed(2)}</div>
            <div class="stat-meta">Cumulative purchase value</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Unique SKUs Received</div>
            <div class="stat-value">${uniqueSkus.size}</div>
            <div class="stat-meta">Distinct catalog lines</div>
          </div>
        `;
      }

      if (rowsData.length === 0) {
        tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; padding: 2rem; color: var(--text-muted);">No inbound stock receipts found for selected timeframe.</td></tr>`;
        tfoot.innerHTML = '';
        return;
      }

      tbody.innerHTML = rowsData.map(r => `
        <tr>
          <td style="font-size: 0.78rem; color: var(--text-secondary);">${new Date(r.h.created_at).toLocaleString()}</td>
          <td><span class="sku-tag">${this.escapeHtml(r.h.sku)}</span></td>
          <td style="font-weight: 600;">${this.escapeHtml(r.h.item_name)}</td>
          <td><span class="badge badge-neutral">${this.escapeHtml(r.item.category || 'General')}</span></td>
          <td><span class="location-tag">${this.escapeHtml(r.h.location)}</span></td>
          <td style="text-align: right; color: var(--success); font-weight: 700;">+${r.qty}</td>
          <td style="font-size: 0.8rem; color: var(--text-secondary);">${this.escapeHtml(r.item.uom || 'EA')}</td>
          <td style="text-align: right; font-size: 0.82rem;">$${r.unitCost.toFixed(2)}</td>
          <td style="text-align: right; font-weight: 600; color: var(--success);">$${r.extVal.toFixed(2)}</td>
          <td style="font-weight: 500;">${this.escapeHtml(r.h.user_name)}</td>
          <td style="font-size: 0.8rem; color: var(--text-secondary); max-width: 180px;">${this.escapeHtml(r.h.notes || '-')}</td>
        </tr>
      `).join('');

      tfoot.innerHTML = `
        <tr>
          <td colspan="5">SUMMARY TOTALS (${rowsData.length} Receipts)</td>
          <td style="text-align: right; color: var(--success); font-weight: 700;">+${totalUnits}</td>
          <td>-</td>
          <td style="text-align: right;">-</td>
          <td style="text-align: right; color: var(--success); font-weight: 700;">$${totalValuation.toFixed(2)}</td>
          <td colspan="2">-</td>
        </tr>
      `;
    },

    renderStockDispatchedReport(filteredHistory, searchTerm, categoryFilter) {
      const titleEl = document.getElementById('report-title-label');
      const countEl = document.getElementById('report-count-badge');
      const thead = document.getElementById('report-table-head');
      const tbody = document.getElementById('report-table-body');
      const tfoot = document.getElementById('report-table-foot');
      const kpiContainer = document.getElementById('report-kpi-cards');

      if (titleEl) titleEl.textContent = 'Stock Dispatched (Outbound) Report';

      thead.innerHTML = `
        <tr>
          <th>Date & Time</th>
          <th>SKU</th>
          <th>Item Name</th>
          <th>Category</th>
          <th>Source Location</th>
          <th style="text-align: right;">Qty Dispatched</th>
          <th>UOM</th>
          <th style="text-align: right;">Unit Cost</th>
          <th style="text-align: right;">Total Valuation</th>
          <th>Dispatched By</th>
          <th>Order / Notes</th>
        </tr>
      `;

      const dispatchedLogs = filteredHistory.filter(h => {
        const isDispatched = h.action_type === 'SUBTRACT' || (Number(h.qty_change) < 0 && h.action_type !== 'ADJUST');
        if (!isDispatched) return false;

        const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
        const matchesCategory = categoryFilter === 'ALL' || (item.category || 'General') === categoryFilter;
        const matchesSearch = !searchTerm ||
          (h.sku && h.sku.toLowerCase().includes(searchTerm)) ||
          (h.item_name && h.item_name.toLowerCase().includes(searchTerm)) ||
          (h.location && h.location.toLowerCase().includes(searchTerm)) ||
          (h.user_name && h.user_name.toLowerCase().includes(searchTerm)) ||
          (h.notes && h.notes.toLowerCase().includes(searchTerm));

        return matchesCategory && matchesSearch;
      });

      let totalUnits = 0;
      let totalValuation = 0;
      const uniqueSkus = new Set();

      const rowsData = dispatchedLogs.map(h => {
        const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
        const qty = Math.abs(Number(h.qty_change) || 0);
        const unitCost = Number(item.unit_cost || 0);
        const extVal = qty * unitCost;

        totalUnits += qty;
        totalValuation += extVal;
        if (h.sku) uniqueSkus.add(h.sku);

        return {
          h,
          item,
          qty,
          unitCost,
          extVal
        };
      });

      if (countEl) countEl.textContent = `${rowsData.length} dispatches`;

      if (kpiContainer) {
        kpiContainer.innerHTML = `
          <div class="stat-card">
            <div class="stat-label">Total Outbound Dispatches</div>
            <div class="stat-value" style="color: var(--danger);">${rowsData.length}</div>
            <div class="stat-meta">Outbound orders picked / fulfilled</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Units Dispatched</div>
            <div class="stat-value" style="color: var(--danger);">-${totalUnits}</div>
            <div class="stat-meta">Physical inventory shipped</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Dispatched Valuation</div>
            <div class="stat-value" style="color: var(--accent);">$${totalValuation.toFixed(2)}</div>
            <div class="stat-meta">Cost basis of fulfilled items</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Unique SKUs Dispatched</div>
            <div class="stat-value">${uniqueSkus.size}</div>
            <div class="stat-meta">Distinct catalog lines</div>
          </div>
        `;
      }

      if (rowsData.length === 0) {
        tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; padding: 2rem; color: var(--text-muted);">No outbound stock dispatches found for selected timeframe.</td></tr>`;
        tfoot.innerHTML = '';
        return;
      }

      tbody.innerHTML = rowsData.map(r => `
        <tr>
          <td style="font-size: 0.78rem; color: var(--text-secondary);">${new Date(r.h.created_at).toLocaleString()}</td>
          <td><span class="sku-tag">${this.escapeHtml(r.h.sku)}</span></td>
          <td style="font-weight: 600;">${this.escapeHtml(r.h.item_name)}</td>
          <td><span class="badge badge-neutral">${this.escapeHtml(r.item.category || 'General')}</span></td>
          <td><span class="location-tag">${this.escapeHtml(r.h.location)}</span></td>
          <td style="text-align: right; color: var(--danger); font-weight: 700;">-${r.qty}</td>
          <td style="font-size: 0.8rem; color: var(--text-secondary);">${this.escapeHtml(r.item.uom || 'EA')}</td>
          <td style="text-align: right; font-size: 0.82rem;">$${r.unitCost.toFixed(2)}</td>
          <td style="text-align: right; font-weight: 600; color: var(--danger);">$${r.extVal.toFixed(2)}</td>
          <td style="font-weight: 500;">${this.escapeHtml(r.h.user_name)}</td>
          <td style="font-size: 0.8rem; color: var(--text-secondary); max-width: 180px;">${this.escapeHtml(r.h.notes || '-')}</td>
        </tr>
      `).join('');

      tfoot.innerHTML = `
        <tr>
          <td colspan="5">SUMMARY TOTALS (${rowsData.length} Dispatches)</td>
          <td style="text-align: right; color: var(--danger); font-weight: 700;">-${totalUnits}</td>
          <td>-</td>
          <td style="text-align: right;">-</td>
          <td style="text-align: right; color: var(--danger); font-weight: 700;">$${totalValuation.toFixed(2)}</td>
          <td colspan="2">-</td>
        </tr>
      `;
    },

    renderOnHandReport(searchTerm, categoryFilter) {
      const titleEl = document.getElementById('report-title-label');
      const countEl = document.getElementById('report-count-badge');
      const thead = document.getElementById('report-table-head');
      const tbody = document.getElementById('report-table-body');
      const tfoot = document.getElementById('report-table-foot');
      const kpiContainer = document.getElementById('report-kpi-cards');

      if (titleEl) titleEl.textContent = 'On-Hand Inventory Report';

      thead.innerHTML = `
        <tr>
          <th>SKU</th>
          <th>Item Name</th>
          <th>Category</th>
          <th>Location</th>
          <th style="text-align: right;">Qty On Hand</th>
          <th>UOM</th>
          <th style="text-align: right;">Safety Point</th>
          <th style="text-align: right;">Unit Cost</th>
          <th style="text-align: right;">Extended Value</th>
          <th>Status</th>
        </tr>
      `;

      const rows = this.inventory.map(inv => {
        const item = this.items.find(i => i.id === inv.item_id) || {};
        const qty = Number(inv.quantity || 0);
        const unitCost = Number(item.unit_cost || 0);
        const extVal = qty * unitCost;
        const reorderPoint = Number(item.reorder_point || 0);

        let status = inv.status;
        if (!status) {
          if (qty === 0) status = 'Out of Stock';
          else if (qty <= reorderPoint) status = 'Low Stock';
          else status = 'In Stock';
        }

        return {
          inv,
          item,
          qty,
          unitCost,
          extVal,
          reorderPoint,
          status
        };
      }).filter(r => {
        const matchesCategory = categoryFilter === 'ALL' || (r.item.category || 'General') === categoryFilter;
        const matchesSearch = !searchTerm ||
          (r.item.sku && r.item.sku.toLowerCase().includes(searchTerm)) ||
          (r.item.name && r.item.name.toLowerCase().includes(searchTerm)) ||
          (r.inv.location && r.inv.location.toLowerCase().includes(searchTerm)) ||
          (r.status && r.status.toLowerCase().includes(searchTerm));
        return matchesCategory && matchesSearch;
      });

      let totalUnits = 0;
      let totalValuation = 0;
      let lowStockCount = 0;

      rows.forEach(r => {
        totalUnits += r.qty;
        totalValuation += r.extVal;
        if (r.status === 'Low Stock' || r.status === 'Out of Stock') {
          lowStockCount++;
        }
      });

      if (countEl) countEl.textContent = `${rows.length} records`;

      if (kpiContainer) {
        kpiContainer.innerHTML = `
          <div class="stat-card">
            <div class="stat-label">Total Inventory Placements</div>
            <div class="stat-value">${rows.length}</div>
            <div class="stat-meta">Active location lines</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Units On-Hand</div>
            <div class="stat-value" style="color: var(--success);">${totalUnits}</div>
            <div class="stat-meta">Physical units across warehouse</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Valuation</div>
            <div class="stat-value" style="color: var(--accent);">$${totalValuation.toFixed(2)}</div>
            <div class="stat-meta">Total inventory asset worth</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Low Stock / Reorder Alerts</div>
            <div class="stat-value" style="color: ${lowStockCount > 0 ? 'var(--danger)' : 'var(--success)'};">${lowStockCount}</div>
            <div class="stat-meta">Locations at or below reorder threshold</div>
          </div>
        `;
      }

      if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; padding: 2rem; color: var(--text-muted);">No on-hand inventory matching criteria.</td></tr>`;
        tfoot.innerHTML = '';
        return;
      }

      tbody.innerHTML = rows.map(r => {
        const badgeClass = r.status === 'In Stock' ? 'badge-success' : r.status === 'Low Stock' ? 'badge-warning' : 'badge-danger';
        return `
          <tr>
            <td><span class="sku-tag">${this.escapeHtml(r.item.sku || '-')}</span></td>
            <td style="font-weight: 600;">${this.escapeHtml(r.item.name || 'Unknown Item')}</td>
            <td><span class="badge badge-neutral">${this.escapeHtml(r.item.category || 'General')}</span></td>
            <td><span class="location-tag">${this.escapeHtml(r.inv.location)}</span></td>
            <td style="text-align: right; font-weight: 700;">${r.qty}</td>
            <td style="font-size: 0.8rem; color: var(--text-secondary);">${this.escapeHtml(r.item.uom || 'EA')}</td>
            <td style="text-align: right; font-size: 0.82rem; color: var(--text-secondary);">${r.reorderPoint}</td>
            <td style="text-align: right; font-size: 0.82rem;">$${r.unitCost.toFixed(2)}</td>
            <td style="text-align: right; font-weight: 600; color: var(--accent);">$${r.extVal.toFixed(2)}</td>
            <td><span class="badge ${badgeClass}">${this.escapeHtml(r.status)}</span></td>
          </tr>
        `;
      }).join('');

      tfoot.innerHTML = `
        <tr>
          <td colspan="4">TOTAL VALUATION SUMMARY (${rows.length} Placement Lines)</td>
          <td style="text-align: right; font-weight: 700;">${totalUnits}</td>
          <td>-</td>
          <td>-</td>
          <td style="text-align: right;">-</td>
          <td style="text-align: right; color: var(--accent); font-weight: 700;">$${totalValuation.toFixed(2)}</td>
          <td>-</td>
        </tr>
      `;
    },

    renderMovementDetailReport(filteredHistory, searchTerm, categoryFilter, actionFilter) {
      const titleEl = document.getElementById('report-title-label');
      const countEl = document.getElementById('report-count-badge');
      const thead = document.getElementById('report-table-head');
      const tbody = document.getElementById('report-table-body');
      const tfoot = document.getElementById('report-table-foot');
      const kpiContainer = document.getElementById('report-kpi-cards');

      if (titleEl) titleEl.textContent = 'Movement Detail (Audit History) Report';

      thead.innerHTML = `
        <tr>
          <th>Date & Time</th>
          <th>Action</th>
          <th>SKU</th>
          <th>Item Name</th>
          <th>Location</th>
          <th style="text-align: right;">Qty Delta</th>
          <th style="text-align: right;">Prev Qty</th>
          <th style="text-align: right;">New Qty</th>
          <th>Operator</th>
          <th>Reference / Notes</th>
        </tr>
      `;

      const rows = filteredHistory.filter(h => {
        const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
        const matchesCategory = categoryFilter === 'ALL' || (item.category || 'General') === categoryFilter;
        const matchesAction = actionFilter === 'ALL' || h.action_type === actionFilter;
        const matchesSearch = !searchTerm ||
          (h.sku && h.sku.toLowerCase().includes(searchTerm)) ||
          (h.item_name && h.item_name.toLowerCase().includes(searchTerm)) ||
          (h.location && h.location.toLowerCase().includes(searchTerm)) ||
          (h.user_name && h.user_name.toLowerCase().includes(searchTerm)) ||
          (h.notes && h.notes.toLowerCase().includes(searchTerm));

        return matchesCategory && matchesAction && matchesSearch;
      });

      let addCount = 0;
      let subCount = 0;
      let otherCount = 0;
      let netDelta = 0;

      rows.forEach(h => {
        const change = Number(h.qty_change) || 0;
        netDelta += change;
        if (h.action_type === 'ADD') addCount++;
        else if (h.action_type === 'SUBTRACT') subCount++;
        else otherCount++;
      });

      if (countEl) countEl.textContent = `${rows.length} events`;

      if (kpiContainer) {
        kpiContainer.innerHTML = `
          <div class="stat-card">
            <div class="stat-label">Total Logged Events</div>
            <div class="stat-value">${rows.length}</div>
            <div class="stat-meta">Audit ledger entries</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Inbound Additions</div>
            <div class="stat-value" style="color: var(--success);">+${addCount}</div>
            <div class="stat-meta">Intake transactions</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Outbound Dispatches</div>
            <div class="stat-value" style="color: var(--danger);">-${subCount}</div>
            <div class="stat-meta">Dispatched / picked events</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Adjustments & Transfers</div>
            <div class="stat-value" style="color: var(--warning);">${otherCount}</div>
            <div class="stat-meta">Audits and bin relocations</div>
          </div>
        `;
      }

      if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; padding: 2rem; color: var(--text-muted);">No audit log events match current criteria.</td></tr>`;
        tfoot.innerHTML = '';
        return;
      }

      tbody.innerHTML = rows.map(h => {
        const isAdd = h.action_type === 'ADD';
        const isSub = h.action_type === 'SUBTRACT';
        const badgeClass = isAdd ? 'badge-success' : isSub ? 'badge-danger' : 'badge-info';

        return `
          <tr>
            <td style="font-size: 0.78rem; color: var(--text-secondary);">${new Date(h.created_at).toLocaleString()}</td>
            <td><span class="badge ${badgeClass}">${this.escapeHtml(h.action_type)}</span></td>
            <td><span class="sku-tag">${this.escapeHtml(h.sku)}</span></td>
            <td style="font-weight: 600;">${this.escapeHtml(h.item_name)}</td>
            <td><span class="location-tag">${this.escapeHtml(h.location)}</span></td>
            <td style="text-align: right; font-weight: 700; color: ${isAdd ? 'var(--success)' : isSub ? 'var(--danger)' : 'var(--text-primary)'};">
              ${isAdd ? '+' : ''}${h.qty_change}
            </td>
            <td style="text-align: right; color: var(--text-secondary);">${h.previous_qty}</td>
            <td style="text-align: right; font-weight: 600;">${h.new_qty}</td>
            <td style="font-weight: 500;">${this.escapeHtml(h.user_name)}</td>
            <td style="font-size: 0.8rem; color: var(--text-secondary); max-width: 200px;">${this.escapeHtml(h.notes || '-')}</td>
          </tr>
        `;
      }).join('');

      tfoot.innerHTML = `
        <tr>
          <td colspan="5">AUDIT LOG TOTALS (${rows.length} Logged Entries)</td>
          <td style="text-align: right; font-weight: 700; color: ${netDelta >= 0 ? 'var(--success)' : 'var(--danger)'};">${netDelta >= 0 ? '+' : ''}${netDelta}</td>
          <td colspan="4">-</td>
        </tr>
      `;
    },

    exportCurrentReport() {
      const type = this.currentReportType || 'movement-summary';
      const searchTerm = (document.getElementById('report-search-input')?.value || '').toLowerCase().trim();
      const categoryFilter = document.getElementById('report-category-filter')?.value || 'ALL';
      const actionFilter = document.getElementById('report-action-filter')?.value || 'ALL';
      const filteredHistory = this.getFilteredHistoryForReports();
      const todayStr = new Date().toISOString().split('T')[0];

      let exportData = [];
      let filename = `Simpletory_Report_${todayStr}.csv`;

      if (type === 'movement-summary') {
        filename = `Simpletory_Stock_Movement_Report_${todayStr}.csv`;
        const itemsList = this.items.filter(item => {
          const matchesCategory = categoryFilter === 'ALL' || (item.category || 'General') === categoryFilter;
          const matchesSearch = !searchTerm ||
            (item.sku && item.sku.toLowerCase().includes(searchTerm)) ||
            (item.name && item.name.toLowerCase().includes(searchTerm)) ||
            (item.category && item.category.toLowerCase().includes(searchTerm));
          return matchesCategory && matchesSearch;
        });

        exportData = itemsList.map(item => {
          const itemHistory = filteredHistory.filter(h => h.sku === item.sku || h.item_name === item.name);
          let inbound = 0;
          let outbound = 0;
          let adjust = 0;

          itemHistory.forEach(h => {
            const qty = Math.abs(Number(h.qty_change) || 0);
            if (h.action_type === 'ADD' || (h.qty_change > 0 && h.action_type !== 'ADJUST')) {
              inbound += qty;
            } else if (h.action_type === 'SUBTRACT' || (h.qty_change < 0 && h.action_type !== 'ADJUST')) {
              outbound += qty;
            } else if (h.action_type === 'ADJUST') {
              adjust += Number(h.qty_change) || 0;
            }
          });

          const net = inbound - outbound + adjust;
          const onHand = this.inventory
            .filter(inv => inv.item_id === item.id)
            .reduce((sum, inv) => sum + Number(inv.quantity || 0), 0);
          const unitCost = Number(item.unit_cost || 0);
          const netValue = (net * unitCost).toFixed(2);

          return {
            'SKU': item.sku || '',
            'Item Name': item.name || '',
            'Category': item.category || 'General',
            'Inbound Units (+)': inbound,
            'Outbound Units (-)': outbound,
            'Adjustment Units (±)': adjust,
            'Net Movement': net,
            'Current On-Hand': onHand,
            'UOM': item.uom || 'EA',
            'Unit Cost ($)': unitCost.toFixed(2),
            'Net Movement Value ($)': netValue,
            'Total Movements': itemHistory.length
          };
        });

      } else if (type === 'received') {
        filename = `Simpletory_Stock_Received_Report_${todayStr}.csv`;
        const receivedLogs = filteredHistory.filter(h => {
          const isReceived = h.action_type === 'ADD' || (Number(h.qty_change) > 0 && h.action_type !== 'ADJUST');
          if (!isReceived) return false;

          const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
          const matchesCategory = categoryFilter === 'ALL' || (item.category || 'General') === categoryFilter;
          const matchesSearch = !searchTerm ||
            (h.sku && h.sku.toLowerCase().includes(searchTerm)) ||
            (h.item_name && h.item_name.toLowerCase().includes(searchTerm)) ||
            (h.location && h.location.toLowerCase().includes(searchTerm)) ||
            (h.user_name && h.user_name.toLowerCase().includes(searchTerm)) ||
            (h.notes && h.notes.toLowerCase().includes(searchTerm));

          return matchesCategory && matchesSearch;
        });

        exportData = receivedLogs.map(h => {
          const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
          const qty = Math.abs(Number(h.qty_change) || 0);
          const unitCost = Number(item.unit_cost || 0);
          const extVal = (qty * unitCost).toFixed(2);

          return {
            'Date & Time': new Date(h.created_at).toLocaleString(),
            'SKU': h.sku || '',
            'Item Name': h.item_name || '',
            'Category': item.category || 'General',
            'Destination Location': h.location || '',
            'Quantity Received': qty,
            'UOM': item.uom || 'EA',
            'Unit Cost ($)': unitCost.toFixed(2),
            'Total Valuation ($)': extVal,
            'Received By': h.user_name || '',
            'PO / Notes': h.notes || ''
          };
        });

      } else if (type === 'dispatched') {
        filename = `Simpletory_Stock_Dispatched_Report_${todayStr}.csv`;
        const dispatchedLogs = filteredHistory.filter(h => {
          const isDispatched = h.action_type === 'SUBTRACT' || (Number(h.qty_change) < 0 && h.action_type !== 'ADJUST');
          if (!isDispatched) return false;

          const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
          const matchesCategory = categoryFilter === 'ALL' || (item.category || 'General') === categoryFilter;
          const matchesSearch = !searchTerm ||
            (h.sku && h.sku.toLowerCase().includes(searchTerm)) ||
            (h.item_name && h.item_name.toLowerCase().includes(searchTerm)) ||
            (h.location && h.location.toLowerCase().includes(searchTerm)) ||
            (h.user_name && h.user_name.toLowerCase().includes(searchTerm)) ||
            (h.notes && h.notes.toLowerCase().includes(searchTerm));

          return matchesCategory && matchesSearch;
        });

        exportData = dispatchedLogs.map(h => {
          const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
          const qty = Math.abs(Number(h.qty_change) || 0);
          const unitCost = Number(item.unit_cost || 0);
          const extVal = (qty * unitCost).toFixed(2);

          return {
            'Date & Time': new Date(h.created_at).toLocaleString(),
            'SKU': h.sku || '',
            'Item Name': h.item_name || '',
            'Category': item.category || 'General',
            'Source Location': h.location || '',
            'Quantity Dispatched': qty,
            'UOM': item.uom || 'EA',
            'Unit Cost ($)': unitCost.toFixed(2),
            'Total Valuation ($)': extVal,
            'Dispatched By': h.user_name || '',
            'Order / Notes': h.notes || ''
          };
        });

      } else if (type === 'on-hand') {
        filename = `Simpletory_On_Hand_Inventory_Report_${todayStr}.csv`;
        const rows = this.inventory.map(inv => {
          const item = this.items.find(i => i.id === inv.item_id) || {};
          const qty = Number(inv.quantity || 0);
          const unitCost = Number(item.unit_cost || 0);
          const extVal = (qty * unitCost).toFixed(2);
          const reorderPoint = Number(item.reorder_point || 0);

          let status = inv.status;
          if (!status) {
            if (qty === 0) status = 'Out of Stock';
            else if (qty <= reorderPoint) status = 'Low Stock';
            else status = 'In Stock';
          }

          return {
            'SKU': item.sku || '',
            'Item Name': item.name || '',
            'Category': item.category || 'General',
            'Location': inv.location || '',
            'Quantity On Hand': qty,
            'UOM': item.uom || 'EA',
            'Safety Reorder Point': reorderPoint,
            'Unit Cost ($)': unitCost.toFixed(2),
            'Extended Valuation ($)': extVal,
            'Stock Status': status
          };
        }).filter(r => {
          const matchesCategory = categoryFilter === 'ALL' || r['Category'] === categoryFilter;
          const matchesSearch = !searchTerm ||
            r['SKU'].toLowerCase().includes(searchTerm) ||
            r['Item Name'].toLowerCase().includes(searchTerm) ||
            r['Location'].toLowerCase().includes(searchTerm) ||
            r['Stock Status'].toLowerCase().includes(searchTerm);
          return matchesCategory && matchesSearch;
        });

        exportData = rows;

      } else if (type === 'audit-detail') {
        filename = `Simpletory_Movement_Detail_Report_${todayStr}.csv`;
        const rows = filteredHistory.filter(h => {
          const item = this.items.find(i => i.sku === h.sku || i.name === h.item_name) || {};
          const matchesCategory = categoryFilter === 'ALL' || (item.category || 'General') === categoryFilter;
          const matchesAction = actionFilter === 'ALL' || h.action_type === actionFilter;
          const matchesSearch = !searchTerm ||
            (h.sku && h.sku.toLowerCase().includes(searchTerm)) ||
            (h.item_name && h.item_name.toLowerCase().includes(searchTerm)) ||
            (h.location && h.location.toLowerCase().includes(searchTerm)) ||
            (h.user_name && h.user_name.toLowerCase().includes(searchTerm)) ||
            (h.notes && h.notes.toLowerCase().includes(searchTerm));

          return matchesCategory && matchesAction && matchesSearch;
        });

        exportData = rows.map(h => ({
          'Date & Time': new Date(h.created_at).toLocaleString(),
          'Action Type': h.action_type || '',
          'SKU': h.sku || '',
          'Item Name': h.item_name || '',
          'Location': h.location || '',
          'Quantity Delta': h.qty_change,
          'Previous Quantity': h.previous_qty,
          'New Quantity': h.new_qty,
          'Operator / User': h.user_name || '',
          'Reference / Notes': h.notes || ''
        }));
      }

      this.exportToCsv(exportData, filename);
    },

    // ==========================================
    // DROPDOWNS & FILTER OPTIONS POPULATOR
    // ==========================================
    populateDropdowns() {
      // Collect unique categories
      const categories = Array.from(new Set(this.items.map(i => i.category || 'General'))).sort();
      const catOptions = `<option value="">All Categories</option>` + categories.map(c => `<option value="${this.escapeAttr(c)}">${this.escapeHtml(c)}</option>`).join('');

      const invCatSelect = document.getElementById('inventory-category-filter');
      const itemCatSelect = document.getElementById('items-category-filter');
      const repCatSelect = document.getElementById('report-category-filter');
      if (invCatSelect) invCatSelect.innerHTML = catOptions;
      if (itemCatSelect) itemCatSelect.innerHTML = catOptions;
      if (repCatSelect) {
        const curVal = repCatSelect.value || 'ALL';
        repCatSelect.innerHTML = `<option value="ALL">All Categories</option>` + categories.map(c => `<option value="${this.escapeAttr(c)}">${this.escapeHtml(c)}</option>`).join('');
        if (categories.includes(curVal)) repCatSelect.value = curVal;
      }

      // Populate item selects in modals
      const itemOptions = `<option value="">-- Select Catalog Item --</option>` + this.items.map(i => `<option value="${this.escapeAttr(i.id)}">${this.escapeHtml(i.sku)} - ${this.escapeHtml(i.name)}</option>`).join('');
      
      const intakeItemSelect = document.getElementById('intake-item-select');
      const dispatchItemSelect = document.getElementById('dispatch-item-select');
      const adjustItemSelect = document.getElementById('adjust-item-select');
      const transferItemSelect = document.getElementById('transfer-item-select');

      if (intakeItemSelect) intakeItemSelect.innerHTML = itemOptions;
      if (dispatchItemSelect) dispatchItemSelect.innerHTML = itemOptions;
      if (adjustItemSelect) adjustItemSelect.innerHTML = itemOptions;
      if (transferItemSelect) transferItemSelect.innerHTML = itemOptions;
    },

    // ==========================================
    // MODALS MANAGEMENT
    // ==========================================
    bindModals() {
      // Close on backdrop or close button
      document.querySelectorAll('.modal-overlay').forEach(modal => {
        modal.addEventListener('click', (e) => {
          if (e.target === modal || e.target.closest('.btn-modal-close')) {
            this.closeModal(modal.id);
          }
        });
      });

      // Auto-sync stock limit when user selects an item in Dispatch modal
      const dispatchItemSelect = document.getElementById('dispatch-item-select');
      const dispatchLocInput = document.getElementById('dispatch-location');
      const dispatchQtyInput = document.getElementById('dispatch-qty');

      const updateDispatchMaxQty = () => {
        const itemId = dispatchItemSelect?.value;
        const loc = (dispatchLocInput?.value || '').trim().toUpperCase();
        if (!itemId) {
          if (dispatchQtyInput) dispatchQtyInput.removeAttribute('max');
          return;
        }
        const matchingInv = this.inventory.filter(i => i.item_id === itemId);
        if (matchingInv.length > 0) {
          if (dispatchLocInput && (!dispatchLocInput.value || dispatchLocInput.value === 'A-01-01')) {
            dispatchLocInput.value = matchingInv[0].location;
          }
          const activeLoc = (dispatchLocInput?.value || '').trim().toUpperCase();
          const targetRecord = matchingInv.find(i => i.location === activeLoc) || matchingInv[0];
          if (dispatchQtyInput && Number(targetRecord.quantity) > 0) {
            dispatchQtyInput.max = Number(targetRecord.quantity);
          } else if (dispatchQtyInput) {
            dispatchQtyInput.removeAttribute('max');
          }
        } else if (dispatchQtyInput) {
          dispatchQtyInput.removeAttribute('max');
        }
      };

      if (dispatchItemSelect) dispatchItemSelect.addEventListener('change', updateDispatchMaxQty);
      if (dispatchLocInput) dispatchLocInput.addEventListener('input', updateDispatchMaxQty);

      // Auto-sync stock limit when user selects an item in Transfer modal
      const transferItemSelect = document.getElementById('transfer-item-select');
      const transferFromLoc = document.getElementById('transfer-from-location');
      const transferQtyInput = document.getElementById('transfer-qty');

      const updateTransferMaxQty = () => {
        const itemId = transferItemSelect?.value;
        if (!itemId) {
          if (transferQtyInput) transferQtyInput.removeAttribute('max');
          return;
        }
        const matchingInv = this.inventory.filter(i => i.item_id === itemId);
        if (matchingInv.length > 0) {
          if (transferFromLoc && (!transferFromLoc.value || transferFromLoc.value === 'A-01-01')) {
            transferFromLoc.value = matchingInv[0].location;
          }
          const activeLoc = (transferFromLoc?.value || '').trim().toUpperCase();
          const targetRecord = matchingInv.find(i => i.location === activeLoc) || matchingInv[0];
          if (transferQtyInput && Number(targetRecord.quantity) > 0) {
            transferQtyInput.max = Number(targetRecord.quantity);
          } else if (transferQtyInput) {
            transferQtyInput.removeAttribute('max');
          }
        } else if (transferQtyInput) {
          transferQtyInput.removeAttribute('max');
        }
      };

      if (transferItemSelect) transferItemSelect.addEventListener('change', updateTransferMaxQty);
      if (transferFromLoc) transferFromLoc.addEventListener('input', updateTransferMaxQty);
    },

    openModal(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.classList.add('active');
        const firstInput = modal.querySelector('input:not([type="hidden"]), select');
        if (firstInput) setTimeout(() => firstInput.focus(), 50);
      }
    },

    closeModal(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) modal.classList.remove('active');
    },

    // Quick open modal helpers
    openQuickIntake(itemId = '', location = 'A-01-01') {
      const select = document.getElementById('intake-item-select');
      const locInput = document.getElementById('intake-location');
      const qtyInput = document.getElementById('intake-qty');
      const notesInput = document.getElementById('intake-notes');

      if (select && itemId) select.value = itemId;
      if (locInput) locInput.value = location;
      if (qtyInput) qtyInput.value = '';
      if (notesInput) notesInput.value = '';

      this.openModal('modal-intake');
    },

    openQuickDispatch(itemId = '', location = 'A-01-01', maxQty = 0) {
      const select = document.getElementById('dispatch-item-select');
      const locInput = document.getElementById('dispatch-location');
      const qtyInput = document.getElementById('dispatch-qty');
      const notesInput = document.getElementById('dispatch-notes');

      if (select && itemId) select.value = itemId;
      if (locInput) locInput.value = location;
      if (qtyInput) {
        qtyInput.value = '';
        if (Number(maxQty) > 0) {
          qtyInput.max = Number(maxQty);
        } else {
          qtyInput.removeAttribute('max');
        }
      }
      if (notesInput) notesInput.value = '';

      this.openModal('modal-dispatch');
    },

    openAdjustModal(itemId = '', location = 'A-01-01', currentQty = 0) {
      const select = document.getElementById('adjust-item-select');
      const locInput = document.getElementById('adjust-location');
      const curInput = document.getElementById('adjust-current-qty');
      const actInput = document.getElementById('adjust-actual-qty');
      const reasonInput = document.getElementById('adjust-reason');

      if (select && itemId) select.value = itemId;
      if (locInput) locInput.value = location;
      if (curInput) curInput.value = currentQty;
      if (actInput) actInput.value = currentQty;
      if (reasonInput) reasonInput.value = '';

      this.openModal('modal-adjust');
    },

    openTransferModal(itemId = '', fromLocation = 'A-01-01', maxQty = 0) {
      const select = document.getElementById('transfer-item-select');
      const fromInput = document.getElementById('transfer-from-location');
      const toInput = document.getElementById('transfer-to-location');
      const qtyInput = document.getElementById('transfer-qty');
      const notesInput = document.getElementById('transfer-notes');

      if (select && itemId) select.value = itemId;
      if (fromInput) fromInput.value = fromLocation;
      if (toInput) toInput.value = '';
      if (qtyInput) {
        qtyInput.value = '';
        if (Number(maxQty) > 0) {
          qtyInput.max = Number(maxQty);
        } else {
          qtyInput.removeAttribute('max');
        }
      }
      if (notesInput) notesInput.value = '';

      this.openModal('modal-transfer');
    },

    openNewItemModal() {
      const role = window.WMSDataService.currentUser?.role || this.currentUser?.role || 'User';
      if (role !== 'Superadmin' && role !== 'Admin' && role !== 'Manager') {
        return this.showToast('Permission Denied: Only Managers, Admins, and Superadmins can add catalog items.', 'warning');
      }

      const form = document.getElementById('form-item');
      if (form) form.reset();
      const idInput = document.getElementById('item-id');
      if (idInput) idInput.value = '';
      const title = document.getElementById('modal-item-title');
      if (title) title.textContent = 'Add New SKU to Catalog';
      this.openModal('modal-item');
    },

    openEditItemModal(itemId) {
      const role = window.WMSDataService.currentUser?.role || this.currentUser?.role || 'User';
      if (role !== 'Superadmin' && role !== 'Admin' && role !== 'Manager') {
        return this.showToast('Permission Denied: Only Managers, Admins, and Superadmins can edit catalog items.', 'warning');
      }

      const item = this.items.find(i => i.id === itemId);
      if (!item) return;

      const form = document.getElementById('form-item');
      if (form) form.reset();

      document.getElementById('item-id').value = item.id;
      document.getElementById('item-sku').value = item.sku;
      document.getElementById('item-name').value = item.name;
      document.getElementById('item-category').value = item.category || 'General';
      document.getElementById('item-subcategory').value = item.sub_category || 'Standard';
      document.getElementById('item-uom').value = item.uom || 'EA';
      document.getElementById('item-cost').value = item.unit_cost || 0;
      document.getElementById('item-reorder').value = item.reorder_point || 0;

      const title = document.getElementById('modal-item-title');
      if (title) title.textContent = `Edit SKU: ${item.sku}`;

      this.openModal('modal-item');
    },

    openNewUserModal() {
      const currentUser = window.WMSDataService.currentUser;
      const role = currentUser?.role || 'User';
      const isSuperadmin = role === 'Superadmin';
      const isAdmin = isSuperadmin || role === 'Admin';
      const isManager = isAdmin || role === 'Manager';

      if (!isManager) {
        return this.showToast('Permission Denied: Only Managers, Admins, and Superadmins can add team members.', 'warning');
      }

      const form = document.getElementById('form-user');
      if (form) form.reset();
      document.getElementById('user-id').value = '';
      document.getElementById('modal-user-title').textContent = 'Add Team Member';

      // Dynamically configure allowed roles
      const roleSelect = document.getElementById('user-role');
      if (roleSelect) {
        if (isSuperadmin) {
          roleSelect.innerHTML = `
            <option value="User">User (Standard Inventory Staff)</option>
            <option value="Manager">Manager (Staff & Inventory Lead)</option>
            <option value="Admin">Admin (Facility Administrator)</option>
            <option value="Superadmin">Superadmin (Global Database Admin)</option>
          `;
        } else if (role === 'Admin') {
          roleSelect.innerHTML = `
            <option value="User">User (Standard Inventory Staff)</option>
            <option value="Manager">Manager (Staff & Inventory Lead)</option>
            <option value="Admin">Admin (Facility Administrator)</option>
          `;
        } else {
          // Manager can only create standard User accounts
          roleSelect.innerHTML = `
            <option value="User">User (Standard Inventory Staff)</option>
          `;
        }
        roleSelect.value = 'User';
      }

      const pwdGroup = document.getElementById('user-password-group');
      const pwdInput = document.getElementById('user-password');
      if (pwdGroup) pwdGroup.style.display = 'block';
      if (pwdInput) pwdInput.required = true;

      const tenantSelect = document.getElementById('user-tenant-select');
      if (tenantSelect) {
        const list = this.allTenants || this.tenants || [];
        tenantSelect.innerHTML = list.map(t => `<option value="${this.escapeAttr(t.id)}">${this.escapeHtml(t.name)}</option>`).join('');
        tenantSelect.value = currentUser.tenant_id || window.WMSDataService.activeTenantId;
        tenantSelect.disabled = !isSuperadmin;
      }

      this.openModal('modal-user');
    },

    openEditUserModal(userId) {
      const currentUser = window.WMSDataService.currentUser;
      const callerRole = currentUser?.role || 'User';
      const isCallerSuperadmin = callerRole === 'Superadmin';
      const isCallerAdmin = isCallerSuperadmin || callerRole === 'Admin';
      const isCallerManager = isCallerAdmin || callerRole === 'Manager';

      if (!isCallerManager) {
        return this.showToast('Permission Denied: Only Managers, Admins, and Superadmins can edit team members.', 'warning');
      }

      const user = this.users.find(u => u.id === userId);
      if (!user) return;

      // Scope guard:
      if (callerRole === 'Manager' && (user.role !== 'User' || user.tenant_id !== currentUser?.tenant_id)) {
        return this.showToast('Permission Denied: Managers can only edit standard Users in their assigned facility.', 'warning');
      }
      if (callerRole === 'Admin' && (user.role === 'Superadmin' || user.tenant_id !== currentUser?.tenant_id)) {
        return this.showToast('Permission Denied: Admins cannot edit Superadmin accounts or users outside their assigned facility.', 'warning');
      }

      document.getElementById('user-id').value = user.id;
      document.getElementById('user-fullname').value = user.full_name || '';
      document.getElementById('user-username').value = user.username || '';
      document.getElementById('user-email').value = user.email || '';

      // Dynamically configure allowed roles
      const roleSelect = document.getElementById('user-role');
      if (roleSelect) {
        if (isCallerSuperadmin) {
          roleSelect.innerHTML = `
            <option value="User">User (Standard Inventory Staff)</option>
            <option value="Manager">Manager (Staff & Inventory Lead)</option>
            <option value="Admin">Admin (Facility Administrator)</option>
            <option value="Superadmin">Superadmin (Global Database Admin)</option>
          `;
        } else if (callerRole === 'Admin') {
          roleSelect.innerHTML = `
            <option value="User">User (Standard Inventory Staff)</option>
            <option value="Manager">Manager (Staff & Inventory Lead)</option>
            <option value="Admin">Admin (Facility Administrator)</option>
          `;
        } else {
          roleSelect.innerHTML = `
            <option value="User">User (Standard Inventory Staff)</option>
          `;
        }
        roleSelect.value = user.role || 'User';
      }

      const pwdGroup = document.getElementById('user-password-group');
      const pwdInput = document.getElementById('user-password');
      if (pwdGroup) pwdGroup.style.display = 'none';
      if (pwdInput) pwdInput.required = false;

      const tenantSelect = document.getElementById('user-tenant-select');
      if (tenantSelect) {
        const list = this.allTenants || this.tenants || [];
        tenantSelect.innerHTML = list.map(t => `<option value="${this.escapeAttr(t.id)}">${this.escapeHtml(t.name)}</option>`).join('');
        tenantSelect.value = user.tenant_id || window.WMSDataService.activeTenantId;
        tenantSelect.disabled = !isCallerSuperadmin;
      }

      document.getElementById('modal-user-title').textContent = `Edit Member: ${user.full_name}`;
      this.openModal('modal-user');
    },

    // ==========================================
    // FORMS SUBMISSION HANDLERS
    // ==========================================
    bindForms() {
      // 1. Catalog Item Form
      const formItem = document.getElementById('form-item');
      if (formItem) {
        formItem.addEventListener('submit', async (e) => {
          e.preventDefault();
          const submitBtn = formItem.querySelector('button[type="submit"]');
          const originalBtnHtml = submitBtn ? submitBtn.innerHTML : '';
          if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span>Saving Item...</span>';
          }
          try {
            const itemData = {
              id: document.getElementById('item-id').value || undefined,
              sku: document.getElementById('item-sku').value.trim().toUpperCase(),
              name: document.getElementById('item-name').value.trim(),
              category: document.getElementById('item-category').value.trim() || 'General',
              sub_category: document.getElementById('item-subcategory').value.trim() || 'Standard',
              uom: document.getElementById('item-uom').value.trim() || 'EA',
              unit_cost: parseFloat(document.getElementById('item-cost').value) || 0,
              reorder_point: parseFloat(document.getElementById('item-reorder').value) || 0
            };

            await window.WMSDataService.upsertItem(itemData);
            this.closeModal('modal-item');
            this.showToast(`Saved SKU: ${itemData.sku}`, 'success');
            await this.refreshAllData();
          } catch (err) {
            this.showToast(`Error saving item: ${err.message}`, 'danger');
          } finally {
            if (submitBtn) {
              submitBtn.disabled = false;
              submitBtn.innerHTML = originalBtnHtml;
            }
          }
        });
      }

      // 2. Stock Intake Form
      const formIntake = document.getElementById('form-intake');
      if (formIntake) {
        formIntake.addEventListener('submit', async (e) => {
          e.preventDefault();
          const submitBtn = formIntake.querySelector('button[type="submit"]');
          const originalBtnHtml = submitBtn ? submitBtn.innerHTML : '';
          try {
            const itemId = document.getElementById('intake-item-select').value;
            const location = document.getElementById('intake-location').value.trim().toUpperCase();
            const qty = parseFloat(document.getElementById('intake-qty').value);
            const notes = document.getElementById('intake-notes').value.trim();

            if (!itemId || !location || isNaN(qty) || qty <= 0) {
              return this.showToast('Please specify item, location, and a valid quantity.', 'warning');
            }

            if (submitBtn) {
              submitBtn.disabled = true;
              submitBtn.innerHTML = '<span>Processing Intake...</span>';
            }

            await window.WMSDataService.executeStockMovement({
              itemId,
              location,
              actionType: 'ADD',
              quantityChange: qty,
              notes: notes || 'Stock intake receipt'
            });

            this.closeModal('modal-intake');
            this.showToast(`Received +${qty} units into ${location}`, 'success');
            await this.refreshAllData();
          } catch (err) {
            this.showToast(`Intake error: ${err.message}`, 'danger');
          } finally {
            if (submitBtn) {
              submitBtn.disabled = false;
              submitBtn.innerHTML = originalBtnHtml;
            }
          }
        });
      }

      // 3. Stock Dispatch Form
      const formDispatch = document.getElementById('form-dispatch');
      if (formDispatch) {
        formDispatch.addEventListener('submit', async (e) => {
          e.preventDefault();
          const submitBtn = formDispatch.querySelector('button[type="submit"]');
          const originalBtnHtml = submitBtn ? submitBtn.innerHTML : '';
          try {
            const itemId = document.getElementById('dispatch-item-select').value;
            const location = document.getElementById('dispatch-location').value.trim().toUpperCase();
            const qty = parseFloat(document.getElementById('dispatch-qty').value);
            const notes = document.getElementById('dispatch-notes').value.trim();

            if (!itemId || !location || isNaN(qty) || qty <= 0) {
              return this.showToast('Please specify item, location, and a valid quantity.', 'warning');
            }

            if (submitBtn) {
              submitBtn.disabled = true;
              submitBtn.innerHTML = '<span>Processing Dispatch...</span>';
            }

            await window.WMSDataService.executeStockMovement({
              itemId,
              location,
              actionType: 'SUBTRACT',
              quantityChange: qty,
              notes: notes || 'Stock pick / dispatch order'
            });

            this.closeModal('modal-dispatch');
            this.showToast(`Dispatched -${qty} units from ${location}`, 'success');
            await this.refreshAllData();
          } catch (err) {
            this.showToast(`Dispatch error: ${err.message}`, 'danger');
          } finally {
            if (submitBtn) {
              submitBtn.disabled = false;
              submitBtn.innerHTML = originalBtnHtml;
            }
          }
        });
      }

      // 4. Stock Adjust Form
      const formAdjust = document.getElementById('form-adjust');
      if (formAdjust) {
        formAdjust.addEventListener('submit', async (e) => {
          e.preventDefault();
          const submitBtn = formAdjust.querySelector('button[type="submit"]');
          const originalBtnHtml = submitBtn ? submitBtn.innerHTML : '';
          try {
            const itemId = document.getElementById('adjust-item-select').value;
            const location = document.getElementById('adjust-location').value.trim().toUpperCase();
            const actualQty = parseFloat(document.getElementById('adjust-actual-qty').value);
            const reason = document.getElementById('adjust-reason').value.trim();

            if (!itemId || !location || isNaN(actualQty) || actualQty < 0) {
              return this.showToast('Please provide valid count values.', 'warning');
            }

            if (submitBtn) {
              submitBtn.disabled = true;
              submitBtn.innerHTML = '<span>Adjusting Stock...</span>';
            }

            await window.WMSDataService.executeStockMovement({
              itemId,
              location,
              actionType: 'ADJUST',
              quantityChange: actualQty,
              notes: `Cycle count reconciliation: ${reason || 'Physical audit'}`
            });

            this.closeModal('modal-adjust');
            this.showToast(`Adjusted stock count at ${location} to ${actualQty}`, 'success');
            await this.refreshAllData();
          } catch (err) {
            this.showToast(`Adjustment error: ${err.message}`, 'danger');
          } finally {
            if (submitBtn) {
              submitBtn.disabled = false;
              submitBtn.innerHTML = originalBtnHtml;
            }
          }
        });
      }

      // 5. Stock Transfer Form
      const formTransfer = document.getElementById('form-transfer');
      if (formTransfer) {
        formTransfer.addEventListener('submit', async (e) => {
          e.preventDefault();
          const submitBtn = formTransfer.querySelector('button[type="submit"]');
          const originalBtnHtml = submitBtn ? submitBtn.innerHTML : '';
          try {
            const itemId = document.getElementById('transfer-item-select').value;
            const fromLocation = document.getElementById('transfer-from-location').value.trim().toUpperCase();
            const toLocation = document.getElementById('transfer-to-location').value.trim().toUpperCase();
            const qty = parseFloat(document.getElementById('transfer-qty').value);
            const notes = document.getElementById('transfer-notes').value.trim();

            if (!itemId || !fromLocation || !toLocation || isNaN(qty) || qty <= 0) {
              return this.showToast('Please complete all transfer fields.', 'warning');
            }

            if (submitBtn) {
              submitBtn.disabled = true;
              submitBtn.innerHTML = '<span>Transferring...</span>';
            }

            await window.WMSDataService.transferStock({
              itemId,
              fromLocation,
              toLocation,
              quantity: qty,
              notes: notes || 'Inter-bay transfer'
            });

            this.closeModal('modal-transfer');
            this.showToast(`Transferred ${qty} units: ${fromLocation} ➔ ${toLocation}`, 'success');
            await this.refreshAllData();
          } catch (err) {
            this.showToast(`Transfer error: ${err.message}`, 'danger');
          } finally {
            if (submitBtn) {
              submitBtn.disabled = false;
              submitBtn.innerHTML = originalBtnHtml;
            }
          }
        });
      }

      // 6. User Management Form
      const formUser = document.getElementById('form-user');
      if (formUser) {
        formUser.addEventListener('submit', async (e) => {
          e.preventDefault();
          const submitBtn = formUser.querySelector('button[type="submit"]');
          const originalBtnHtml = submitBtn ? submitBtn.innerHTML : '';
          try {
            const userId = document.getElementById('user-id').value;
            const fullName = document.getElementById('user-fullname').value.trim();
            const username = document.getElementById('user-username').value.trim().toLowerCase();
            const email = document.getElementById('user-email').value.trim();
            const tenantId = document.getElementById('user-tenant-select')?.value || window.WMSDataService.activeTenantId;
            const role = document.getElementById('user-role').value;
            const password = document.getElementById('user-password')?.value;

            if (userId) {
              if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span>Updating Member...</span>';
              }
              await window.WMSDataService.updateUser(userId, {
                full_name: fullName,
                username: username,
                email: email,
                tenant_id: tenantId,
                role: role
              });
              this.showToast(`Updated member: ${fullName}`, 'success');
            } else {
              if (!password || password.length < 6) {
                return this.showToast('Please enter a password of at least 6 characters.', 'warning');
              }
              if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span>Adding Member...</span>';
              }
              await window.WMSDataService.createUser({
                username,
                email,
                password,
                fullName,
                role,
                tenantId
              });
              this.showToast(`Added team member: ${fullName}`, 'success');
            }

            this.closeModal('modal-user');
            await this.refreshAllData();
          } catch (err) {
            this.showToast(`Error saving member: ${err.message}`, 'danger');
          } finally {
            if (submitBtn) {
              submitBtn.disabled = false;
              submitBtn.innerHTML = originalBtnHtml;
            }
          }
        });
      }

      // Delete User Confirmation Modal Submission
      const btnConfirmDelete = document.getElementById('btn-confirm-delete-user-submit');
      if (btnConfirmDelete) {
        btnConfirmDelete.addEventListener('click', async () => {
          const idEl = document.getElementById('delete-user-confirm-id');
          const userId = idEl ? idEl.value : '';
          if (!userId) return;

          btnConfirmDelete.disabled = true;
          btnConfirmDelete.textContent = 'Deleting...';

          try {
            await window.WMSDataService.deleteUser(userId);
            this.showToast('Team member removed successfully.', 'info');
            this.closeModal('modal-confirm-delete-user');
            await this.refreshAllData();
          } catch (err) {
            console.error('Failed to delete user:', err);
            this.showToast(`Error removing member: ${err.message}`, 'danger');
          } finally {
            btnConfirmDelete.disabled = false;
            btnConfirmDelete.textContent = 'Delete Member';
          }
        });
      }

      // 7. Supabase Settings Form
      const btnSaveSupabase = document.getElementById('btn-save-supabase');
      if (btnSaveSupabase) {
        btnSaveSupabase.addEventListener('click', async () => {
          const role = window.WMSDataService.currentUser?.role || this.currentUser?.role;
          if (role !== 'Superadmin') {
            return this.showToast('Superadmin access required to configure database credentials.', 'danger');
          }
          const url = document.getElementById('setting-supabase-url').value;
          const key = document.getElementById('setting-supabase-key').value;
          const res = window.WMSDataService.saveConfig(url, key);
          if (res.success) {
            this.showToast('Testing database connection...', 'info');
            const testRes = await window.WMSDataService.testConnection();
            if (testRes.success) {
              this.showToast('Connected to live database successfully!', 'success');
            } else {
              this.showToast(`Saved, but ${testRes.message}`, 'warning');
            }
            this.updateSyncIndicator();
            this.refreshAllData();
          } else {
            this.showToast(`Failed: ${res.error}`, 'danger');
          }
        });
      }

      const btnTestSupabase = document.getElementById('btn-test-supabase');
      if (btnTestSupabase) {
        btnTestSupabase.addEventListener('click', async () => {
          const testRes = await window.WMSDataService.testConnection();
          if (testRes.success) {
            this.showToast(testRes.message, 'success');
          } else {
            this.showToast(testRes.message, 'danger');
          }
        });
      }

      // 8. Demo Reset Button
      const btnResetDemo = document.getElementById('btn-reset-demo-data');
      if (btnResetDemo) {
        btnResetDemo.addEventListener('click', () => {
          if (confirm('Are you sure you want to reset all demo inventory data to factory defaults?')) {
            window.WMSDataService.resetLocalSeed();
            this.showToast('Demo data restored to initial state.', 'info');
            this.refreshAllData();
          }
        });
      }

      // 9. Facility / Tenant Management Form
      const btnAddFacility = document.getElementById('btn-add-facility');
      if (btnAddFacility) {
        btnAddFacility.addEventListener('click', () => {
          const form = document.getElementById('form-facility');
          if (form) form.reset();
          this.openModal('modal-facility');
        });
      }

      const formFacility = document.getElementById('form-facility');
      if (formFacility) {
        formFacility.addEventListener('submit', async (e) => {
          e.preventDefault();
          const submitBtn = formFacility.querySelector('button[type="submit"]');
          const originalBtnHtml = submitBtn ? submitBtn.innerHTML : '';
          try {
            const name = document.getElementById('facility-name').value.trim();
            const id = document.getElementById('facility-id').value.trim().toLowerCase();
            const isActive = document.getElementById('facility-active').checked;

            if (!name || !id) {
              return this.showToast('Please provide both a name and an ID code.', 'warning');
            }

            if (submitBtn) {
              submitBtn.disabled = true;
              submitBtn.innerHTML = '<span>Creating Facility...</span>';
            }

            await window.WMSDataService.upsertTenant({ id, name, is_active: isActive });
            this.closeModal('modal-facility');
            this.showToast(`Facility ${name} registered successfully!`, 'success');
            await this.loadTenants();
            await this.refreshAllData();
          } catch (err) {
            this.showToast(`Error creating facility: ${err.message}`, 'danger');
          } finally {
            if (submitBtn) {
              submitBtn.disabled = false;
              submitBtn.innerHTML = originalBtnHtml;
            }
          }
        });
      }

      // 10. User Self-Service Profile & Password Update Form
      const formProfile = document.getElementById('form-profile');
      if (formProfile) {
        formProfile.addEventListener('submit', async (e) => {
          e.preventDefault();
          const userId = document.getElementById('profile-user-id').value;
          const fullName = document.getElementById('profile-fullname').value.trim();
          const email = document.getElementById('profile-email').value.trim();
          const currentPassword = document.getElementById('profile-current-password').value;
          const password = document.getElementById('profile-password').value;
          const passwordConfirm = document.getElementById('profile-password-confirm').value;
          const alertEl = document.getElementById('profile-error-alert');
          const saveBtn = document.getElementById('btn-save-profile');

          if (alertEl) alertEl.style.display = 'none';

          if (!fullName || !email) {
            if (alertEl) {
              alertEl.textContent = 'Please fill out your full name and email address.';
              alertEl.style.display = 'block';
            }
            return;
          }

          if (password) {
            if (!currentPassword || !currentPassword.trim()) {
              if (alertEl) {
                alertEl.textContent = 'Please enter your current password to authorize setting a new password.';
                alertEl.style.display = 'block';
              }
              return;
            }
            if (password.length < 6) {
              if (alertEl) {
                alertEl.textContent = 'New password must be at least 6 characters long.';
                alertEl.style.display = 'block';
              }
              return;
            }
            if (password !== passwordConfirm) {
              if (alertEl) {
                alertEl.textContent = 'Passwords do not match. Please verify your confirmation password.';
                alertEl.style.display = 'block';
              }
              return;
            }
          }

          if (saveBtn) {
            saveBtn.disabled = true;
            saveBtn.textContent = 'Saving Changes...';
          }

          try {
            await window.WMSDataService.updateUserProfile(userId, {
              fullName,
              email,
              currentPassword: currentPassword || undefined,
              password: password || undefined
            });

            this.closeModal('modal-profile');
            this.showToast('Your profile and account settings have been updated!', 'success');
            this.applyRolePermissions();
            await this.refreshAllData();
          } catch (err) {
            if (alertEl) {
              alertEl.textContent = `Update error: ${err.message}`;
              alertEl.style.display = 'block';
            }
            this.showToast(`Error updating profile: ${err.message}`, 'danger');
          } finally {
            if (saveBtn) {
              saveBtn.disabled = false;
              saveBtn.textContent = 'Save Changes';
            }
          }
        });
      }
    },

    // ==========================================
    // GLOBAL ACTIONS & SEARCH SHORTCUTS
    // ==========================================
    bindGlobalActions() {
      // Global Search
      const searchInput = document.getElementById('global-search-input');
      if (searchInput) {
        searchInput.addEventListener('input', (e) => {
          const val = e.target.value;
          const invSearch = document.getElementById('inventory-search-input');
          const itemSearch = document.getElementById('items-search-input');
          const histSearch = document.getElementById('history-search-input');

          if (invSearch) invSearch.value = val;
          if (itemSearch) itemSearch.value = val;
          if (histSearch) histSearch.value = val;

          this.renderInventoryTable();
          this.renderItemsTable();
          this.renderHistoryTable();
        });
      }

      // Filter Inputs Live Handlers
      ['inventory-search-input', 'inventory-category-filter', 'inventory-status-filter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', () => this.renderInventoryTable());
      });

      ['items-search-input', 'items-category-filter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', () => this.renderItemsTable());
      });

      ['history-search-input', 'history-action-filter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', () => this.renderHistoryTable());
      });

      // Export Buttons
      const btnExportInv = document.getElementById('btn-export-inventory');
      if (btnExportInv) {
        btnExportInv.addEventListener('click', () => {
          this.exportToCsv(this.inventory.map(inv => {
            const item = this.items.find(i => i.id === inv.item_id) || {};
            const extVal = (Number(inv.quantity) * Number(item.unit_cost || 0)).toFixed(2);
            return {
              SKU: item.sku || '',
              ItemName: item.name || '',
              Category: item.category || '',
              SubCategory: item.sub_category || '',
              Location: inv.location,
              Quantity: inv.quantity,
              UOM: item.uom || 'EA',
              UnitCost: item.unit_cost || 0,
              ExtendedValue: extVal,
              Status: inv.status
            };
          }), 'simpletory_inventory_export.csv');
        });
      }

      const btnExportItems = document.getElementById('btn-export-items');
      if (btnExportItems) {
        btnExportItems.addEventListener('click', () => {
          this.exportToCsv(this.items, 'simpletory_catalog_export.csv');
        });
      }

      const btnExportHist = document.getElementById('btn-export-history');
      if (btnExportHist) {
        btnExportHist.addEventListener('click', () => {
          this.exportToCsv(this.history, 'simpletory_history_export.csv');
        });
      }

      // Header Theme Toggle
      const themeBtn = document.getElementById('btn-toggle-theme');
      if (themeBtn) {
        themeBtn.addEventListener('click', () => this.toggleTheme());
      }
    },

    bindShortcuts() {
      window.addEventListener('keydown', (e) => {
        // Ignore shortcuts if in modal or form input
        if (['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
          if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
          }
          return;
        }

        if (e.key === '/') {
          e.preventDefault();
          const search = document.getElementById('global-search-input');
          if (search) search.focus();
        } else if (e.key.toLowerCase() === 'i' && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          this.openQuickIntake();
        } else if (e.key.toLowerCase() === 'd' && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          this.switchView('dashboard');
        } else if (e.key.toLowerCase() === 'c' && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          this.switchView('items');
        } else if (e.key.toLowerCase() === 'h' && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          this.switchView('history');
        } else if (e.key.toLowerCase() === 's' && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          this.switchView('settings');
        } else if (e.key.toLowerCase() === 'u' && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          this.switchView('users');
        } else if (e.key.toLowerCase() === 'r' && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          this.switchView('reports');
        } else if ((e.key === '?' || e.key === 'F1') && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          this.switchView('help');
        }
      });
    },

    bindHelpCenter() {
      const searchInput = document.getElementById('help-search-input');
      const pillButtons = document.querySelectorAll('.help-pill-btn');
      const guideCards = document.querySelectorAll('.help-guide-card');
      const faqHeaders = document.querySelectorAll('.faq-header');

      // 1. Live Category Filtering
      pillButtons.forEach(btn => {
        btn.addEventListener('click', () => {
          pillButtons.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          const category = btn.getAttribute('data-category');

          guideCards.forEach(card => {
            const cardCat = card.getAttribute('data-category') || '';
            if (category === 'all' || cardCat.includes(category)) {
              card.style.display = 'block';
            } else {
              card.style.display = 'none';
            }
          });
        });
      });

      // 2. Live Keyword Search
      if (searchInput) {
        searchInput.addEventListener('input', (e) => {
          const q = (e.target.value || '').toLowerCase().trim();
          guideCards.forEach(card => {
            const text = card.textContent.toLowerCase();
            const keywords = (card.getAttribute('data-keywords') || '').toLowerCase();
            if (!q || text.includes(q) || keywords.includes(q)) {
              card.style.display = 'block';
            } else {
              card.style.display = 'none';
            }
          });
        });
      }
    },

    async handleDeleteItem(itemId) {
      const role = window.WMSDataService.currentUser?.role || this.currentUser?.role || 'User';
      if (role !== 'Superadmin' && role !== 'Admin' && role !== 'Manager') {
        return this.showToast('Permission Denied: Only Admins, Managers, and Superadmins can delete catalog items.', 'warning');
      }

      const item = this.items.find(i => i.id === itemId);
      if (!item) return;
      if (confirm(`Are you sure you want to delete SKU "${item.sku}"? This will also remove associated inventory records.`)) {
        await window.WMSDataService.deleteItem(itemId);
        this.showToast(`Deleted SKU: ${item.sku}`, 'info');
        await this.refreshAllData();
      }
    },

    handleDeleteUser(userId) {
      const role = window.WMSDataService.currentUser?.role || this.currentUser?.role;
      if (role !== 'Superadmin' && role !== 'Admin' && role !== 'Manager') {
        return this.showToast('Permission Denied: Only Admins, Managers, and Superadmins can manage members.', 'warning');
      }

      const user = this.users.find(u => u.id === userId);
      if (!user) return;

      if (role === 'Manager' && user.role !== 'User') {
        return this.showToast('Managers can only delete standard User accounts.', 'warning');
      }
      if (role === 'Admin' && user.role === 'Superadmin') {
        return this.showToast('Admins cannot delete Superadmin accounts.', 'warning');
      }
      if (user.id === (window.WMSDataService.currentUser?.id || this.currentUser?.id)) {
        return this.showToast('You cannot delete your own account.', 'warning');
      }

      const nameEl = document.getElementById('delete-user-confirm-name');
      const idEl = document.getElementById('delete-user-confirm-id');
      if (nameEl) nameEl.textContent = `"${user.full_name}" (${user.username})`;
      if (idEl) idEl.value = userId;

      this.openModal('modal-confirm-delete-user');
    },

    // ==========================================
    // UTILITIES: TOASTS, CSV
    // ==========================================
    showToast(message, type = 'info') {
      const container = document.getElementById('toast-container');
      if (!container) return;

      const toast = document.createElement('div');
      toast.className = `toast toast-${type}`;
      toast.innerHTML = `
        <div style="flex:1;">${message}</div>
        <button style="background:none; border:none; color:inherit; cursor:pointer; font-size:1rem;">×</button>
      `;

      toast.querySelector('button').addEventListener('click', () => toast.remove());
      container.appendChild(toast);

      setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
      }, 3500);
    },

    exportToCsv(dataArray, filename) {
      if (!dataArray || dataArray.length === 0) {
        return this.showToast('No data available to export.', 'warning');
      }
      const headers = Object.keys(dataArray[0]);
      const csvRows = [
        headers.map(h => `"${String(h).replace(/"/g, '""')}"`).join(','),
        ...dataArray.map(row => headers.map(fieldName => {
          let val = row[fieldName] ?? '';
          val = String(val).replace(/"/g, '""');
          return `"${val}"`;
        }).join(','))
      ];
      const blob = new Blob(['\uFEFF' + csvRows.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      this.showToast(`Exported ${filename}`, 'success');
    },

    formatTimeAgo(isoString) {
      if (!isoString) return 'recently';
      const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
      if (seconds < 60) return `${seconds}s ago`;
      const mins = Math.floor(seconds / 60);
      if (mins < 60) return `${mins}m ago`;
      const hrs = Math.floor(mins / 24);
      if (hrs < 24) return `${hrs}h ago`;
      return `${Math.floor(hrs / 24)}d ago`;
    }
  };

  window.App = App;
  App.init();
});
