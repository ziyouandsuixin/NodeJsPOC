// ========== Common Utilities ==========

// Sidebar collapse functionality
export function initSidebar() {
  const sidebar = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('sidebarToggle');
  const toggleIcon = document.getElementById('toggleIcon');
  
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('collapsed');
      
      if (sidebar.classList.contains('collapsed')) {
        toggleIcon.classList.remove('bi-chevron-left');
        toggleIcon.classList.add('bi-chevron-right');
      } else {
        toggleIcon.classList.remove('bi-chevron-right');
        toggleIcon.classList.add('bi-chevron-left');
      }
    });
  }
  
  // Mobile menu
  const mobileMenuToggle = document.getElementById('mobileMenuToggle');
  if (mobileMenuToggle) {
    mobileMenuToggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
  }
}

// Global search shortcut
export function initSearchShortcut() {
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      const searchInput = document.querySelector('.search-input');
      if (searchInput) searchInput.focus();
    }
  });
}

// Collapse/Expand functionality
export function toggleSection(id) {
  const section = document.getElementById(id);
  if (!section) return;
  
  const icon = section.previousElementSibling?.querySelector('.bi-chevron-down, .bi-chevron-up');
  if (section.style.display === 'none' || section.style.display === '') {
    section.style.display = 'block';
    if (icon) {
      icon.classList.remove('bi-chevron-down');
      icon.classList.add('bi-chevron-up');
    }
  } else {
    section.style.display = 'none';
    if (icon) {
      icon.classList.remove('bi-chevron-up');
      icon.classList.add('bi-chevron-down');
    }
  }
}

// View toggle (Grid/Table)
export function initViewToggle(gridSelector, tableSelector, viewOptions) {
  const gridView = document.querySelector(viewOptions?.grid || '.view-option:first-child');
  const tableView = document.querySelector(viewOptions?.table || '.view-option:last-child');
  const dataGrid = document.querySelector(gridSelector);
  const dataTable = document.querySelector(tableSelector);
  
  if (gridView && tableView && dataGrid && dataTable) {
    gridView.addEventListener('click', () => {
      gridView.classList.add('active');
      tableView.classList.remove('active');
      dataGrid.style.display = 'grid';
      dataTable.style.display = 'none';
    });
    
    tableView.addEventListener('click', () => {
      tableView.classList.add('active');
      gridView.classList.remove('active');
      dataGrid.style.display = 'none';
      dataTable.style.display = 'block';
    });
  }
}

// Format date
export function formatDate(dateString) {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  
  if (diffMins < 60) {
    return diffMins <= 0 ? 'Just now' : `${diffMins} minutes ago`;
  } else if (diffHours < 24) {
    return `${diffHours} hours ago`;
  } else if (diffDays < 7) {
    return `${diffDays} days ago`;
  } else {
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }
}

// Show notification
export function showNotification(message, type = 'info') {
  // Create notification element
  const notification = document.createElement('div');
  notification.className = `notification-toast notification-${type}`;
  notification.innerHTML = `
    <i class="bi bi-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
    <span>${message}</span>
  `;
  
  // Add styles
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: white;
    border-left: 4px solid ${type === 'success' ? '#198754' : type === 'error' ? '#dc3545' : '#0d6efd'};
    border-radius: 8px;
    padding: 12px 20px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 9999;
    display: flex;
    align-items: center;
    gap: 12px;
    animation: slideIn 0.3s ease;
  `;
  
  document.body.appendChild(notification);
  
  // Auto-remove after 3 seconds
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => {
      document.body.removeChild(notification);
    }, 300);
  }, 3000);
}

// Add animation styles
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
  }
`;
document.head.appendChild(style);