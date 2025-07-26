/**
 * SANA Toolkit Core JavaScript
 * Consolidated functionality used across all pages
 */

// Theme Management
const themeToggle = document.getElementById('theme-toggle');
const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');

function setTheme(isDark) {
    document.documentElement.classList.toggle('dark-theme', isDark);
    themeToggle.innerHTML = `<i class="fas fa-${isDark ? 'sun' : 'moon'}"></i>`;
    localStorage.setItem('themePreference', isDark ? 'dark' : 'light');
}

// Initialize theme
const savedTheme = localStorage.getItem('themePreference');
if (savedTheme) {
    setTheme(savedTheme === 'dark');
        } else {
    setTheme(prefersDarkScheme.matches);
}

// Theme toggle event
themeToggle.addEventListener('click', () => {
    const isDark = !document.documentElement.classList.contains('dark-theme');
    setTheme(isDark);
});

// Sidebar Management
    const sidebar = document.querySelector('.sidebar');
const sidebarToggle = document.getElementById('sidebar-toggle');
const mobileSidebarToggle = document.getElementById('mobile-sidebar-toggle');

function toggleSidebar() {
    sidebar.classList.toggle('active');
    document.body.classList.toggle('sidebar-collapsed');
}

// OLD CODE - Replace this section
// Enhanced Sidebar Toggle with Animation
function toggleSidebar() {
    sidebar.classList.toggle('collapsed');
    document.body.classList.toggle('sidebar-collapsed');
    
    // Add active state to button
    const toggleBtn = document.querySelector('.sana-toggle-btn');
    if (toggleBtn) {
        toggleBtn.classList.toggle('active');
        
        // Remove active state after animation
        setTimeout(() => {
            toggleBtn.classList.remove('active');
        }, 600);
    }
    
    // Update content area
    const contentArea = document.querySelector('.content-area');
    if (sidebar.classList.contains('collapsed')) {
        contentArea.classList.add('expanded');
    } else {
        contentArea.classList.remove('expanded');
    }
    
    // Save state to localStorage
    localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
}

// Initialize sidebar state from localStorage
document.addEventListener('DOMContentLoaded', () => {
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    if (isCollapsed) {
        sidebar.classList.add('collapsed');
        document.body.classList.add('sidebar-collapsed');
        document.querySelector('.content-area')?.classList.add('expanded');
    }
});

// Event listeners
sidebarToggle.addEventListener('click', toggleSidebar);
if (mobileSidebarToggle) {
    mobileSidebarToggle.addEventListener('click', toggleSidebar);
}

// Keyboard accessibility
sidebarToggle.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleSidebar();
    }
});

// Custom Cursor
const cursor = document.querySelector('.custom-cursor');
const cursorDot = cursor.querySelector('.cursor-dot');
const cursorRing = cursor.querySelector('.cursor-ring');
const scanRing = cursor.querySelector('.scan-ring');

let cursorX = -100;
let cursorY = -100;
let cursorTargetX = -100;
let cursorTargetY = -100;
let speed = 0.2;

function updateCursor() {
    const dx = cursorTargetX - cursorX;
    const dy = cursorTargetY - cursorY;
    
    cursorX += dx * speed;
    cursorY += dy * speed;
    
    cursor.style.transform = `translate(${cursorX}px, ${cursorY}px)`;
    requestAnimationFrame(updateCursor);
}
    
    document.addEventListener('mousemove', (e) => {
    cursorTargetX = e.clientX;
    cursorTargetY = e.clientY;
});

document.addEventListener('mousedown', () => {
    cursorDot.style.transform = 'translate(-50%, -50%) scale(0.8)';
    cursorRing.style.transform = 'translate(-50%, -50%) scale(1.4)';
});

document.addEventListener('mouseup', () => {
    cursorDot.style.transform = 'translate(-50%, -50%) scale(1)';
    cursorRing.style.transform = 'translate(-50%, -50%) scale(1)';
});

// Hover effects for interactive elements
document.querySelectorAll('a, button, input, select, textarea').forEach(el => {
    el.addEventListener('mouseenter', () => {
        cursorRing.style.transform = 'translate(-50%, -50%) scale(1.5)';
        cursorRing.style.borderColor = 'var(--primary)';
    });
    
    el.addEventListener('mouseleave', () => {
        cursorRing.style.transform = 'translate(-50%, -50%) scale(1)';
        cursorRing.style.borderColor = 'var(--primary)';
    });
});

// Special hover effect for security-related elements
document.querySelectorAll('.security-status, .stats-card, .tool-card').forEach(el => {
    el.addEventListener('mouseenter', () => {
        scanRing.style.transform = 'translate(-50%, -50%) scale(1)';
        scanRing.style.opacity = '0.5';
    });
    
    el.addEventListener('mouseleave', () => {
        scanRing.style.transform = 'translate(-50%, -50%) scale(0.8)';
        scanRing.style.opacity = '0';
    });
});

// Start cursor animation
updateCursor();

// Toast Notifications System
class ToastManager {
    constructor() {
        this.container = document.querySelector('.toast-container');
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.className = 'toast-container';
            document.body.appendChild(this.container);
        }
    }
    
    show(message, type = 'info', duration = 3000) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = document.createElement('i');
        icon.className = `fas fa-${
            type === 'success' ? 'check-circle' :
            type === 'error' ? 'exclamation-circle' :
            type === 'warning' ? 'exclamation-triangle' :
            'info-circle'
        }`;
        
        const text = document.createElement('span');
        text.textContent = message;
        
        toast.appendChild(icon);
        toast.appendChild(text);
        this.container.appendChild(toast);
        
        // Trigger reflow for animation
        toast.offsetHeight;
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(100%)';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
    
    success(message, duration) {
        this.show(message, 'success', duration);
    }
    
    error(message, duration) {
        this.show(message, 'error', duration);
    }
    
    warning(message, duration) {
        this.show(message, 'warning', duration);
    }
    
    info(message, duration) {
        this.show(message, 'info', duration);
    }
}

// Initialize Toast Manager
window.toast = new ToastManager();

// Example usage:
// toast.success('Operation completed successfully');
// toast.error('An error occurred');
// toast.warning('Please check your input');
// toast.info('New update available');

// Animation Manager
class AnimationManager {
    constructor() {
        this.setupIntersectionObserver();
        this.setupParallaxEffect();
    }

    setupIntersectionObserver() {
        const options = {
            root: null,
            rootMargin: '0px',
            threshold: 0.1
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('fade-in');
                    observer.unobserve(entry.target);
                }
            });
        }, options);

        // Observe elements with animate-on-scroll class
        document.querySelectorAll('.animate-on-scroll').forEach(el => {
            observer.observe(el);
        });
    }

    setupParallaxEffect() {
        document.addEventListener('mousemove', (e) => {
            const parallaxElements = document.querySelectorAll('.parallax');
            const mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
            const mouseY = (e.clientY / window.innerHeight - 0.5) * 2;

            parallaxElements.forEach(el => {
                const speed = el.getAttribute('data-speed') || 1;
                const x = mouseX * 20 * speed;
                const y = mouseY * 20 * speed;
                el.style.transform = `translate(${x}px, ${y}px)`;
      });
    });
    }
}

// Initialize everything when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.animationManager = new AnimationManager();

    // Example usage of toast notifications
    const showExampleToasts = () => {
        toast.show('Operation completed successfully!');
        setTimeout(() => {
            toast.show('Please check your input and try again.', 'error');
        }, 1000);
        setTimeout(() => {
            toast.show('Your session will expire soon.', 'warning');
        }, 2000);
        setTimeout(() => {
            toast.show('New updates are available!');
        }, 3000);
    };

    // Uncomment to test toast notifications
    // showExampleToasts();
}); 