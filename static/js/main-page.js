// Set theme immediately to prevent flash
(function() {
    const savedTheme = localStorage.getItem('theme');
    const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');
    
    if (savedTheme === 'dark' || (!savedTheme && prefersDarkScheme.matches)) {
      document.body.classList.add('dark-theme');
      // Update icon immediately if it exists
      setTimeout(() => {
        if (document.getElementById('theme-toggle')) {
          document.getElementById('theme-toggle').innerHTML = '<i class="fas fa-sun"></i>';
        }
      }, 0);
    }
  })();
  
  document.addEventListener('DOMContentLoaded', () => {
    // Custom Cursor Implementation
    initCustomCursor();
    
    // Apply theme immediately based on localStorage
    applyThemeFromPreference();
    
    // Initialize sidebar
    initSidebar();
    
    // Add mobile menu toggle
    addMobileMenuToggle();
    
    // Check screen size for responsive adjustments
    checkScreenSize();
    
    // Fetch recent scans count
    fetchRecentScansCount();
    
    // Fetch dashboard stats
    fetchDashboardStats();
    
    // Add toast notification styles
    addToastStyles();
    
    // Initialize animations
    observeElements();
    
    // Theme toggle handler
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    // Apply theme based on localStorage preference
    function applyThemeFromPreference() {
        const savedTheme = localStorage.getItem('themePreference');
        if (savedTheme === 'light') {
            document.body.classList.remove('dark-theme');
            if (themeToggle) themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        } else {
            // Default to dark theme if no preference or dark preference
            document.body.classList.add('dark-theme');
            if (themeToggle) themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        }
    }
    
    // Toggle between light and dark theme
    function toggleTheme() {
        if (document.body.classList.contains('dark-theme')) {
            document.body.classList.remove('dark-theme');
            localStorage.setItem('themePreference', 'light');
            if (themeToggle) themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        } else {
            document.body.classList.add('dark-theme');
            localStorage.setItem('themePreference', 'dark');
            if (themeToggle) themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        }
    }
    
    function initCustomCursor() {
        const cursor = document.querySelector('.custom-cursor');
        if (!cursor) return;
        
        let mouseX = 0;
        let mouseY = 0;
        let cursorX = 0;
        let cursorY = 0;
        
        // Show custom cursor on VirusTotal page (reverting previous change)
        const isVirusTotalPage = window.location.pathname.includes('/virustotal');

        document.addEventListener('mousemove', (e) => {
            mouseX = e.clientX;
            mouseY = e.clientY;
        });

        function updateCursor() {
            // Direct cursor position without smoothing for better responsiveness
            cursorX = mouseX;
            cursorY = mouseY;
            
            cursor.style.left = cursorX + 'px';
            cursor.style.top = cursorY + 'px';

            requestAnimationFrame(updateCursor);
        }
        updateCursor();

        // Add hover effect with optimized selectors
        const hoverElements = document.querySelectorAll('a, button, .tool-card, .nav-item, .quick-action-btn, .sidebar-toggle');
        hoverElements.forEach(element => {
            element.addEventListener('mouseenter', () => {
                cursor.classList.add('hover');
            });
            element.addEventListener('mouseleave', () => {
                cursor.classList.remove('hover');
            });
        });

        // Add click effect
        document.addEventListener('mousedown', () => {
            cursor.classList.add('click');
        });
        document.addEventListener('mouseup', () => {
            cursor.classList.remove('click');
        });

        // Hide cursor when leaving window
        document.addEventListener('mouseleave', () => {
            cursor.style.display = 'none';
        });
        document.addEventListener('mouseenter', () => {
            cursor.style.display = 'block';
        });
    }
    
    function initSidebar() {
        const sidebar = document.querySelector('.sidebar');
        const contentArea = document.querySelector('.content-area');
        const toggleBtn = document.querySelector('.sidebar-toggle');
        const navItems = document.querySelectorAll('.nav-item');

        // Load sidebar state from localStorage
        const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
        if (isCollapsed) {
            sidebar.classList.add('collapsed');
            contentArea.classList.add('expanded');
        }

        // Toggle sidebar
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            contentArea.classList.toggle('expanded');
            localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
        });

        // Handle window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth < 768) {
                sidebar.classList.add('collapsed');
                contentArea.classList.add('expanded');
            }
        });

        // Add tooltips for collapsed state
        navItems.forEach(item => {
            const text = item.querySelector('span').textContent;
            
            item.addEventListener('mouseenter', () => {
                if (sidebar.classList.contains('collapsed')) {
                    const tooltip = document.createElement('div');
                    tooltip.className = 'nav-tooltip';
                    tooltip.textContent = text;
                    item.appendChild(tooltip);
                }
            });

            item.addEventListener('mouseleave', () => {
                const tooltip = item.querySelector('.nav-tooltip');
                if (tooltip) {
                    tooltip.remove();
                }
            });
        });
    }

    const addMobileMenuToggle = () => {
        // Check if mobile menu toggle already exists
        if (document.querySelector('.mobile-menu-toggle')) return;
        
        // Create mobile menu toggle button
        const mobileMenuToggle = document.createElement('button');
        mobileMenuToggle.className = 'mobile-menu-toggle';
        mobileMenuToggle.innerHTML = '<i class="fas fa-bars"></i>';
        document.querySelector('.content-header').prepend(mobileMenuToggle);
        
        // Add event listener
        mobileMenuToggle.addEventListener('click', () => {
            const sidebar = document.querySelector('.sidebar');
            sidebar.classList.toggle('open');
            
            // Change icon based on state
            if (sidebar.classList.contains('open')) {
                mobileMenuToggle.innerHTML = '<i class="fas fa-times"></i>';
            } else {
                mobileMenuToggle.innerHTML = '<i class="fas fa-bars"></i>';
            }
        });
    };

    const checkScreenSize = () => {
        // Initial check
        if (window.innerWidth < 768) {
            document.querySelector('.sidebar').classList.add('collapsed');
            document.querySelector('.content-area').classList.add('expanded');
        }
        
        // Add resize listener
        window.addEventListener('resize', () => {
            if (window.innerWidth < 768) {
                document.querySelector('.sidebar').classList.add('collapsed');
                document.querySelector('.content-area').classList.add('expanded');
                
                // Close mobile menu if open
                document.querySelector('.sidebar').classList.remove('open');
                
                // Reset mobile menu toggle icon
                const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
                if (mobileMenuToggle) {
                    mobileMenuToggle.innerHTML = '<i class="fas fa-bars"></i>';
                }
            }
        });
    };

    // Number animation function
    function animateValue(element, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            element.textContent = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }

    const fetchRecentScansCount = async () => {
        try {
            const response = await fetch('/scan-count');
            if (response.ok) {
                const data = await response.json();
                const countElement = document.getElementById('recent-scans-count');
                if (countElement && data.count !== undefined) {
                    // Animate the number
                    animateValue(countElement, 0, data.count, 1500);
                }
            }
        } catch (error) {
            console.error('Error fetching scan count:', error);
        }
    };

    const fetchDashboardStats = async () => {
        try {
            const response = await fetch('/dashboard-stats');
            if (response.ok) {
                const data = await response.json();
                
                // Update vulnerabilities count
                const vulnsElement = document.getElementById('vulns-count');
                if (vulnsElement && data.threats_found !== undefined) {
                    animateValue(vulnsElement, 0, data.threats_found, 1500);
                }
                
                // Update hosts count
                const hostsElement = document.getElementById('hosts-count');
                if (hostsElement && data.hosts_discovered !== undefined) {
                    animateValue(hostsElement, 0, data.hosts_discovered, 1500);
                }
                
                // Update ports count
                const portsElement = document.getElementById('ports-count');
                if (portsElement && data.ports_found !== undefined) {
                    animateValue(portsElement, 0, data.ports_found, 1500);
                }
                
                console.log('Dashboard stats updated:', data);
            }
        } catch (error) {
            console.error('Error fetching dashboard stats:', error);
        }
    };

    const addToastStyles = () => {
        // Create toast container if it doesn't exist
        if (!document.getElementById('toast-container')) {
            const toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.style.cssText = `
                position: fixed;
                bottom: 20px;
                right: 20px;
                z-index: 9999;
            `;
            document.body.appendChild(toastContainer);
        }
        
        // Toast function for showing notifications
        window.showToast = function(message, type = 'info', duration = 3000) {
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.innerHTML = message;
            
            toast.style.cssText = `
                background-color: ${type === 'success' ? '#4caf50' : type === 'error' ? '#f44336' : '#2196f3'};
                color: white;
                padding: 12px 20px;
                border-radius: 4px;
                margin-top: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
                font-weight: 500;
                min-width: 250px;
                opacity: 0;
                transform: translateY(20px);
                transition: all 0.3s ease;
            `;
            
            document.getElementById('toast-container').appendChild(toast);
            
            // Show with animation
            setTimeout(() => {
                toast.style.opacity = '1';
                toast.style.transform = 'translateY(0)';
            }, 10);
            
            // Hide after duration
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(20px)';
                
                // Remove from DOM after animation
                setTimeout(() => {
                    toast.remove();
                }, 300);
            }, duration);
        };
    };

    const observeElements = () => {
        // Check if IntersectionObserver is supported
        if ('IntersectionObserver' in window) {
            const options = {
                root: null,
                rootMargin: '0px',
                threshold: 0.1
            };
            
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('animate');
                        observer.unobserve(entry.target);
                    }
                });
            }, options);
            
            // Observe elements that should animate on scroll
            document.querySelectorAll('.stat-card, .tool-card').forEach(el => {
                observer.observe(el);
            });
        } else {
            // Fallback for browsers that don't support IntersectionObserver
            addAnimationClass();
        }
    };

    const addAnimationClass = () => {
        document.querySelectorAll('.stat-card, .tool-card').forEach(el => {
            el.classList.add('animate');
        });
    };
    
    // Add activity feed items
    window.addActivityItem = function(icon, message) {
        const activityList = document.getElementById('activity-list');
        if (!activityList) return;
        
        const item = document.createElement('div');
        item.className = 'activity-item';
        item.style.opacity = '0';
        item.innerHTML = `
            <div class="activity-icon">
                <i class="fas fa-${icon}"></i>
            </div>
            <div class="activity-details">
                <p>${message}</p>
                <p class="activity-time">${new Date().toLocaleTimeString()}</p>
            </div>
        `;
        activityList.prepend(item);
        
        // Animate in
        setTimeout(() => {
            item.style.transition = 'opacity 0.3s ease';
            item.style.opacity = '1';
        }, 10);
        
        // Keep only last 5 items
        if (activityList.children.length > 5) {
            activityList.removeChild(activityList.lastChild);
        }
    };
  });