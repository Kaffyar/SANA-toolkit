/**
 * SANA Toolkit - Enhanced Settings Page JavaScript
 * Handles all settings page interactions, form submissions, and API calls
 */

class SettingsManager {
    constructor() {
        this.currentSettings = {};
        this.isLoading = false;
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadUserStats();
        this.initializeThemeSelector();
        this.setupApiKeyToggle();
        this.setupThemeCards();
        this.initializeGearAnimation();
    }

    bindEvents() {
        // Settings form submission
        document.getElementById('save-settings-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.saveSettings();
        });

        // Reset settings
        document.getElementById('reset-settings-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.resetSettings();
        });

        // Email change
        document.getElementById('edit-email-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showEmailEditForm();
        });

        document.getElementById('save-email-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.saveEmail();
        });

        document.getElementById('cancel-email-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.hideEmailEditForm();
        });

        // Password change
        document.getElementById('change-password-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showPasswordChangeForm();
        });

        document.getElementById('save-password-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.savePassword();
        });

        document.getElementById('cancel-password-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.hidePasswordChangeForm();
        });

        // API key toggle and validation
        document.getElementById('toggle-api-key')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.toggleApiKeyVisibility();
        });

        document.getElementById('validate-api-key')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.validateApiKey();
        });

        // Cleanup functionality
        document.getElementById('cleanup-now-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.cleanupHistory();
        });

        // Scan timeout change
        document.getElementById('scan-timeout')?.addEventListener('change', (e) => {
            this.handleScanTimeoutChange(e.target.value);
        });

        // History cleanup change
        document.getElementById('history-cleanup')?.addEventListener('change', (e) => {
            this.handleHistoryCleanupChange(e.target.value);
        });

        // Form validation
        this.setupFormValidation();
    }

    setupThemeCards() {
        const themeCards = document.querySelectorAll('.theme-option-card');
        themeCards.forEach(card => {
            card.addEventListener('click', () => {
                const radio = card.querySelector('input[type="radio"]');
                if (radio) {
                    radio.checked = true;
                    this.handleThemeChange(radio.value);
                }
            });
        });
    }

    initializeGearAnimation() {
        // Add hover effects to gears
        const gears = document.querySelectorAll('.gear');
        gears.forEach(gear => {
            gear.addEventListener('mouseenter', () => {
                gear.style.transform = 'scale(1.1)';
            });
            
            gear.addEventListener('mouseleave', () => {
                gear.style.transform = '';
            });
        });
    }

    async saveSettings() {
        if (this.isLoading) return;

        this.isLoading = true;
        this.showLoadingState('save-settings-btn', 'Saving...');

        try {
            const settings = this.collectSettingsData();
            const response = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(settings)
            });

            const data = await response.json();

            if (data.success) {
                this.showAlert('Settings saved successfully!', 'success');
                this.currentSettings = data.settings;
                this.updateUIWithSettings(data.settings);
            } else {
                this.showAlert(data.error || 'Failed to save settings', 'error');
            }
        } catch (error) {
            console.error('Error saving settings:', error);
            this.showAlert('An error occurred while saving settings', 'error');
        } finally {
            this.isLoading = false;
            this.hideLoadingState('save-settings-btn', 'Save All Settings');
        }
    }

    async resetSettings() {
        if (this.isLoading) return;

        if (!confirm('Are you sure you want to reset all settings to defaults? This action cannot be undone.')) {
            return;
        }

        this.isLoading = true;
        this.showLoadingState('reset-settings-btn', 'Resetting...');

        try {
            const response = await fetch('/api/settings/reset', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            const data = await response.json();

            if (data.success) {
                this.showAlert('Settings reset to defaults successfully!', 'success');
                this.currentSettings = data.settings;
                this.updateUIWithSettings(data.settings);
            } else {
                this.showAlert(data.error || 'Failed to reset settings', 'error');
            }
        } catch (error) {
            console.error('Error resetting settings:', error);
            this.showAlert('An error occurred while resetting settings', 'error');
        } finally {
            this.isLoading = false;
            this.hideLoadingState('reset-settings-btn', 'Reset to Defaults');
        }
    }

    collectSettingsData() {
        const settings = {};

        // Theme - get from radio buttons
        const selectedTheme = document.querySelector('input[name="theme"]:checked');
        if (selectedTheme) {
            settings.theme = selectedTheme.value;
        }

        // Scan timeout
        const scanTimeout = document.getElementById('scan-timeout');
        if (scanTimeout) {
            settings.scan_timeout = parseInt(scanTimeout.value);
        }

        // VirusTotal API key
        const virustotalKey = document.getElementById('virustotal-api-key');
        if (virustotalKey) {
            settings.virustotal_api_key = virustotalKey.value;
        }

        // History cleanup days
        const historyCleanup = document.getElementById('history-cleanup');
        if (historyCleanup) {
            settings.history_cleanup_days = parseInt(historyCleanup.value);
        }

        return settings;
    }

    updateUIWithSettings(settings) {
        // Update theme selection
        if (settings.theme) {
            const themeRadio = document.querySelector(`input[name="theme"][value="${settings.theme}"]`);
            if (themeRadio) {
                themeRadio.checked = true;
            }
        }

        // Update scan timeout
        const scanTimeout = document.getElementById('scan-timeout');
        if (scanTimeout && settings.scan_timeout) {
            scanTimeout.value = settings.scan_timeout;
        }

        // Update VirusTotal API key
        const virustotalKey = document.getElementById('virustotal-api-key');
        if (virustotalKey && settings.virustotal_api_key) {
            virustotalKey.value = settings.virustotal_api_key;
        }

        // Update history cleanup
        const historyCleanup = document.getElementById('history-cleanup');
        if (historyCleanup && settings.history_cleanup_days !== undefined) {
            historyCleanup.value = settings.history_cleanup_days;
        }
    }

    // Email Management
    showEmailEditForm() {
        const emailForm = document.getElementById('email-edit-form');
        const newEmailInput = document.getElementById('new-email');
        
        if (emailForm && newEmailInput) {
            emailForm.style.display = 'block';
            newEmailInput.focus();
            newEmailInput.value = '';
            
            // Add smooth animation
            emailForm.style.opacity = '0';
            emailForm.style.transform = 'translateY(-10px)';
            setTimeout(() => {
                emailForm.style.transition = 'all 0.3s ease';
                emailForm.style.opacity = '1';
                emailForm.style.transform = 'translateY(0)';
            }, 10);
        }
    }

    hideEmailEditForm() {
        const emailForm = document.getElementById('email-edit-form');
        if (emailForm) {
            emailForm.style.transition = 'all 0.3s ease';
            emailForm.style.opacity = '0';
            emailForm.style.transform = 'translateY(-10px)';
            setTimeout(() => {
                emailForm.style.display = 'none';
            }, 300);
        }
    }

    async saveEmail() {
        const newEmailInput = document.getElementById('new-email');
        if (!newEmailInput) return;

        const newEmail = newEmailInput.value.trim();
        if (!newEmail) {
            this.showAlert('Please enter a new email address', 'error');
            return;
        }

        if (!this.validateEmail(newEmail)) {
            this.showAlert('Please enter a valid email address', 'error');
            return;
        }

        this.isLoading = true;
        this.showLoadingState('save-email-btn', 'Saving...');

        try {
            const response = await fetch('/api/settings/change-email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ new_email: newEmail })
            });

            const data = await response.json();

            if (data.success) {
                this.showAlert('Email changed successfully!', 'success');
                this.hideEmailEditForm();
                
                // Update the displayed email
                const userEmail = document.getElementById('user-email');
                if (userEmail) {
                    userEmail.value = data.new_email;
                }
            } else {
                this.showAlert(data.error || 'Failed to change email', 'error');
            }
        } catch (error) {
            console.error('Error changing email:', error);
            this.showAlert('An error occurred while changing email', 'error');
        } finally {
            this.isLoading = false;
            this.hideLoadingState('save-email-btn', 'Save Changes');
        }
    }

    // Password Management
    showPasswordChangeForm() {
        const passwordForm = document.getElementById('password-change-form');
        if (passwordForm) {
            passwordForm.style.display = 'block';
            document.getElementById('current-password')?.focus();
            
            // Add smooth animation
            passwordForm.style.opacity = '0';
            passwordForm.style.transform = 'translateY(-10px)';
            setTimeout(() => {
                passwordForm.style.transition = 'all 0.3s ease';
                passwordForm.style.opacity = '1';
                passwordForm.style.transform = 'translateY(0)';
            }, 10);
        }
    }

    hidePasswordChangeForm() {
        const passwordForm = document.getElementById('password-change-form');
        if (passwordForm) {
            passwordForm.style.transition = 'all 0.3s ease';
            passwordForm.style.opacity = '0';
            passwordForm.style.transform = 'translateY(-10px)';
            setTimeout(() => {
                passwordForm.style.display = 'none';
                // Clear form fields
                const inputs = passwordForm.querySelectorAll('input[type="password"]');
                inputs.forEach(input => input.value = '');
            }, 300);
        }
    }

    async savePassword() {
        const currentPassword = document.getElementById('current-password')?.value || '';
        const newPassword = document.getElementById('new-password')?.value || '';
        const confirmPassword = document.getElementById('confirm-password')?.value || '';

        // Validation
        if (!currentPassword) {
            this.showAlert('Please enter your current password', 'error');
            return;
        }

        if (!newPassword) {
            this.showAlert('Please enter a new password', 'error');
            return;
        }

        if (newPassword !== confirmPassword) {
            this.showAlert('New passwords do not match', 'error');
            return;
        }

        if (!this.validatePassword(newPassword)) {
            this.showAlert('Password must be at least 8 characters with uppercase, lowercase, digit, and special character', 'error');
            return;
        }

        this.isLoading = true;
        this.showLoadingState('save-password-btn', 'Saving...');

        try {
            const response = await fetch('/api/settings/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword,
                    confirm_password: confirmPassword
                })
            });

            const data = await response.json();

            if (data.success) {
                this.showAlert('Password changed successfully!', 'success');
                this.hidePasswordChangeForm();
            } else {
                this.showAlert(data.error || 'Failed to change password', 'error');
            }
        } catch (error) {
            console.error('Error changing password:', error);
            this.showAlert('An error occurred while changing password', 'error');
        } finally {
            this.isLoading = false;
            this.hideLoadingState('save-password-btn', 'Update Password');
        }
    }

    // API Key Management
    setupApiKeyToggle() {
        const toggleBtn = document.getElementById('toggle-api-key');
        const apiKeyInput = document.getElementById('virustotal-api-key');
        
        if (toggleBtn && apiKeyInput) {
            toggleBtn.addEventListener('click', () => {
                this.toggleApiKeyVisibility();
            });
        }
    }

    toggleApiKeyVisibility() {
        const apiKeyInput = document.getElementById('virustotal-api-key');
        const toggleBtn = document.getElementById('toggle-api-key');
        
        if (apiKeyInput && toggleBtn) {
            if (apiKeyInput.type === 'password') {
                apiKeyInput.type = 'text';
                toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
            } else {
                apiKeyInput.type = 'password';
                toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
            }
        }
    }

    async validateApiKey() {
        const apiKeyInput = document.getElementById('virustotal-api-key');
        if (!apiKeyInput) return;

        const apiKey = apiKeyInput.value.trim();
        if (!apiKey) {
            this.showAlert('Please enter a VirusTotal API key to validate', 'error');
            return;
        }

        this.isLoading = true;
        this.showLoadingState('validate-api-key', 'Validating...');

        try {
            const response = await fetch('/api/settings/validate-virustotal-key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ api_key: apiKey })
            });

            const data = await response.json();

            if (data.success) {
                this.showAlert('API key format is valid!', 'success');
            } else {
                this.showAlert(data.error || 'Invalid API key format', 'error');
            }
        } catch (error) {
            console.error('Error validating API key:', error);
            this.showAlert('An error occurred while validating the API key', 'error');
        } finally {
            this.isLoading = false;
            this.hideLoadingState('validate-api-key', 'Validate API Key');
        }
    }

    // History Cleanup
    async cleanupHistory() {
        if (this.isLoading) return;

        // Show cleanup options
        const cleanupOptions = [
            { value: null, label: 'Use current settings (90 days)' },
            { value: 7, label: 'Clean up scans older than 7 days' },
            { value: 30, label: 'Clean up scans older than 30 days' },
            { value: 1, label: 'Clean up scans older than 1 day (for testing)' }
        ];

        const selectedOption = await this.showCleanupOptions(cleanupOptions);
        if (!selectedOption) return; // User cancelled

        const confirmMessage = selectedOption.value === null 
            ? 'Are you sure you want to clean up old scan history based on your current settings? This action cannot be undone.'
            : `Are you sure you want to clean up scans older than ${selectedOption.value} day(s)? This action cannot be undone.`;

        if (!confirm(confirmMessage)) {
            return;
        }

        this.isLoading = true;
        this.showLoadingState('cleanup-now-btn', 'Cleaning...');

        try {
            const requestBody = selectedOption.value !== null ? { force_days: selectedOption.value } : {};
            
            const response = await fetch('/api/settings/cleanup-history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody)
            });

            const data = await response.json();

            if (data.success) {
                this.showAlert(data.message, 'success');
                // Refresh user stats
                this.loadUserStats();
            } else {
                this.showAlert(data.error || 'Failed to cleanup history', 'error');
            }
        } catch (error) {
            console.error('Error cleaning up history:', error);
            this.showAlert('An error occurred while cleaning up history', 'error');
        } finally {
            this.isLoading = false;
            this.hideLoadingState('cleanup-now-btn', 'Cleanup Now');
        }
    }

    showCleanupOptions(options) {
        return new Promise((resolve) => {
            const optionList = options.map(opt => 
                `${opt.value === null ? '✓' : '○'} ${opt.label}`
            ).join('\n');
            
            const message = `Select cleanup option:\n\n${optionList}\n\nEnter the number (1-${options.length}) or press Cancel:`;
            
            const choice = prompt(message);
            if (!choice) {
                resolve(null); // User cancelled
                return;
            }
            
            const index = parseInt(choice) - 1;
            if (index >= 0 && index < options.length) {
                resolve(options[index]);
            } else {
                alert('Invalid selection. Please try again.');
                resolve(null);
            }
        });
    }

    // Theme Management
    initializeThemeSelector() {
        // Set initial theme based on current selection
        const selectedTheme = document.querySelector('input[name="theme"]:checked');
        if (selectedTheme) {
            this.handleThemeChange(selectedTheme.value);
        }
    }

    handleThemeChange(theme) {
        // Update localStorage
        localStorage.setItem('themePreference', theme);
        
        // Apply theme
        if (theme === 'light') {
            document.documentElement.classList.remove('dark-theme');
        } else if (theme === 'dark') {
            document.documentElement.classList.add('dark-theme');
        } else if (theme === 'auto') {
            // Auto theme - check system preference
            if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                document.documentElement.classList.add('dark-theme');
            } else {
                document.documentElement.classList.remove('dark-theme');
            }
        }

        // Show feedback
        this.showAlert(`Theme changed to ${theme}`, 'success');
    }

    handleScanTimeoutChange(timeout) {
        const timeoutText = timeout >= 60 ? `${timeout / 60} minute${timeout / 60 > 1 ? 's' : ''}` : `${timeout} second${timeout > 1 ? 's' : ''}`;
        this.showAlert(`Default scan timeout set to ${timeoutText}`, 'info');
    }

    handleHistoryCleanupChange(days) {
        const message = days === '0' ? 'Scan history will be kept indefinitely' : `Old scans will be automatically deleted after ${days} days`;
        this.showAlert(message, 'info');
    }

    // User Statistics
    async loadUserStats() {
        try {
            const response = await fetch('/api/settings/user-stats');
            const data = await response.json();

            if (data.success) {
                this.updateUserStatsDisplay(data.stats);
            }
        } catch (error) {
            console.error('Error loading user stats:', error);
        }
    }

    updateUserStatsDisplay(stats) {
        // Update hero stats
        const totalScansElement = document.getElementById('total-scans-count');
        if (totalScansElement) {
            totalScansElement.textContent = stats.total_scans || 0;
        }

        const completedScansElement = document.getElementById('completed-scans');
        if (completedScansElement) {
            completedScansElement.textContent = stats.completed_scans || 0;
        }

        // Update info panel stats
        const totalScansDisplay = document.getElementById('total-scans-display');
        if (totalScansDisplay) {
            totalScansDisplay.textContent = stats.total_scans || 0;
        }

        const completedScansDisplay = document.getElementById('completed-scans-display');
        if (completedScansDisplay) {
            completedScansDisplay.textContent = stats.completed_scans || 0;
        }

        const failedScansDisplay = document.getElementById('failed-scans-display');
        if (failedScansDisplay) {
            failedScansDisplay.textContent = stats.failed_scans || 0;
        }

        const lastScanDate = document.getElementById('last-scan-date');
        if (lastScanDate) {
            if (stats.last_scan_date) {
                const date = new Date(stats.last_scan_date);
                lastScanDate.textContent = date.toLocaleDateString();
            } else {
                lastScanDate.textContent = 'N/A';
            }
        }
    }

    // Form Validation
    setupFormValidation() {
        // Email validation
        const newEmailInput = document.getElementById('new-email');
        if (newEmailInput) {
            newEmailInput.addEventListener('input', (e) => {
                this.validateEmailField(e.target);
            });
        }

        // Password validation
        const newPasswordInput = document.getElementById('new-password');
        if (newPasswordInput) {
            newPasswordInput.addEventListener('input', (e) => {
                this.validatePasswordField(e.target);
            });
        }

        const confirmPasswordInput = document.getElementById('confirm-password');
        if (confirmPasswordInput) {
            confirmPasswordInput.addEventListener('input', (e) => {
                this.validateConfirmPasswordField(e.target);
            });
        }
    }

    validateEmailField(input) {
        const email = input.value.trim();
        const isValid = this.validateEmail(email);
        
        input.classList.toggle('error', !isValid && email.length > 0);
        input.classList.toggle('success', isValid);
        
        this.showValidationMessage(input, isValid ? 'Valid email format' : 'Please enter a valid email address', isValid ? 'success' : 'error');
    }

    validatePasswordField(input) {
        const password = input.value;
        const isValid = this.validatePassword(password);
        
        input.classList.toggle('error', !isValid && password.length > 0);
        input.classList.toggle('success', isValid);
        
        this.showValidationMessage(input, isValid ? 'Password meets requirements' : 'Password must be at least 8 characters with uppercase, lowercase, digit, and special character', isValid ? 'success' : 'error');
    }

    validateConfirmPasswordField(input) {
        const confirmPassword = input.value;
        const newPassword = document.getElementById('new-password')?.value || '';
        const isValid = confirmPassword === newPassword && confirmPassword.length > 0;
        
        input.classList.toggle('error', !isValid && confirmPassword.length > 0);
        input.classList.toggle('success', isValid);
        
        this.showValidationMessage(input, isValid ? 'Passwords match' : 'Passwords do not match', isValid ? 'success' : 'error');
    }

    showValidationMessage(input, message, type) {
        // Remove existing validation message
        const existingMessage = input.parentNode.querySelector('.validation-message');
        if (existingMessage) {
            existingMessage.remove();
        }

        // Create new validation message
        const validationMessage = document.createElement('div');
        validationMessage.className = `validation-message ${type}`;
        validationMessage.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check' : 'exclamation-triangle'}"></i>
            <span>${message}</span>
        `;

        input.parentNode.appendChild(validationMessage);
    }

    // Utility Methods
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    validatePassword(password) {
        if (password.length < 8) return false;
        
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasDigit = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        
        return hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
    }

    showAlert(message, type = 'info') {
        const alertContainer = document.getElementById('settings-messages');
        const alertElement = document.getElementById('settings-messages');
        const messageText = document.getElementById('settings-message-text');
        
        if (alertContainer && alertElement && messageText) {
            // Remove existing classes
            alertElement.className = 'settings-alert';
            
            // Add new classes
            alertElement.classList.add(type);
            
            // Set message
            messageText.textContent = message;
            
            // Show alert with animation
            alertContainer.style.display = 'block';
            alertContainer.style.opacity = '0';
            alertContainer.style.transform = 'translateY(-10px)';
            
            setTimeout(() => {
                alertContainer.style.transition = 'all 0.3s ease';
                alertContainer.style.opacity = '1';
                alertContainer.style.transform = 'translateY(0)';
            }, 10);
            
            // Auto-hide after 5 seconds
            setTimeout(() => {
                alertContainer.style.transition = 'all 0.3s ease';
                alertContainer.style.opacity = '0';
                alertContainer.style.transform = 'translateY(-10px)';
                setTimeout(() => {
                    alertContainer.style.display = 'none';
                }, 300);
            }, 5000);
        }
    }

    showLoadingState(buttonId, loadingText) {
        const button = document.getElementById(buttonId);
        if (button) {
            button.disabled = true;
            button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${loadingText}`;
        }
    }

    hideLoadingState(buttonId, originalText) {
        const button = document.getElementById(buttonId);
        if (button) {
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }
}

// Initialize settings manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SettingsManager();
});

// Export for global access
window.SettingsManager = SettingsManager; 