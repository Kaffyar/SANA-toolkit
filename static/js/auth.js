/* ===== SANA TOOLKIT AUTHENTICATION JAVASCRIPT ===== */
/* Comprehensive client-side authentication handling */

class SANAAuth {
    constructor() {
        this.initializeNotificationSystem();
        this.initializeFormHandlers();
        this.initializeUIEnhancements();
        this.initializeAccessibility();
        
        // Configuration
        this.config = {
            endpoints: {
                sendLoginOTP: '/auth/api/send-login-otp',
                sendSignupOTP: '/auth/api/send-signup-otp', 
                verifyOTP: '/auth/api/verify-otp',
                resendOTP: '/auth/api/resend-otp',
                checkAuth: '/auth/api/check-auth'
            },
            timers: {
                otpExpiry: 600, // 10 minutes in seconds
                resendCooldown: 60 // 1 minute in seconds
            },
            animations: {
                duration: 300,
                easing: 'cubic-bezier(0.4, 0, 0.2, 1)'
            }
        };

        // State management
        this.state = {
            isSubmitting: false,
            currentForm: null,
            timers: {
                expiry: null,
                resend: null
            }
        };

        console.log('🛡️ SANA Authentication System Initialized');
    }

    /* ===== NOTIFICATION SYSTEM ===== */
    initializeNotificationSystem() {
        // Create notification container if it doesn't exist
        if (!document.getElementById('notification-container')) {
            const container = document.createElement('div');
            container.id = 'notification-container';
            container.className = 'notification-container';
            document.body.appendChild(container);
        }

        // Make notification function globally available
        window.showNotification = this.showNotification.bind(this);
    }

    showNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notification-container');
        if (!container) return;

        // Check for existing notifications with the same message to prevent duplicates
        const existingNotifications = container.querySelectorAll('.notification');
        for (let i = 0; i < existingNotifications.length; i++) {
            const notificationMessage = existingNotifications[i].querySelector('.notification-message');
            if (notificationMessage && notificationMessage.textContent === message) {
                // Remove the existing notification with the same message
                existingNotifications[i].remove();
            }
        }

        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        const icon = this.getNotificationIcon(type);
        notification.innerHTML = `
            <i class="${icon}"></i>
            <span class="notification-message">${message}</span>
        `;

        container.appendChild(notification);

        // Auto-remove notification
        setTimeout(() => {
            notification.style.animation = 'slideOutNotification 0.3s ease-in forwards';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, duration);

        // Add click to dismiss
        notification.addEventListener('click', () => {
            notification.style.animation = 'slideOutNotification 0.3s ease-in forwards';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        });
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-triangle',
            warning: 'fas fa-exclamation-circle',
            info: 'fas fa-info-circle'
        };
        return icons[type] || icons.info;
    }

    /* ===== FORM HANDLERS ===== */
    initializeFormHandlers() {
        // Login form
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            this.handleLoginForm(loginForm);
        }

        // Signup form
        const signupForm = document.getElementById('signup-form');
        if (signupForm) {
            this.handleSignupForm(signupForm);
        }

        // OTP form
        const otpForm = document.getElementById('otp-form');
        if (otpForm) {
            this.handleOTPForm(otpForm);
        }
    }

    handleLoginForm(form) {
        const emailInput = form.querySelector('#email');
        const passwordInput = form.querySelector('#password');
        const submitBtn = form.querySelector('#login-btn');

        // Real-time email validation
        emailInput.addEventListener('input', (e) => {
            this.validateEmailField(e.target);
        });

        // Form submission
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (this.state.isSubmitting) return;
            
            const email = emailInput.value.trim();
            const password = passwordInput.value;
            
            if (!this.validateEmailField(emailInput)) {
                emailInput.focus();
                return;
            }

            if (!password) {
                this.showFieldError(passwordInput, 'Password is required');
                passwordInput.focus();
                return;
            }

            await this.submitPasswordForm(email, password, submitBtn);
        });
    }

    handleSignupForm(form) {
        const emailInput = form.querySelector('#signup-email');
        const submitBtn = form.querySelector('#signup-btn');

        // Real-time email validation with domain suggestions
        emailInput.addEventListener('input', (e) => {
            this.validateEmailField(e.target);
        });

        emailInput.addEventListener('blur', (e) => {
            this.suggestEmailDomain(e.target);
        });

        // Form submission
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (this.state.isSubmitting) return;
            
            const email = emailInput.value.trim();
            
            if (!this.validateEmailField(emailInput)) {
                emailInput.focus();
                return;
            }

            await this.submitEmailForm(email, 'signup', submitBtn);
        });
    }

    handleOTPForm(form) {
        const otpInput = form.querySelector('#otp-input');
        const passwordInput = form.querySelector('#password');
        const confirmPasswordInput = form.querySelector('#confirm-password');
        const submitBtn = form.querySelector('#verify-btn');
        const resendBtn = form.querySelector('#resend-btn');

        // Initialize OTP input
        if (otpInput) {
            this.initializeOTPInput(otpInput);
        }

        // Initialize password fields for signup
        if (passwordInput && confirmPasswordInput) {
            this.initializePasswordFields(passwordInput, confirmPasswordInput);
        }

        // Initialize timers
        this.initializeTimers();

        // Form submission
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (this.state.isSubmitting) return;
            
            const otpCode = otpInput.value.trim();
            const password = passwordInput ? passwordInput.value : null;
            
            if (otpCode.length !== 6) {
                this.showFieldError(otpInput, 'Please enter a complete 6-digit verification code');
                otpInput.focus();
                return;
            }

            // Validate password for signup
            if (passwordInput && !this.validatePasswordFields(passwordInput, confirmPasswordInput)) {
                return;
            }

            await this.submitOTPForm(otpCode, password, submitBtn);
        });

        // Resend OTP
        if (resendBtn) {
            resendBtn.addEventListener('click', async () => {
                if (resendBtn.disabled) return;
                await this.resendOTP(resendBtn);
            });
        }
    }

    /* ===== EMAIL VALIDATION ===== */
    validateEmailField(input) {
        const email = input.value.trim();
        const isValid = email && this.isValidEmail(email);
        const validationElement = input.parentNode.querySelector('.input-validation');
        const feedbackElement = document.getElementById(input.id + '-feedback');

        this.updateFieldValidation(input, validationElement, isValid);

        if (email && !isValid) {
            this.showFieldError(input, 'Please enter a valid email address', feedbackElement);
        } else {
            this.hideFieldError(feedbackElement);
        }

        return isValid || !email;
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    suggestEmailDomain(input) {
        const email = input.value.trim();
        const commonDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'];
        const feedbackElement = document.getElementById(input.id + '-feedback');
        
        if (!email.includes('@') || this.isValidEmail(email)) return;

        const [localPart, domain] = email.split('@');
        if (!domain || domain.length < 2) return;

        const suggestion = commonDomains.find(d => 
            d.toLowerCase().startsWith(domain.toLowerCase()) && d !== domain.toLowerCase()
        );

        if (suggestion) {
            const suggestedEmail = `${localPart}@${suggestion}`;
            this.showFieldInfo(
                `Did you mean: <span style="cursor: pointer; text-decoration: underline;" onclick="document.getElementById('${input.id}').value = '${suggestedEmail}'; this.parentNode.style.display = 'none';">${suggestedEmail}</span>?`,
                feedbackElement
            );
        }
    }

    /* ===== OTP INPUT HANDLING ===== */
    initializeOTPInput(input) {
        const visualContainer = input.parentNode.querySelector('.otp-visual');
        
        // Format input - numbers only
        input.addEventListener('input', (e) => {
            let value = e.target.value.replace(/\D/g, '');
            if (value.length > 6) value = value.slice(0, 6);
            e.target.value = value;
            this.updateOTPVisual(value, visualContainer);
            
            // Clear previous errors
            this.hideFieldError(document.getElementById('otp-feedback'));
            
            // Auto-submit when complete (for login only)
            if (value.length === 6) {
                const form = input.closest('form');
                const isSignup = document.getElementById('password') !== null;
                
                if (!isSignup) {
                    setTimeout(() => {
                        form.dispatchEvent(new Event('submit'));
                    }, 300);
                }
            }
        });

        // Prevent non-numeric input
        input.addEventListener('keydown', (e) => {
            // Allow: backspace, delete, tab, escape, enter, home, end, left, right, up, down
            const allowedKeys = [8, 9, 27, 13, 36, 35, 37, 39, 38, 40, 46];
            const isCtrlCmd = e.ctrlKey || e.metaKey;
            
            if (allowedKeys.includes(e.keyCode) || 
                (isCtrlCmd && [65, 67, 86, 88].includes(e.keyCode))) {
                return;
            }
            
            // Ensure it's a number
            if ((e.shiftKey || e.keyCode < 48 || e.keyCode > 57) && 
                (e.keyCode < 96 || e.keyCode > 105)) {
                e.preventDefault();
            }
        });

        // Handle paste
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const paste = (e.clipboardData || window.clipboardData).getData('text');
            const numbers = paste.replace(/\D/g, '').slice(0, 6);
            input.value = numbers;
            this.updateOTPVisual(numbers, visualContainer);
        });
    }

    updateOTPVisual(value, container) {
        if (!container) return;
        
        const digits = container.querySelectorAll('.otp-digit');
        digits.forEach((digit, index) => {
            if (index < value.length) {
                digit.textContent = value[index];
                digit.classList.add('filled');
            } else {
                digit.textContent = '';
                digit.classList.remove('filled');
            }
        });
    }

    /* ===== PASSWORD VALIDATION ===== */
    initializePasswordFields(passwordInput, confirmPasswordInput) {
        // Password visibility toggles
        const passwordToggle = document.getElementById('password-toggle');
        const confirmPasswordToggle = document.getElementById('confirm-password-toggle');

        if (passwordToggle) {
            passwordToggle.addEventListener('click', () => {
                this.togglePasswordVisibility(passwordInput, passwordToggle);
            });
        }

        if (confirmPasswordToggle) {
            confirmPasswordToggle.addEventListener('click', () => {
                this.togglePasswordVisibility(confirmPasswordInput, confirmPasswordToggle);
            });
        }

        // Real-time validation
        passwordInput.addEventListener('input', () => {
            this.validatePasswordFields(passwordInput, confirmPasswordInput);
        });

        confirmPasswordInput.addEventListener('input', () => {
            this.validatePasswordFields(passwordInput, confirmPasswordInput);
        });
    }

    togglePasswordVisibility(input, button) {
        const icon = button.querySelector('i');
        const isPassword = input.type === 'password';
        
        input.type = isPassword ? 'text' : 'password';
        icon.className = isPassword ? 'fas fa-eye-slash' : 'fas fa-eye';
        
        // Brief focus to maintain cursor position
        setTimeout(() => {
            input.focus();
        }, 10);
    }

    validatePasswordFields(passwordInput, confirmPasswordInput) {
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        
        // Validate password requirements
        const requirements = this.checkPasswordRequirements(password);
        this.updatePasswordRequirements(requirements);
        
        const isPasswordValid = Object.values(requirements).every(Boolean);
        const passwordsMatch = password === confirmPassword;
        
        // Update password field validation
        const passwordValidation = document.getElementById('password-validation');
        const passwordFeedback = document.getElementById('password-feedback');
        
        this.updateFieldValidation(passwordInput, passwordValidation, isPasswordValid && password);
        
        if (password && !isPasswordValid) {
            this.showFieldError(passwordInput, 'Password does not meet requirements', passwordFeedback);
        } else {
            this.hideFieldError(passwordFeedback);
        }
        
        // Update confirm password field validation
        const confirmValidation = document.getElementById('confirm-password-validation');
        const confirmFeedback = document.getElementById('confirm-password-feedback');
        
        this.updateFieldValidation(confirmPasswordInput, confirmValidation, passwordsMatch && isPasswordValid && confirmPassword);
        
        if (confirmPassword && (!passwordsMatch || !isPasswordValid)) {
            const message = !passwordsMatch ? 'Passwords do not match' : 'Password does not meet requirements';
            this.showFieldError(confirmPasswordInput, message, confirmFeedback);
        } else {
            this.hideFieldError(confirmFeedback);
        }
        
        return isPasswordValid && passwordsMatch;
    }

    checkPasswordRequirements(password) {
        return {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            digit: /\d/.test(password),
            special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
        };
    }

    updatePasswordRequirements(requirements) {
        Object.keys(requirements).forEach(req => {
            const element = document.querySelector(`[data-requirement="${req}"]`);
            if (!element) return;
            
            const icon = element.querySelector('i');
            const isValid = requirements[req];
            
            if (isValid) {
                element.classList.add('valid');
                icon.className = 'fas fa-circle-check';
            } else {
                element.classList.remove('valid');
                icon.className = 'fas fa-circle-xmark';
            }
        });
    }

    /* ===== FORM SUBMISSIONS ===== */
    async submitEmailForm(email, type, button) {
        const endpoint = type === 'login' ? this.config.endpoints.sendLoginOTP : this.config.endpoints.sendSignupOTP;
        
        // Prevent duplicate requests
        if (this.state.isSubmitting) {
            console.log('Request already in progress, ignoring duplicate submission');
            return;
        }
        
        // Set a flag to track submission state
        this.state.isSubmitting = true;
        this.setButtonLoading(button, true);
        
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    email: email,
                    password: type === 'signup' ? document.getElementById('signup-password').value : undefined
                })
            });
            
            const data = await response.json();
            
            if (response.ok && data.status === 'success') {
                this.showNotification(data.message, 'success');
                
                // Redirect to OTP verification
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1500);
            } else {
                const errorMessage = data.message || `Failed to send ${type} code`;
                this.showNotification(errorMessage, 'error');
                
                // Show specific feedback for existing user during signup
                if (type === 'signup' && errorMessage.includes('already exists')) {
                    setTimeout(() => {
                        this.showNotification('This email is already registered. Try logging in instead.', 'info');
                    }, 2000);
                }
            }
        } catch (error) {
            console.error(`${type} error:`, error);
            this.showNotification('Network error. Please check your connection and try again.', 'error');
        } finally {
            // Add a small delay before allowing another submission
            setTimeout(() => {
                this.state.isSubmitting = false;
                this.setButtonLoading(button, false);
            }, 1000);
        }
    }

    async submitPasswordForm(email, password, button) {
        this.state.isSubmitting = true;
        this.setButtonLoading(button, true);
        
        try {
            const response = await fetch('/auth/api/verify-password', { // CORRECT ENDPOINT
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    email: email,
                    password: password // INCLUDE PASSWORD
                })
            });
            
            const data = await response.json();
            
            if (response.ok && data.status === 'success') {
                this.showNotification(data.message, 'success');
                
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1500);
            } else {
                const errorMessage = data.message || 'Invalid email or password';
                this.showNotification(errorMessage, 'error');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showNotification('Network error. Please check your connection and try again.', 'error');
        } finally {
            setTimeout(() => {
                this.state.isSubmitting = false;
                this.setButtonLoading(button, false);
            }, 1000);
        }
    }

    async submitOTPForm(otpCode, password, button) {
        this.state.isSubmitting = true;
        this.setButtonLoading(button, true);
        
        const requestData = { otp_code: otpCode };
        if (password) {
            requestData.password = password;
        }
        
        try {
            // First, try the regular OTP verification endpoint
            let response = await fetch(this.config.endpoints.verifyOTP, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });
            
            let data = await response.json();
            
            // If the regular endpoint fails with session error, try database fallback
            if (!response.ok && (data.message?.includes('Email is required') || data.message?.includes('Session not found'))) {
                console.log('🔄 Session-based verification failed, trying database fallback...');
                
                // Get email from the page or form
                const emailElement = document.querySelector('[data-email]') || 
                                   document.querySelector('.email-display') ||
                                   document.querySelector('.verification-email');
                
                let email = null;
                if (emailElement) {
                    email = emailElement.textContent || emailElement.getAttribute('data-email');
                }
                
                // If we can't find email, try to extract from page text
                if (!email) {
                    const pageText = document.body.textContent;
                    const emailMatch = pageText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
                    if (emailMatch) {
                        email = emailMatch[0];
                    }
                }
                
                if (email) {
                    // Try database fallback endpoint
                    const fallbackData = {
                        email: email,
                        otp_code: otpCode
                    };
                    
                    if (password) {
                        fallbackData.password = password;
                    }
                    
                    // Get temp_user_id if available (for signup)
                    const tempUserIdElement = document.querySelector('[data-temp-user-id]');
                    const formElement = document.getElementById('otp-form');
                    if (tempUserIdElement) {
                        fallbackData.temp_user_id = tempUserIdElement.getAttribute('data-temp-user-id');
                    } else if (formElement && formElement.hasAttribute('data-temp-user-id')) {
                        fallbackData.temp_user_id = formElement.getAttribute('data-temp-user-id');
                    }
                    
                    response = await fetch('/auth/api/verify-otp-db', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(fallbackData)
                    });
                    
                    data = await response.json();
                    console.log('🔄 Database fallback result:', data);
                }
            }
            
            if (response.ok && data.status === 'success') {
                // Clear timers
                this.clearTimers();
                
                this.showNotification(data.message, 'success');
                
                // Redirect
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1500);
            } else {
                const errorMessage = data.message || 'Verification failed';
                this.showNotification(errorMessage, 'error');
                
                // Clear OTP input and refocus
                const otpInput = document.getElementById('otp-input');
                if (otpInput) {
                    otpInput.value = '';
                    const visualContainer = otpInput.parentNode.querySelector('.otp-visual');
                    this.updateOTPVisual('', visualContainer);
                    otpInput.focus();
                }
            }
        } catch (error) {
            console.error('OTP verification error:', error);
            this.showNotification('Network error. Please check your connection and try again.', 'error');
        } finally {
            this.state.isSubmitting = false;
            this.setButtonLoading(button, false);
        }
    }

    async resendOTP(button) {
        this.setButtonLoading(button, true, 'Sending...');
        
        try {
            const response = await fetch(this.config.endpoints.resendOTP, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            const data = await response.json();
            
            if (response.ok && data.status === 'success') {
                this.showNotification(data.message, 'success');
                
                // Reset timers
                this.initializeTimers();
                
                // Start resend cooldown
                this.startResendCooldown(button);
            } else {
                const errorMessage = data.message || 'Failed to resend code';
                this.showNotification(errorMessage, 'error');
                this.setButtonLoading(button, false);
            }
        } catch (error) {
            console.error('Resend error:', error);
            this.showNotification('Network error. Please try again.', 'error');
            this.setButtonLoading(button, false);
        }
    }

/* ===== TIMER MANAGEMENT ===== */
initializeTimers() {
    // Check if config and timers exist
    if (!this.config || !this.config.timers) {
        console.warn('Timer config not available, using defaults');
        return;
    }
    
    // OTP expiry timer
    const timerMinutes = document.getElementById('timer-minutes');
    const timerSeconds = document.getElementById('timer-seconds');
    
    if (timerMinutes && timerSeconds) {
        let timeLeft = this.config.timers.otpExpiry;
        
        this.state.timers.expiry = setInterval(() => {
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            
            timerMinutes.textContent = minutes;
            timerSeconds.textContent = seconds.toString().padStart(2, '0');
            
            if (timeLeft <= 0) {
                this.handleTimerExpiry();
            }
            
            timeLeft--;
        }, 1000);
    }
}
    startResendCooldown(button) {
        let timeLeft = this.config.timers.resendCooldown;
        const countdownSpan = button.querySelector('#resend-countdown');
        
        button.disabled = true;
        button.querySelector('.btn-text').style.display = 'none';
        button.querySelector('.btn-countdown').style.display = 'flex';
        
        this.state.timers.resend = setInterval(() => {
            if (countdownSpan) {
                countdownSpan.textContent = timeLeft;
            }
            
            if (timeLeft <= 0) {
                clearInterval(this.state.timers.resend);
                button.disabled = false;
                button.querySelector('.btn-text').style.display = 'flex';
                button.querySelector('.btn-countdown').style.display = 'none';
            }
            
            timeLeft--;
        }, 1000);
    }

    handleTimerExpiry() {
        clearInterval(this.state.timers.expiry);
        
        const verifyBtn = document.getElementById('verify-btn');
        if (verifyBtn) {
            verifyBtn.disabled = true;
        }
        
        this.showNotification('Verification code has expired. Please request a new one.', 'warning');
        
        const otpFeedback = document.getElementById('otp-feedback');
        if (otpFeedback) {
            this.showFieldError(null, 'Verification code has expired. Please request a new one.', otpFeedback);
        }
    }

    clearTimers() {
        if (this.state.timers.expiry) {
            clearInterval(this.state.timers.expiry);
            this.state.timers.expiry = null;
        }
        if (this.state.timers.resend) {
            clearInterval(this.state.timers.resend);
            this.state.timers.resend = null;
        }
    }

    /* ===== UI UTILITIES ===== */
    setButtonLoading(button, loading, text = 'Processing...') {
        const btnText = button.querySelector('.btn-text');
        const btnLoading = button.querySelector('.btn-loading');
        
        if (loading) {
            button.disabled = true;
            if (btnText) btnText.style.display = 'none';
            if (btnLoading) {
                btnLoading.style.display = 'flex';
                const loadingText = btnLoading.querySelector('span:last-child');
                if (loadingText) loadingText.textContent = text;
            }
        } else {
            button.disabled = false;
            if (btnText) btnText.style.display = 'flex';
            if (btnLoading) btnLoading.style.display = 'none';
        }
    }

    updateFieldValidation(input, validationElement, isValid) {
        if (!validationElement) return;
        
        const wrapper = input.closest('.input-wrapper');
        
        if (isValid) {
            wrapper.classList.remove('error');
            wrapper.classList.add('valid');
            validationElement.innerHTML = '<i class="fas fa-check"></i>';
            validationElement.className = 'input-validation valid';
        } else {
            wrapper.classList.remove('valid');
            wrapper.classList.add('error');
            validationElement.innerHTML = '<i class="fas fa-times"></i>';
            validationElement.className = 'input-validation invalid';
        }
    }

    showFieldError(input, message, feedbackElement = null) {
        if (!feedbackElement && input) {
            feedbackElement = document.getElementById(input.id + '-feedback');
        }
        
        if (feedbackElement) {
            feedbackElement.innerHTML = message;
            feedbackElement.className = 'input-feedback error';
            feedbackElement.style.display = 'block';
        }
    }

    showFieldInfo(message, feedbackElement) {
        if (feedbackElement) {
            feedbackElement.innerHTML = message;
            feedbackElement.className = 'input-feedback info';
            feedbackElement.style.display = 'block';
        }
    }

    hideFieldError(feedbackElement) {
        if (feedbackElement) {
            feedbackElement.style.display = 'none';
        }
    }

    /* ===== UI ENHANCEMENTS ===== */
    initializeUIEnhancements() {
        // Enhanced input focus effects
        this.initializeInputEffects();
        
        // Initialize loading overlay
        this.initializeLoadingOverlay();
        
        // Initialize animations
        this.initializeAnimations();
        
        // Initialize keyboard shortcuts
        this.initializeKeyboardShortcuts();
    }

    initializeInputEffects() {
        const inputs = document.querySelectorAll('.auth-input, .form-control');
        
        inputs.forEach(input => {
            input.addEventListener('focus', (e) => {
                const wrapper = e.target.closest('.input-wrapper');
                if (wrapper) {
                    wrapper.classList.add('focused');
                }
            });
            
            input.addEventListener('blur', (e) => {
                const wrapper = e.target.closest('.input-wrapper');
                if (wrapper) {
                    wrapper.classList.remove('focused');
                }
            });
            
            // Auto-focus first input
            if (input.hasAttribute('autofocus') || input.id === 'email' || input.id === 'signup-email' || input.id === 'otp-input') {
                setTimeout(() => input.focus(), 100);
            }
        });
    }

    initializeLoadingOverlay() {
        window.showLoadingOverlay = (show = true, text = 'Processing...') => {
            const overlay = document.getElementById('loading-overlay');
            const loadingText = document.getElementById('loading-text');
            
            if (overlay) {
                if (show) {
                    if (loadingText) loadingText.textContent = text;
                    overlay.style.display = 'flex';
                    document.body.style.overflow = 'hidden';
                } else {
                    overlay.style.display = 'none';
                    document.body.style.overflow = '';
                }
            }
        };
    }

    initializeAnimations() {
        // Fade in elements on page load
        const animatedElements = document.querySelectorAll('.animate-fade-up');
        
        animatedElements.forEach((element, index) => {
            setTimeout(() => {
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';
            }, index * 100);
        });

        // Intersection Observer for scroll animations
        if ('IntersectionObserver' in window) {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('animate-in');
                    }
                });
            }, { threshold: 0.1 });

            document.querySelectorAll('.feature-card, .requirement-item').forEach(el => {
                observer.observe(el);
            });
        }
    }

    initializeKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Enter key for form submission
            if (e.key === 'Enter' && !e.shiftKey) {
                const activeForm = document.querySelector('form:focus-within');
                if (activeForm && !this.state.isSubmitting) {
                    const submitButton = activeForm.querySelector('button[type="submit"]');
                    if (submitButton && !submitButton.disabled) {
                        e.preventDefault();
                        submitButton.click();
                    }
                }
            }
            
            // Escape key to clear errors
            if (e.key === 'Escape') {
                document.querySelectorAll('.input-feedback').forEach(el => {
                    this.hideFieldError(el);
                });
            }
        });
    }

    /* ===== ACCESSIBILITY ===== */
    initializeAccessibility() {
        // ARIA labels and descriptions
        this.enhanceAriaAttributes();
        
        // Screen reader announcements
        this.initializeScreenReaderSupport();
        
        // High contrast mode detection
        this.detectHighContrastMode();
        
        // Reduced motion preferences
        this.respectReducedMotion();
    }

    enhanceAriaAttributes() {
        // Add ARIA labels to form elements
        const inputs = document.querySelectorAll('.auth-input, .form-control');
        inputs.forEach(input => {
            const label = document.querySelector(`label[for="${input.id}"]`);
            if (label && !input.getAttribute('aria-label')) {
                input.setAttribute('aria-label', label.textContent.trim());
            }
        });

        // Add ARIA descriptions for validation
        const feedbacks = document.querySelectorAll('.input-feedback');
        feedbacks.forEach(feedback => {
            const inputId = feedback.id.replace('-feedback', '');
            const input = document.getElementById(inputId);
            if (input) {
                input.setAttribute('aria-describedby', feedback.id);
            }
        });
    }

    initializeScreenReaderSupport() {
        // Create live region for announcements
        const liveRegion = document.createElement('div');
        liveRegion.setAttribute('aria-live', 'polite');
        liveRegion.setAttribute('aria-atomic', 'true');
        liveRegion.style.position = 'absolute';
        liveRegion.style.left = '-10000px';
        liveRegion.style.width = '1px';
        liveRegion.style.height = '1px';
        liveRegion.style.overflow = 'hidden';
        document.body.appendChild(liveRegion);

        // Function to announce to screen readers
        window.announceToScreenReader = (message) => {
            liveRegion.textContent = message;
            setTimeout(() => {
                liveRegion.textContent = '';
            }, 1000);
        };
    }

    detectHighContrastMode() {
        // Detect high contrast mode and adjust UI accordingly
        const highContrast = window.matchMedia('(prefers-contrast: high)').matches;
        if (highContrast) {
            document.documentElement.classList.add('high-contrast');
        }
    }

    respectReducedMotion() {
        // Respect user's reduced motion preference
        const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (reducedMotion) {
            document.documentElement.classList.add('reduced-motion');
        }
    }

    /* ===== CLEANUP ===== */
    destroy() {
        // Clear all timers
        this.clearTimers();
        
        // Remove event listeners
        // (In a real implementation, you'd store references to remove them)
        
        console.log('🛡️ SANA Authentication System Destroyed');
    }
}

/* ===== ADDITIONAL CSS ANIMATIONS (JavaScript-triggered) ===== */
const additionalCSS = `
@keyframes slideOutNotification {
    from { 
        transform: translateX(0); 
        opacity: 1; 
    }
    to { 
        transform: translateX(100%); 
        opacity: 0; 
    }
}

.animate-in {
    animation: fadeInUp 0.6s ease-out forwards;
}

.reduced-motion * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
}

.high-contrast * {
    border-color: #000 !important;
}
`;

// Inject additional CSS
const styleSheet = document.createElement('style');
styleSheet.textContent = additionalCSS;
document.head.appendChild(styleSheet);

/* ===== INITIALIZE ON DOM CONTENT LOADED ===== */
document.addEventListener('DOMContentLoaded', () => {
    // Skip initialization if disabled (e.g., on verify-otp page)
    if (window.DISABLE_AUTH_JS) {
        console.log('🔄 Skipping auth.js initialization (disabled for this page)');
        return;
    }
    
    // Initialize SANA Authentication System
    window.SANAAuth = new SANAAuth();

    // === Advanced Branding Interactions ===
    const brandingSection = document.querySelector('.sticky-branding');
    const brandLogo = document.querySelector('.brand-logo');

    if (brandingSection) {
        // Parallax effect on mouse move
        brandingSection.addEventListener('mousemove', function(e) {
            const mouseX = e.clientX / window.innerWidth;
            const mouseY = e.clientY / window.innerHeight;
            if (brandLogo) {
                brandLogo.style.transform = `translate(${mouseX * 10 - 5}px, ${mouseY * 10 - 5}px)`;
            }
            // 3D tilt effect
            const rect = brandingSection.getBoundingClientRect();
            const centerX = rect.left + rect.width / 2;
            const centerY = rect.top + rect.height / 2;
            const relX = e.clientX - centerX;
            const relY = e.clientY - centerY;
            const rotateX = relY * -0.005;
            const rotateY = relX * 0.005;
            brandingSection.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.01, 1.01, 1.01)`;
        });
        brandingSection.addEventListener('mouseleave', function() {
            if (brandLogo) {
                brandLogo.style.transform = 'translate(0, 0)';
            }
            brandingSection.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) scale3d(1, 1, 1)';
        });
    }

    // particles.js loading fallback
    const particlesContainer = document.getElementById('particles-js');
    if (particlesContainer) {
        if (typeof particlesJS !== 'undefined') {
            // particles.js config is already loaded in the template
        } else {
            // Fallback: Add simple CSS animation
            const fallback = document.createElement('div');
            fallback.className = 'particles-fallback';
            particlesContainer.appendChild(fallback);
        }
    }
});

/* ===== CLEANUP ON PAGE UNLOAD ===== */
window.addEventListener('beforeunload', () => {
    if (window.SANAAuth) {
        window.SANAAuth.destroy();
    }
});

/* ===== EXPORT FOR MODULE USAGE ===== */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SANAAuth;
}