 // Common form validation functions - Enhanced Version
document.addEventListener('DOMContentLoaded', function() {
    initializeFormValidations();
    setupInputValidation();
    initializeSessionValidation();
    setupEnhancedValidationStyles();
});

function initializeFormValidations() {
    // Login form validation
    const loginForm = document.querySelector('.login-container form');
    if (loginForm) {
        loginForm.addEventListener('submit', validateLoginForm);
        setupRealTimeValidation(loginForm);
    }

    // Registration form validation
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        initializeRegistrationValidation(registerForm);
        setupRealTimeValidation(registerForm);
    }

    // Session creation form validation (only for lecturers)
    const sessionForm = document.querySelector('.session-form');
    if (sessionForm) {
        sessionForm.addEventListener('submit', validateSessionForm);
        setupRealTimeValidation(sessionForm);
    }

    // Index page form validation
    const indexForms = document.querySelectorAll('.container form');
    indexForms.forEach(form => {
        if (form.querySelector('input[name="login"]')) {
            form.addEventListener('submit', validateLoginForm);
            setupRealTimeValidation(form);
        } else if (form.querySelector('input[name="register"]')) {
            form.addEventListener('submit', validateRegistrationForm);
            setupRealTimeValidation(form);
        }
    });

    // Manual session code entry validation
    const manualEntryForm = document.querySelector('.manual-entry form');
    if (manualEntryForm) {
        manualEntryForm.addEventListener('submit', validateSessionCodeForm);
        setupRealTimeValidation(manualEntryForm);
    }

    // QR session creation form in dashboard
    const qrSessionForm = document.querySelector('form[action*="dashboard"]');
    if (qrSessionForm && qrSessionForm.querySelector('input[name="session_name"]')) {
        qrSessionForm.addEventListener('submit', validateSessionForm);
        setupRealTimeValidation(qrSessionForm);
    }

    // New session creation form with date/time fields
    const newSessionForm = document.getElementById('sessionForm');
    if (newSessionForm) {
        newSessionForm.addEventListener('submit', validateNewSessionForm);
        setupRealTimeValidation(newSessionForm);
        setupDateTimeValidation(newSessionForm);
    }
}

// Enhanced Login form validation
function validateLoginForm(e) {
    const form = this;
    const email = form.querySelector('#email')?.value || form.querySelector('input[type="email"]')?.value;
    const password = form.querySelector('#password')?.value || form.querySelector('input[type="password"]')?.value;
    
    clearFieldErrors(form);
    
    let isValid = true;
    
    if (!email) {
        showFieldError(form.querySelector('#email') || form.querySelector('input[type="email"]'), 'Email is required');
        isValid = false;
    } else if (!isValidEmail(email)) {
        showFieldError(form.querySelector('#email') || form.querySelector('input[type="email"]'), 'Please enter a valid email address');
        isValid = false;
    }
    
    if (!password) {
        showFieldError(form.querySelector('#password') || form.querySelector('input[type="password"]'), 'Password is required');
        isValid = false;
    } else if (password.length < 6) {
        showFieldError(form.querySelector('#password') || form.querySelector('input[type="password"]'), 'Password must be at least 6 characters');
        isValid = false;
    }
    
    if (!isValid) {
        e.preventDefault();
        showAlert('Please fix the errors below', 'error');
        return false;
    }
    
    return true;
}

// Enhanced Registration form validation
function validateRegistrationForm(e) {
    const form = this;
    const username = form.querySelector('#username')?.value;
    const email = form.querySelector('#email')?.value;
    const password = form.querySelector('#password')?.value;
    const confirmPassword = form.querySelector('#confirm_password')?.value;
    const role = form.querySelector('#role')?.value;
    
    clearFieldErrors(form);
    
    let isValid = true;
    
    // Username validation
    if (!username) {
        showFieldError(form.querySelector('#username'), 'Username is required');
        isValid = false;
    } else if (username.length < 3) {
        showFieldError(form.querySelector('#username'), 'Username must be at least 3 characters long');
        isValid = false;
    } else if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        showFieldError(form.querySelector('#username'), 'Username can only contain letters, numbers, and underscores');
        isValid = false;
    }
    
    // Email validation
    if (!email) {
        showFieldError(form.querySelector('#email'), 'Email is required');
        isValid = false;
    } else if (!isValidEmail(email)) {
        showFieldError(form.querySelector('#email'), 'Please enter a valid email address');
        isValid = false;
    }
    
    // Password validation
    if (!password) {
        showFieldError(form.querySelector('#password'), 'Password is required');
        isValid = false;
    } else {
        const passwordErrors = validatePasswordStrength(password);
        if (passwordErrors.length > 0) {
            showFieldError(form.querySelector('#password'), passwordErrors.join(', '));
            isValid = false;
        }
    }
    
    // Confirm password validation
    if (!confirmPassword) {
        showFieldError(form.querySelector('#confirm_password'), 'Please confirm your password');
        isValid = false;
    } else if (password !== confirmPassword) {
        showFieldError(form.querySelector('#confirm_password'), 'Passwords do not match');
        isValid = false;
    }
    
    // Role validation (if exists)
    if (role && !role) {
        showFieldError(form.querySelector('#role'), 'Please select a role');
        isValid = false;
    }
    
    if (!isValid) {
        e.preventDefault();
        showAlert('Please fix the errors below', 'error');
        return false;
    }
    
    return true;
}

// OLD Session creation form validation (for duration-based sessions)
function validateSessionForm(e) {
    const form = this;
    const sessionName = form.querySelector('input[name="session_name"]')?.value;
    const duration = form.querySelector('select[name="duration"]')?.value;
    
    clearFieldErrors(form);
    
    let isValid = true;
    
    if (!sessionName || sessionName.trim() === '') {
        showFieldError(form.querySelector('input[name="session_name"]'), 'Session name is required');
        isValid = false;
    } else if (sessionName.trim().length < 3) {
        showFieldError(form.querySelector('input[name="session_name"]'), 'Session name must be at least 3 characters long');
        isValid = false;
    } else if (sessionName.trim().length > 255) {
        showFieldError(form.querySelector('input[name="session_name"]'), 'Session name is too long (max 255 characters)');
        isValid = false;
    }
    
    if (!duration || duration <= 0) {
        showFieldError(form.querySelector('select[name="duration"]'), 'Please select a valid duration');
        isValid = false;
    }
    
    if (!isValid) {
        e.preventDefault();
        showAlert('Please fix the errors below', 'error');
        return false;
    }
    
    return true;
}

// NEW Session creation form validation (for date/time-based sessions)
function validateNewSessionForm(e) {
    const form = this;
    const sessionName = form.querySelector('input[name="session_name"]')?.value;
    const courseCode = form.querySelector('input[name="course_code"]')?.value;
    const startDate = form.querySelector('input[name="start_date"]')?.value;
    const startTime = form.querySelector('input[name="start_time"]')?.value;
    const endDate = form.querySelector('input[name="end_date"]')?.value;
    const endTime = form.querySelector('input[name="end_time"]')?.value;
    
    clearFieldErrors(form);
    
    let isValid = true;
    
    // Session name validation
    if (!sessionName || sessionName.trim() === '') {
        showFieldError(form.querySelector('input[name="session_name"]'), 'Session name is required');
        isValid = false;
    } else if (sessionName.trim().length < 3) {
        showFieldError(form.querySelector('input[name="session_name"]'), 'Session name must be at least 3 characters long');
        isValid = false;
    } else if (sessionName.trim().length > 255) {
        showFieldError(form.querySelector('input[name="session_name"]'), 'Session name is too long (max 255 characters)');
        isValid = false;
    }
    
    // Course code validation
    if (!courseCode || courseCode.trim() === '') {
        showFieldError(form.querySelector('input[name="course_code"]'), 'Course code is required');
        isValid = false;
    } else if (courseCode.trim().length < 2) {
        showFieldError(form.querySelector('input[name="course_code"]'), 'Course code must be at least 2 characters long');
        isValid = false;
    } else if (courseCode.trim().length > 20) {
        showFieldError(form.querySelector('input[name="course_code"]'), 'Course code is too long (max 20 characters)');
        isValid = false;
    } else if (!/^[A-Za-z0-9]+$/.test(courseCode)) {
        showFieldError(form.querySelector('input[name="course_code"]'), 'Course code can only contain letters and numbers');
        isValid = false;
    }
    
    // Date and time validation
    if (!validateDateTime('start', startDate, startTime)) {
        isValid = false;
    }
    
    if (!validateDateTime('end', endDate, endTime, startDate + ' ' + startTime)) {
        isValid = false;
    }
    
    if (!isValid) {
        e.preventDefault();
        showAlert('Please fix the errors below', 'error');
        return false;
    }
    
    return true;
}

// Session code validation for manual entry
function validateSessionCodeForm(e) {
    const form = this;
    const sessionCode = form.querySelector('input[name="session"]')?.value;
    
    clearFieldErrors(form);
    
    let isValid = true;
    
    if (!sessionCode || sessionCode.trim() === '') {
        showFieldError(form.querySelector('input[name="session"]'), 'Session code is required');
        isValid = false;
    } else if (sessionCode.trim().length < 5) {
        showFieldError(form.querySelector('input[name="session"]'), 'Session code must be at least 5 characters');
        isValid = false;
    } else if (!/^[a-zA-Z0-9_-]+$/.test(sessionCode)) {
        showFieldError(form.querySelector('input[name="session"]'), 'Invalid session code format');
        isValid = false;
    }
    
    if (!isValid) {
        e.preventDefault();
        showAlert('Please fix the errors below', 'error');
        return false;
    }
    
    return true;
}

// Enhanced Registration-specific validation initialization
function initializeRegistrationValidation(form) {
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const passwordStrength = document.getElementById('passwordStrength');
    const passwordMatch = document.getElementById('passwordMatch');
    const usernameInput = document.getElementById('username');

    // Username availability check (debounced)
    if (usernameInput) {
        let usernameTimeout;
        usernameInput.addEventListener('input', function() {
            clearTimeout(usernameTimeout);
            const username = this.value.trim();
            
            // Clear previous feedback for short usernames
            if (username.length < 3) {
                const feedback = document.getElementById('usernameFeedback');
                if (feedback) feedback.remove();
                return;
            }
            
            usernameTimeout = setTimeout(() => {
                checkUsernameAvailability(username);
            }, 500);
        });
    }

    if (passwordInput && passwordStrength) {
        passwordInput.addEventListener('input', function() {
            updatePasswordStrength(this.value, passwordStrength);
            validatePasswordMatch(); // Also update match status when password changes
        });
    }

    if (passwordInput && confirmPasswordInput) {
        function validatePasswordMatch() {
            const password = passwordInput.value;
            const confirmPassword = confirmPasswordInput.value;
            
            // Create or get match feedback element
            let matchElement = document.getElementById('passwordMatchFeedback');
            if (!matchElement) {
                matchElement = document.createElement('div');
                matchElement.id = 'passwordMatchFeedback';
                matchElement.className = 'password-feedback';
                confirmPasswordInput.parentNode.appendChild(matchElement);
            }
            
            if (confirmPassword.length === 0) {
                matchElement.textContent = '';
                matchElement.className = 'password-feedback';
            } else if (password === confirmPassword) {
                matchElement.textContent = '✓ Passwords match';
                matchElement.className = 'password-feedback match';
            } else {
                matchElement.textContent = '✗ Passwords do not match';
                matchElement.className = 'password-feedback no-match';
            }
        }

        passwordInput.addEventListener('input', validatePasswordMatch);
        confirmPasswordInput.addEventListener('input', validatePasswordMatch);
    }

    form.addEventListener('submit', validateRegistrationForm);
}

// Enhanced Password strength calculation
function updatePasswordStrength(password, strengthElement) {
    let strength = 0;
    const feedback = strengthElement.parentElement.querySelector('.password-feedback') || 
                    document.createElement('div');
    
    if (!feedback.className.includes('password-feedback')) {
        feedback.className = 'password-feedback';
        strengthElement.parentElement.appendChild(feedback);
    }
    
    if (password.length >= 6) strength++;
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    // Update strength bar and feedback
    strengthElement.className = 'strength-bar';
    
    if (password.length === 0) {
        strengthElement.style.width = '0%';
        feedback.textContent = '';
    } else if (strength <= 2) {
        strengthElement.className += ' strength-weak';
        strengthElement.style.width = '33%';
        feedback.textContent = 'Weak password';
        feedback.className = 'password-feedback weak';
    } else if (strength <= 4) {
        strengthElement.className += ' strength-medium';
        strengthElement.style.width = '66%';
        feedback.textContent = 'Medium strength password';
        feedback.className = 'password-feedback medium';
    } else {
        strengthElement.className += ' strength-strong';
        strengthElement.style.width = '100%';
        feedback.textContent = 'Strong password';
        feedback.className = 'password-feedback strong';
    }
}

// Comprehensive password validation
function validatePasswordStrength(password) {
    const errors = [];
    
    if (password.length < 6) {
        errors.push('at least 6 characters');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('one uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('one lowercase letter');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('one number');
    }
    
    return errors;
}

// Email validation helper
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Date and time validation helper
function validateDateTime(type, date, time, compareTime = null) {
    const dateErrorElement = document.getElementById(`${type}_date_error`) || createErrorElement(`${type}_date`);
    const timeErrorElement = document.getElementById(`${type}_time_error`) || createErrorElement(`${type}_time`);
    const dateElement = document.getElementById(`${type}_date`);
    const timeElement = document.getElementById(`${type}_time`);
    
    let isValid = true;
    
    if (!date) {
        showFieldError(dateElement, dateErrorElement, `${type.charAt(0).toUpperCase() + type.slice(1)} date is required`);
        isValid = false;
    } else {
        clearFieldError(dateElement, dateErrorElement);
    }
    
    if (!time) {
        showFieldError(timeElement, timeErrorElement, `${type.charAt(0).toUpperCase() + type.slice(1)} time is required`);
        isValid = false;
    } else {
        clearFieldError(timeElement, timeErrorElement);
    }
    
    if (date && time) {
        const datetime = new Date(date + 'T' + time);
        const now = new Date();
        
        if (type === 'start' && datetime < now) {
            showFieldError(dateElement, dateErrorElement, 'Start time must be in the future');
            showFieldError(timeElement, timeErrorElement, 'Start time must be in the future');
            isValid = false;
        }
        
        if (type === 'end' && compareTime) {
            const startDatetime = new Date(compareTime.replace(' ', 'T'));
            if (datetime <= startDatetime) {
                showFieldError(dateElement, dateErrorElement, 'End time must be after start time');
                showFieldError(timeElement, timeErrorElement, 'End time must be after start time');
                isValid = false;
            }
        }
    }
    
    return isValid;
}

// Setup date/time validation
function setupDateTimeValidation(form) {
    const startDateInput = form.querySelector('input[name="start_date"]');
    const startTimeInput = form.querySelector('input[name="start_time"]');
    const endDateInput = form.querySelector('input[name="end_date"]');
    const endTimeInput = form.querySelector('input[name="end_time"]');
    
    if (startDateInput && startTimeInput && endDateInput && endTimeInput) {
        // Update end date min when start date changes
        startDateInput.addEventListener('change', function() {
            endDateInput.min = this.value;
            if (endDateInput.value < this.value) {
                endDateInput.value = this.value;
            }
        });
        
        // Update end time when dates are the same and start time changes
        startTimeInput.addEventListener('change', function() {
            if (startDateInput.value === endDateInput.value) {
                endTimeInput.min = this.value;
                if (endTimeInput.value < this.value) {
                    endTimeInput.value = this.value;
                }
            }
        });
    }
}

// Real-time validation setup
function setupRealTimeValidation(form) {
    const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
    
    inputs.forEach(input => {
        input.addEventListener('blur', function() {
            validateField(this);
        });
        
        input.addEventListener('input', function() {
            clearFieldError(this);
            if (this.value.trim()) {
                this.classList.add('dirty');
            }
        });
    });
}

// Individual field validation
function validateField(field) {
    const value = field.value.trim();
    let isValid = true;
    let errorMessage = '';
    
    if (field.hasAttribute('required') && !value) {
        isValid = false;
        errorMessage = field.getAttribute('data-required-message') || 'This field is required';
    } else if (field.type === 'email' && value && !isValidEmail(value)) {
        isValid = false;
        errorMessage = 'Please enter a valid email address';
    } else if (field.type === 'password' && value) {
        if (field.id === 'password' || field.name === 'password') {
            const errors = validatePasswordStrength(value);
            if (errors.length > 0) {
                isValid = false;
                errorMessage = `Password needs: ${errors.join(', ')}`;
            }
        }
    } else if (field.name === 'username' && value) {
        if (value.length < 3) {
            isValid = false;
            errorMessage = 'Username must be at least 3 characters';
        } else if (!/^[a-zA-Z0-9_]+$/.test(value)) {
            isValid = false;
            errorMessage = 'Only letters, numbers, and underscores allowed';
        }
    } else if (field.name === 'confirm_password' && value) {
        const passwordField = field.form.querySelector('#password') || field.form.querySelector('input[type="password"]');
        if (passwordField && value !== passwordField.value) {
            isValid = false;
            errorMessage = 'Passwords do not match';
        }
    } else if (field.name === 'session_name' && value) {
        if (value.length < 3) {
            isValid = false;
            errorMessage = 'Session name must be at least 3 characters';
        } else if (value.length > 255) {
            isValid = false;
            errorMessage = 'Session name is too long (max 255 characters)';
        }
    } else if (field.name === 'course_code' && value) {
        if (value.length < 2) {
            isValid = false;
            errorMessage = 'Course code must be at least 2 characters';
        } else if (value.length > 20) {
            isValid = false;
            errorMessage = 'Course code is too long (max 20 characters)';
        } else if (!/^[A-Za-z0-9]+$/.test(value)) {
            isValid = false;
            errorMessage = 'Course code can only contain letters and numbers';
        }
    } else if (field.name === 'session' && value) {
        if (value.length < 5) {
            isValid = false;
            errorMessage = 'Session code must be at least 5 characters';
        } else if (!/^[a-zA-Z0-9_-]+$/.test(value)) {
            isValid = false;
            errorMessage = 'Invalid session code format';
        }
    } else if (field.type === 'date' && value) {
        const selectedDate = new Date(value);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        if (selectedDate < today) {
            isValid = false;
            errorMessage = 'Date cannot be in the past';
        }
    } else if (field.type === 'time' && value) {
        // Basic time format validation
        const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
        if (!timeRegex.test(value)) {
            isValid = false;
            errorMessage = 'Please enter a valid time';
        }
    }
    
    if (!isValid) {
        showFieldError(field, errorMessage);
    } else {
        clearFieldError(field);
        field.classList.add('valid');
    }
    
    return isValid;
}

// Field error handling
function showFieldError(field, message) {
    clearFieldError(field);
    
    field.classList.add('error');
    field.classList.remove('valid');
    
    const errorElement = document.createElement('div');
    errorElement.className = 'field-error';
    errorElement.textContent = message;
    
    field.parentNode.appendChild(errorElement);
}

function clearFieldError(field) {
    field.classList.remove('error');
    const existingError = field.parentNode.querySelector('.field-error');
    if (existingError) {
        existingError.remove();
    }
}

function clearFieldErrors(form) {
    const errorFields = form.querySelectorAll('.error');
    errorFields.forEach(field => {
        field.classList.remove('error');
    });
    
    const errorMessages = form.querySelectorAll('.field-error');
    errorMessages.forEach(error => error.remove());
}

function createErrorElement(fieldName) {
    const errorElement = document.createElement('div');
    errorElement.id = `${fieldName}_error`;
    errorElement.className = 'field-error';
    const field = document.getElementById(fieldName);
    if (field && field.parentNode) {
        field.parentNode.appendChild(errorElement);
    }
    return errorElement;
}

// Username availability check (simulated)
function checkUsernameAvailability(username) {
    if (username.length < 3) return;
    
    // Create or get feedback element
    let feedback = document.getElementById('usernameFeedback');
    if (!feedback) {
        feedback = document.createElement('div');
        feedback.id = 'usernameFeedback';
        feedback.className = 'password-feedback';
        const usernameField = document.getElementById('username');
        if (usernameField && usernameField.parentNode) {
            usernameField.parentNode.appendChild(feedback);
        }
    }
    
    // Show loading state
    feedback.textContent = 'Checking availability...';
    feedback.className = 'password-feedback checking';
    
    // Simulate API call
    setTimeout(() => {
        // Simulate some taken usernames
        const takenUsernames = ['admin', 'user', 'test', 'lecturer', 'student', 'teacher', 'professor'];
        if (takenUsernames.includes(username.toLowerCase())) {
            feedback.textContent = '✗ Username is already taken';
            feedback.className = 'password-feedback no-match';
        } else {
            feedback.textContent = '✓ Username is available';
            feedback.className = 'password-feedback match';
        }
    }, 800);
}

// Session validation initialization
function initializeSessionValidation() {
    // Check for expired sessions
    const sessionItems = document.querySelectorAll('.session-item');
    sessionItems.forEach(item => {
        const expiresAt = item.querySelector('.expires-at')?.textContent || 
                         item.querySelector('.session-meta')?.textContent?.match(/Expires: ([^|]+)/)?.[1];
        if (expiresAt && isSessionExpired(expiresAt.trim())) {
            item.classList.add('expired');
            const actions = item.querySelector('.session-actions');
            if (actions) {
                actions.innerHTML = '<span class="expired-badge">Expired</span>';
            }
        }
    });
}

function isSessionExpired(expiresAt) {
    try {
        return new Date() > new Date(expiresAt);
    } catch (e) {
        console.error('Error parsing date:', e);
        return false;
    }
}

// Enhanced Alert system
function showAlert(message, type = 'info', duration = 5000) {
    // Remove existing alerts
    const existingAlert = document.querySelector('.custom-alert');
    if (existingAlert) {
        existingAlert.remove();
    }

    // Create alert element
    const alert = document.createElement('div');
    alert.className = `custom-alert ${type}`;
    
    const icon = type === 'success' ? '✓' : 
                 type === 'error' ? '✗' : 
                 type === 'warning' ? '⚠' : 'ℹ';
    
    alert.innerHTML = `
        <div class="alert-content">
            <span class="alert-icon">${icon}</span>
            <span class="alert-message">${message}</span>
            <button class="alert-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
    `;
    
    document.body.appendChild(alert);
    
    // Add show animation
    setTimeout(() => alert.classList.add('show'), 10);
    
    // Auto remove after duration
    if (duration > 0) {
        setTimeout(() => {
            if (alert.parentElement) {
                alert.classList.remove('show');
                setTimeout(() => alert.remove(), 300);
            }
        }, duration);
    }
    
    return alert;
}

// Enhanced Input field validation styling
function setupInputValidation() {
    const inputs = document.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.classList.add('focused');
        });
        
        input.addEventListener('blur', function() {
            this.classList.remove('focused');
            if (this.value.trim()) {
                this.classList.add('dirty');
            }
        });
        
        // Live validation for required fields
        if (input.hasAttribute('required')) {
            input.addEventListener('input', function() {
                if (this.value.trim()) {
                    this.classList.remove('error');
                    this.classList.add('valid');
                } else {
                    this.classList.remove('valid');
                }
            });
        }
    });
}

// Form submission handler with loading states
function handleFormSubmit(form, callback) {
    const submitButton = form.querySelector('button[type="submit"]');
    const originalText = submitButton.innerHTML;
    
    form.addEventListener('submit', function(e) {
        if (callback && !callback(e)) {
            return false;
        }
        
        // Show loading state
        submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        submitButton.disabled = true;
        
        // Re-enable button after 5 seconds (safety net)
        setTimeout(() => {
            submitButton.innerHTML = originalText;
            submitButton.disabled = false;
        }, 5000);
    });
}

// Initialize enhanced form validation styles
function setupEnhancedValidationStyles() {
    const enhancedStyles = `
        .error {
            border-color: #ff4757 !important;
            background-color: #fff5f5;
        }
        
        .valid {
            border-color: #2ed573 !important;
            background-color: #f8fff9;
        }
        
        .focused {
            border-color: #667eea !important;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .field-error {
            color: #ff4757;
            font-size: 0.8em;
            margin-top: 5px;
            display: block;
            animation: slideDown 0.3s ease;
        }
        
        .password-feedback {
            font-size: 0.8em;
            margin-top: 5px;
            display: block;
            animation: slideDown 0.3s ease;
        }
        
        .password-feedback.match {
            color: #2ed573;
        }
        
        .password-feedback.no-match {
            color: #ff4757;
        }
        
        .password-feedback.checking {
            color: #667eea;
        }
        
        .password-feedback.weak { color: #ff4757; }
        .password-feedback.medium { color: #ffa502; }
        .password-feedback.strong { color: #2ed573; }
        
        .strength-bar {
            height: 4px;
            border-radius: 2px;
            margin-top: 5px;
            transition: all 0.3s ease;
            width: 0%;
        }
        
        .strength-weak { background: #ff4757; }
        .strength-medium { background: #ffa502; }
        .strength-strong { background: #2ed573; }
        
        .expired {
            opacity: 0.6;
            background-color: #f8f9fa;
        }
        
        .expired-badge {
            background: #ff4757;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        
        .custom-alert {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            z-index: 10000;
            min-width: 300px;
            max-width: 500px;
            transform: translateX(400px);
            opacity: 0;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .custom-alert.show {
            transform: translateX(0);
            opacity: 1;
        }
        
        .custom-alert.success {
            background: #2ed573;
            border-left: 4px solid #1e9050;
        }
        
        .custom-alert.error {
            background: #ff4757;
            border-left: 4px solid #cc2e3d;
        }
        
        .custom-alert.warning {
            background: #ffa502;
            border-left: 4px solid #cc8400;
        }
        
        .custom-alert.info {
            background: #667eea;
            border-left: 4px solid #4a5fc9;
        }
        
        .custom-alert .alert-content {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .alert-icon {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .alert-message {
            flex: 1;
        }
        
        .alert-close {
            background: none;
            border: none;
            color: inherit;
            font-size: 1.2em;
            cursor: pointer;
            margin-left: auto;
            opacity: 0.8;
            transition: opacity 0.2s;
        }
        
        .alert-close:hover {
            opacity: 1;
        }
        
        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-5px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(400px);
                opacity: 0;
            }
        }
        
        /* Loading state for buttons */
        .btn-loading {
            position: relative;
            color: transparent !important;
        }
        
        .btn-loading::after {
            content: '';
            position: absolute;
            width: 16px;
            height: 16px;
            top: 50%;
            left: 50%;
            margin-left: -8px;
            margin-top: -8px;
            border: 2px solid #ffffff;
            border-radius: 50%;
            border-right-color: transparent;
            animation: spin 0.8s linear infinite;
        }
        
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        /* Form row styling for date/time inputs */
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        
        @media (max-width: 768px) {
            .form-row {
                grid-template-columns: 1fr;
            }
        }
    `;
    
    // Only add styles if they haven't been added already
    if (!document.getElementById('enhanced-validation-styles')) {
        const styleSheet = document.createElement('style');
        styleSheet.id = 'enhanced-validation-styles';
        styleSheet.textContent = enhancedStyles;
        document.head.appendChild(styleSheet);
    }
}

// Utility function to show loading state on any button
function setButtonLoading(button, isLoading) {
    if (isLoading) {
        button.classList.add('btn-loading');
        button.disabled = true;
    } else {
        button.classList.remove('btn-loading');
        button.disabled = false;
    }
}

// Export functions for global access (if using modules)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        validateLoginForm,
        validateRegistrationForm,
        validateSessionForm,
        validateNewSessionForm,
        validateSessionCodeForm,
        showAlert,
        setButtonLoading
    };
}