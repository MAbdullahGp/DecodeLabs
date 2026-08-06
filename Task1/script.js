document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const passwordInput = document.getElementById('password-input');
    const toggleVisibilityBtn = document.getElementById('toggle-visibility-btn');
    const eyeIcon = document.getElementById('eye-icon');
    const eyeOffIcon = document.getElementById('eye-off-icon');
    const copyBtn = document.getElementById('copy-btn');
    
    const strengthBadge = document.getElementById('strength-badge');
    const meterFill = document.getElementById('meter-fill');
    const scoreText = document.getElementById('score-text');
    const entropyText = document.getElementById('entropy-text');
    const crackTime = document.getElementById('crack-time');
    const recommendationText = document.getElementById('recommendation-text');

    const chkLen8 = document.getElementById('chk-len8');
    const chkLen12 = document.getElementById('chk-len12');
    const chkUpper = document.getElementById('chk-upper');
    const chkLower = document.getElementById('chk-lower');
    const chkDigit = document.getElementById('chk-digit');
    const chkSymbol = document.getElementById('chk-symbol');

    const lengthSlider = document.getElementById('length-slider');
    const lengthVal = document.getElementById('length-val');
    const generateBtn = document.getElementById('generate-btn');
    const toast = document.getElementById('toast');

    // Common weak password dictionary
    const COMMON_PASSWORDS = [
        'password', '123456', '123456789', 'qwerty', '12345678', '111111', 
        '1234567', 'dragon', 'welcome', '123123', 'admin', 'letmein', 'monkey'
    ];

    // Toggle Password Visibility
    toggleVisibilityBtn.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        eyeIcon.classList.toggle('hidden', isPassword);
        eyeOffIcon.classList.toggle('hidden', !isPassword);
    });

    // Copy Password
    copyBtn.addEventListener('click', () => {
        const val = passwordInput.value;
        if (!val) return;
        
        navigator.clipboard.writeText(val).then(() => {
            showToast('Copied to clipboard!');
        }).catch(() => {
            // Fallback for clipboard API if needed
            passwordInput.select();
            document.execCommand('copy');
            showToast('Copied to clipboard!');
        });
    });

    // Toast notification
    function showToast(msg) {
        toast.textContent = msg;
        toast.classList.remove('hidden');
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 2000);
    }

    // Slider sync
    lengthSlider.addEventListener('input', (e) => {
        lengthVal.textContent = e.target.value;
    });

    // Generate Strong Password
    generateBtn.addEventListener('click', () => {
        const len = parseInt(lengthSlider.value, 10);
        const generated = generateStrongPassword(len);
        passwordInput.value = generated;
        analyzePassword();
    });

    function generateStrongPassword(length) {
        const lowers = 'abcdefghijklmnopqrstuvwxyz';
        const uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const digits = '0123456789';
        const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        let chars = [
            lowers[Math.floor(Math.random() * lowers.length)],
            uppers[Math.floor(Math.random() * uppers.length)],
            digits[Math.floor(Math.random() * digits.length)],
            symbols[Math.floor(Math.random() * symbols.length)]
        ];

        const all = lowers + uppers + digits + symbols;
        for (let i = 4; i < length; i++) {
            chars.push(all[Math.floor(Math.random() * all.length)]);
        }

        // Shuffle array using Crypto API if available, else Math.random
        for (let i = chars.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [chars[i], chars[j]] = [chars[j], chars[i]];
        }

        return chars.join('');
    }

    // Calculate Entropy in bits
    function calculateEntropy(pwd) {
        let pool = 0;
        if (/[a-z]/.test(pwd)) pool += 26;
        if (/[A-Z]/.test(pwd)) pool += 26;
        if (/[0-9]/.test(pwd)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;

        if (pool === 0 || pwd.length === 0) return 0;
        return Math.round(pwd.length * Math.log2(pool) * 10) / 10;
    }

    // Estimate crack time based on entropy
    function estimateCrackTime(entropy) {
        if (entropy === 0) return 'Instant';
        if (entropy < 28) return 'Instant (< 1 sec)';
        if (entropy < 36) return 'Few seconds';
        if (entropy < 44) return 'A few minutes to hours';
        if (entropy < 56) return 'Several days to weeks';
        if (entropy < 70) return 'Months to several years';
        if (entropy < 85) return 'Decades to centuries';
        return 'Millions of years';
    }

    // Main Password Analysis Logic
    function analyzePassword() {
        const pwd = passwordInput.value;
        const len = pwd.length;

        if (len === 0) {
            resetUI();
            return;
        }

        const hasLower = /[a-z]/.test(pwd);
        const hasUpper = /[A-Z]/.test(pwd);
        const hasDigit = /[0-9]/.test(pwd);
        const hasSymbol = /[^a-zA-Z0-9]/.test(pwd);
        const isCommon = COMMON_PASSWORDS.includes(pwd.toLowerCase());

        let typesCount = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
        let entropy = calculateEntropy(pwd);

        // Update Checklist UI
        updateChecklistItem(chkLen8, len >= 8);
        updateChecklistItem(chkLen12, len >= 12);
        updateChecklistItem(chkUpper, hasUpper);
        updateChecklistItem(chkLower, hasLower);
        updateChecklistItem(chkDigit, hasDigit);
        updateChecklistItem(chkSymbol, hasSymbol);

        // Scoring algorithm (0-100)
        let score = 0;

        // Length component (up to 40)
        if (len >= 16) score += 40;
        else if (len >= 12) score += 30;
        else if (len >= 8) score += 20;
        else if (len >= 6) score += 10;
        else score += 5;

        // Diversity component (up to 40)
        score += typesCount * 10;

        // Bonus for length + variety (up to 20)
        if (len >= 10 && typesCount >= 3) score += 10;
        if (len >= 12 && typesCount === 4) score += 10;

        // Penalties
        if (isCommon) score = 10;
        else if (len < 6) score = Math.min(score, 20);

        // Clamped Score
        score = Math.min(100, Math.max(0, score));

        // Stats Display
        scoreText.textContent = `Score: ${score} / 100`;
        entropyText.textContent = `Entropy: ${entropy} bits`;
        crackTime.textContent = isCommon ? 'Instant (Common Word!)' : estimateCrackTime(entropy);

        // Recommendation & Badge Logic
        let level = 'weak';
        let badgeLabel = 'Weak';
        let recommendation = '';

        if (isCommon) {
            level = 'weak';
            badgeLabel = 'Weak (Common)';
            recommendation = 'Avoid using predictable dictionary words or common phrases!';
        } else if (score < 45 || len < 8 || typesCount < 2) {
            level = 'weak';
            badgeLabel = 'Weak';
            recommendation = len < 8 ? 'Increase length to at least 8 characters.' : 'Add numbers and symbols for better variety.';
        } else if (score < 75 || typesCount < 3 || len < 10) {
            level = 'medium';
            badgeLabel = 'Medium';
            recommendation = 'Good start! Make it 12+ characters and add special characters to reach Strong.';
        } else if (score < 90 || len < 14) {
            level = 'strong';
            badgeLabel = 'Strong';
            recommendation = 'Great password! Meets strong security standards.';
        } else {
            level = 'super';
            badgeLabel = 'Super Strong';
            recommendation = 'Excellent! Highly resistant to brute-force attacks.';
        }

        // Apply Styles
        strengthBadge.className = `badge badge-${level}`;
        strengthBadge.textContent = badgeLabel;

        meterFill.style.width = `${Math.max(5, score)}%`;
        if (level === 'weak') {
            meterFill.style.backgroundColor = 'var(--color-weak)';
            meterFill.style.boxShadow = '0 0 10px rgba(239, 68, 68, 0.5)';
        } else if (level === 'medium') {
            meterFill.style.backgroundColor = 'var(--color-medium)';
            meterFill.style.boxShadow = '0 0 10px rgba(245, 158, 11, 0.5)';
        } else if (level === 'strong') {
            meterFill.style.backgroundColor = 'var(--color-strong)';
            meterFill.style.boxShadow = '0 0 10px rgba(16, 185, 129, 0.5)';
        } else {
            meterFill.style.backgroundColor = 'var(--color-super)';
            meterFill.style.boxShadow = '0 0 10px rgba(6, 182, 212, 0.5)';
        }

        recommendationText.textContent = recommendation;
        recommendationText.classList.remove('text-subtle');
    }

    function updateChecklistItem(el, isValid) {
        const icon = el.querySelector('.chk-icon');
        if (isValid) {
            el.classList.add('valid');
            icon.textContent = '✓';
        } else {
            el.classList.remove('valid');
            icon.textContent = '✕';
        }
    }

    function resetUI() {
        strengthBadge.className = 'badge badge-empty';
        strengthBadge.textContent = 'None';
        meterFill.style.width = '0%';
        meterFill.style.boxShadow = 'none';
        scoreText.textContent = 'Score: 0 / 100';
        entropyText.textContent = 'Entropy: 0 bits';
        crackTime.textContent = 'Instant';
        recommendationText.textContent = 'Enter a password to analyze.';
        recommendationText.classList.add('text-subtle');

        [chkLen8, chkLen12, chkUpper, chkLower, chkDigit, chkSymbol].forEach(el => updateChecklistItem(el, false));
    }

    // Input Event Listeners
    passwordInput.addEventListener('input', analyzePassword);

    // Initial Trigger
    analyzePassword();
});
