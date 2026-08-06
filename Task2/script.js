/**
 * CipherVault - Encryption & Decryption Engine
 * Implements Caesar Cipher and ROT13 logic
 */

document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const cipherTabs = document.querySelectorAll('.cipher-tab');
    const caesarSettings = document.getElementById('caesar-settings');
    const shiftInput = document.getElementById('shift-input');
    const shiftValueDisplay = document.getElementById('shift-value-display');
    
    const btnModeEncrypt = document.getElementById('btn-mode-encrypt');
    const btnModeDecrypt = document.getElementById('btn-mode-decrypt');
    const preserveCaseCb = document.getElementById('preserve-case');
    const keepNonAlphaCb = document.getElementById('keep-non-alpha');

    const userInput = document.getElementById('user-input');
    const userOutput = document.getElementById('user-output');
    const inputLabelText = document.getElementById('input-label-text');
    const outputLabelText = document.getElementById('output-label-text');
    
    const btnClear = document.getElementById('btn-clear');
    const btnPaste = document.getElementById('btn-paste');
    const btnCopy = document.getElementById('btn-copy');
    const btnSwap = document.getElementById('btn-swap');
    
    const inputCharCount = document.getElementById('input-char-count');
    const inputWordCount = document.getElementById('input-word-count');
    const outputCharCount = document.getElementById('output-char-count');
    const statusTag = document.getElementById('status-tag');
    
    const plainAlphabetContainer = document.getElementById('plain-alphabet');
    const cipherAlphabetContainer = document.getElementById('cipher-alphabet');
    const shiftArrowText = document.getElementById('shift-arrow-text');
    const stepsGrid = document.getElementById('steps-grid');

    // Current State
    let state = {
        cipher: 'caesar', // 'caesar', 'rot13'
        mode: 'encrypt',  // 'encrypt', 'decrypt'
        shift: 3,
        preserveCase: true,
        keepNonAlpha: true,
        text: 'Hello, World!'
    };

    // Initialize UI
    userInput.value = state.text;
    buildAlphabetStrips();
    processText();

    // Event Listeners - Cipher Tabs
    cipherTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            cipherTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            state.cipher = tab.dataset.cipher;

            if (state.cipher === 'caesar') {
                caesarSettings.classList.remove('hidden');
            } else if (state.cipher === 'rot13') {
                caesarSettings.classList.add('hidden');
            }

            renderVisualizer();
            processText();
        });
    });

    // Event Listeners - Shift Slider
    shiftInput.addEventListener('input', (e) => {
        state.shift = parseInt(e.target.value, 10);
        shiftValueDisplay.textContent = state.shift;
        renderVisualizer();
        processText();
    });

    // Mode Toggles (Encrypt / Decrypt)
    btnModeEncrypt.addEventListener('click', () => {
        setMode('encrypt');
    });

    btnModeDecrypt.addEventListener('click', () => {
        setMode('decrypt');
    });

    function setMode(mode) {
        state.mode = mode;
        if (mode === 'encrypt') {
            btnModeEncrypt.classList.add('active');
            btnModeDecrypt.classList.remove('active');
            inputLabelText.textContent = 'Plaintext (Original Message)';
            outputLabelText.textContent = 'Ciphertext (Encrypted Message)';
            statusTag.textContent = 'Encrypted';
            statusTag.style.borderColor = 'rgba(168, 85, 247, 0.3)';
            statusTag.style.color = 'var(--accent-purple)';
        } else {
            btnModeDecrypt.classList.add('active');
            btnModeEncrypt.classList.remove('active');
            inputLabelText.textContent = 'Ciphertext (Encrypted Message)';
            outputLabelText.textContent = 'Plaintext (Decrypted Message)';
            statusTag.textContent = 'Decrypted';
            statusTag.style.borderColor = 'rgba(16, 185, 129, 0.3)';
            statusTag.style.color = 'var(--accent-teal)';
        }
        renderVisualizer();
        processText();
    }

    // Checkboxes
    preserveCaseCb.addEventListener('change', (e) => {
        state.preserveCase = e.target.checked;
        processText();
    });

    keepNonAlphaCb.addEventListener('change', (e) => {
        state.keepNonAlpha = e.target.checked;
        processText();
    });

    // User Text Input
    userInput.addEventListener('input', (e) => {
        state.text = e.target.value;
        processText();
    });

    // Action Buttons
    btnClear.addEventListener('click', () => {
        userInput.value = '';
        state.text = '';
        processText();
    });

    btnPaste.addEventListener('click', async () => {
        try {
            const text = await navigator.clipboard.readText();
            userInput.value = text;
            state.text = text;
            processText();
        } catch (err) {
            console.warn('Clipboard read failed:', err);
        }
    });

    btnCopy.addEventListener('click', () => {
        if (!userOutput.value) return;
        navigator.clipboard.writeText(userOutput.value);
        const tooltip = btnCopy.querySelector('.copy-tooltip');
        tooltip.classList.add('show');
        setTimeout(() => tooltip.classList.remove('show'), 2000);
    });

    btnSwap.addEventListener('click', () => {
        const temp = userInput.value;
        userInput.value = userOutput.value;
        state.text = userOutput.value;
        userOutput.value = temp;
        // Swap mode
        setMode(state.mode === 'encrypt' ? 'decrypt' : 'encrypt');
    });

    // --- Core Cryptographic Logic --- //

    function processText() {
        const text = state.text;
        let result = '';

        if (state.cipher === 'caesar') {
            const shift = state.mode === 'encrypt' ? state.shift : (26 - (state.shift % 26)) % 26;
            result = caesarCipher(text, shift);
        } else if (state.cipher === 'rot13') {
            result = caesarCipher(text, 13);
        }

        userOutput.value = result;

        // Update counts
        inputCharCount.textContent = `${text.length} character${text.length !== 1 ? 's' : ''}`;
        const words = text.trim() ? text.trim().split(/\s+/).length : 0;
        inputWordCount.textContent = `${words} word${words !== 1 ? 's' : ''}`;
        outputCharCount.textContent = `${result.length} character${result.length !== 1 ? 's' : ''}`;

        renderStepsBreakdown(text, result);
    }

    /**
     * Caesar Cipher algorithm implementation
     */
    function caesarCipher(str, shift) {
        let output = '';
        for (let i = 0; i < str.length; i++) {
            let char = str[i];

            if (char.match(/[a-z]/i)) {
                const code = str.charCodeAt(i);
                // Uppercase letters
                if (code >= 65 && code <= 90) {
                    let shiftedCode = ((code - 65 + shift) % 26) + 65;
                    char = String.fromCharCode(shiftedCode);
                    if (!state.preserveCase) char = char.toLowerCase();
                }
                // Lowercase letters
                else if (code >= 97 && code <= 122) {
                    let shiftedCode = ((code - 97 + shift) % 26) + 97;
                    char = String.fromCharCode(shiftedCode);
                    if (!state.preserveCase) char = char.toLowerCase();
                }
            } else {
                if (!state.keepNonAlpha) {
                    continue; // Skip punctuation/space if disabled
                }
            }
            output += char;
        }
        return output;
    }

    // --- Visualizer Rendering --- //

    function buildAlphabetStrips() {
        plainAlphabetContainer.innerHTML = '';
        cipherAlphabetContainer.innerHTML = '';

        for (let i = 0; i < 26; i++) {
            const letter = String.fromCharCode(65 + i);

            const cellPlain = document.createElement('div');
            cellPlain.className = 'char-cell';
            cellPlain.id = `plain-cell-${i}`;
            cellPlain.textContent = letter;
            plainAlphabetContainer.appendChild(cellPlain);

            const cellCipher = document.createElement('div');
            cellCipher.className = 'char-cell';
            cellCipher.id = `cipher-cell-${i}`;
            cellCipher.textContent = letter;
            cipherAlphabetContainer.appendChild(cellCipher);
        }
    }

    function renderVisualizer() {
        let activeShift = 0;

        if (state.cipher === 'caesar') {
            activeShift = state.mode === 'encrypt' ? state.shift : (26 - (state.shift % 26)) % 26;
            shiftArrowText.textContent = `↓ Shifted by ${state.mode === 'encrypt' ? '+' : '-'}${state.shift} positions ↓`;
        } else if (state.cipher === 'rot13') {
            activeShift = 13;
            shiftArrowText.textContent = `↓ ROT13 Fixed 13-Position Shift ↓`;
        }

        for (let i = 0; i < 26; i++) {
            const shiftedIdx = (i + activeShift) % 26;
            const cipherCell = document.getElementById(`cipher-cell-${i}`);
            if (cipherCell) {
                cipherCell.textContent = String.fromCharCode(65 + shiftedIdx);
            }
        }
    }

    function renderStepsBreakdown(inputText, outputText) {
        stepsGrid.innerHTML = '';
        const limit = Math.min(inputText.length, 8); // Display first 8 characters sample

        for (let i = 0; i < limit; i++) {
            const inChar = inputText[i];
            const outChar = outputText[i] || '';

            if (!inChar.match(/[a-z]/i)) continue; // skip punctuation for step display

            const stepCard = document.createElement('div');
            stepCard.className = 'step-card';

            const inCode = inChar.toUpperCase().charCodeAt(0) - 65;
            const outCode = outChar.toUpperCase().charCodeAt(0) - 65;

            stepCard.innerHTML = `
                <span class="src-char">${inChar}</span>
                <span class="arrow">→</span>
                <span class="dest-char">${outChar}</span>
                <span class="math-info">(${inCode} ➔ ${outCode})</span>
            `;

            stepsGrid.appendChild(stepCard);
        }

        if (stepsGrid.children.length === 0) {
            stepsGrid.innerHTML = '<span style="color: var(--text-dim); font-size: 0.85rem;">Type letters in the input box to see character transformations...</span>';
        }
    }
});
