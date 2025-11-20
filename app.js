// Password Generator
(() => {
  // Elements
  const inputPassword = document.getElementById('password');
  const lengthRange = document.getElementById('length');
  const lengthOutput = document.getElementById('length-value');
  const btnGenerate = document.querySelector('.btn-generate');
  const btnCopy = document.querySelector('.btn-copy');

  // Checkbox options
  const cbUpper = document.getElementById('include-uppercase');
  const cbLower = document.getElementById('include-lowercase');
  const cbNumbers = document.getElementById('include-numbers');
  const cbSymbols = document.getElementById('include-symbols');
  const cbExcludeSimilar = document.getElementById('exclude-similar');
  const cbExcludeAmbiguous = document.getElementById('exclude-ambiguous');

  let hasGeneratedOnce = false;

  const DEFAULT_PWD = "P4$5W0rD!";

  const SETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-={}[]|;:,.<>?/~'
  };

  const SIMILAR_CHARS = new Set(['i', 'I', 'l', 'L', '1', 'o', 'O', '0', 's', 'S', '5', 'z', 'Z', '2', 'b', 'B', '8', 'g', 'q', '9', 't', 'T', '+']);
  const AMBIGUOUS = new Set(['{', '}', '[', ']', '(', ')', '/', '\\', "'", '"', '', '~', ',', ';', ':', '<', '>']);

  // Secure random integer
  function randomInt(max) {
    const arr = new Uint32Array(1);
    window.crypto.getRandomValues(arr);
    return arr[0] % max;
  }

  // Get selected character types
  function getSelectedCharacterTypes() {
    return {
      includeUppercase: cbUpper.checked,
      includeLowercase: cbLower.checked,
      includeNumbers: cbNumbers.checked,
      includeSymbols: cbSymbols.checked,
      excludeSimilar: cbExcludeSimilar.checked,
      excludeAmbiguous: cbExcludeAmbiguous.checked
    };
  }

  // Generate password
  function generatePassword(options, length) {
    let pool = '';
    if (options.includeUppercase) pool += SETS.upper;
    if (options.includeLowercase) pool += SETS.lower;
    if (options.includeNumbers) pool += SETS.numbers;
    if (options.includeSymbols) pool += SETS.symbols;

    if (options.excludeSimilar) pool = [...pool].filter(c => !SIMILAR_CHARS.has(c)).join('');
    if (options.excludeAmbiguous) pool = [...pool].filter(c => !AMBIGUOUS.has(c)).join('');

    if (!pool.length) return '';

    const mandatory = [];
    if (options.includeUppercase) mandatory.push([...SETS.upper].filter(c => pool.includes(c))[randomInt([...SETS.upper].filter(c => pool.includes(c)).length)]);
    if (options.includeLowercase) mandatory.push([...SETS.lower].filter(c => pool.includes(c))[randomInt([...SETS.lower].filter(c => pool.includes(c)).length)]);
    if (options.includeNumbers) mandatory.push([...SETS.numbers].filter(c => pool.includes(c))[randomInt([...SETS.numbers].filter(c => pool.includes(c)).length)]);
    if (options.includeSymbols) mandatory.push([...SETS.symbols].filter(c => pool.includes(c))[randomInt([...SETS.symbols].filter(c => pool.includes(c)).length)]);

    const remainingLength = Math.max(0, length - mandatory.length);
    const passwordChars = [...mandatory];
    for (let i = 0; i < remainingLength; i++) passwordChars.push(pool[randomInt(pool.length)]);

    // Shuffle
    for (let i = passwordChars.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
    }

    return passwordChars.join('');
  }

  // Display error
  function displayErrorMessage(msg) {
    const box = document.querySelector('.error-box');
    if (!box) return;
    box.textContent = msg;
    box.hidden = false;
    box.classList.add('show');
    box.classList.remove('shake');
    void box.offsetWidth;
    box.classList.add('shake');
  }

  // Hide error
  function hideErrorMessage() {
    const box = document.querySelector('.error-box');
    if (!box) return;
    box.hidden = true;
    box.classList.remove('show', 'shake');
  }

  // Validate form (only on Generate)
  function validateForm() {
    const options = getSelectedCharacterTypes();
    const length = parseInt(lengthRange.value);

    if (!options.includeUppercase && !options.includeLowercase && !options.includeNumbers && !options.includeSymbols) {
      displayErrorMessage("Please select at least one character type.");
      return false;
    }

    if (length < 4) {
      displayErrorMessage("Password length must be at least 4 characters.");
      return false;
    }

    hideErrorMessage();
    return true;
  }

  // Update password color
  function updatePasswordColor(password) {
    inputPassword.style.color = password ? 'var(--grey-200)' : 'var(--grey-700)';
  }


  /* ============================================
   PASSWORD STRENGTH SYSTEM — FINAL STRICT VERSION
   ============================================ */

  /* Charset counter (UI + logic reuse) */
  function countCharsets(password) {
    let count = 0;
    if (/[A-Z]/.test(password)) count++;
    if (/[a-z]/.test(password)) count++;
    if (/[0-9]/.test(password)) count++;
    if (/[^A-Za-z0-9]/.test(password)) count++;
    return count;
  }

  /* Small blacklist */
  const COMMON_PASSWORDS = new Set([
    "123456", "password", "12345678", "qwerty", "abc123", "111111", "123456789",
    "12345", "1234", "password1", "iloveyou", "admin", "letmein", "welcome", "monkey",
    "login", "princess", "qwerty123", "sunshine", "dragon"
  ]);

  /* Charset size approx */
  function estimateCharsetSize(password) {
    let size = 0;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigits = /[0-9]/.test(password);
    const hasSymbols = /[^A-Za-z0-9]/.test(password);

    if (hasLower) size += 26;
    if (hasUpper) size += 26;
    if (hasDigits) size += 10;
    if (hasSymbols) size += 33;

    return Math.max(1, size);
  }

  /* Raw entropy */
  function rawEntropy(password) {
    const L = password.length;
    const charset = estimateCharsetSize(password);
    return L * Math.log2(charset);
  }

  /* Penalties */
  function patternPenalties(password) {
    if (!password) return 0;
    let p = 0;
    const low = password.toLowerCase();

    if (/(.)\1{2,}/.test(password)) p += 12;   // aaa, 1111
    if (/([a-z0-9])(.{0,2})\1\2\1/.test(low)) p += 8; // abababa
    if (/(abc|abcd|password|123|012|qwerty|asdf|zxc)/.test(low)) p += 18;
    if (/(qwerty|asdfgh|zxcvbn|1qaz|2wsx)/.test(low)) p += 12;
    if (/(0123|1234|2345|3456|4567|5678|6789)/.test(low)) p += 12;

    return p;
  }

  function diversityPenalty(password) {
    const c = countCharsets(password);
    if (c === 1) return 10;
    if (c === 2) return 4;
    return 0;
  }

  /* Final entropy */
  function finalEntropy(password) {
    const base = rawEntropy(password);
    const penalties = patternPenalties(password) + diversityPenalty(password);
    return Math.max(0, base - penalties);
  }

  /* Blacklist and numeric easy cases */
  function isBlacklisted(password) {
    return COMMON_PASSWORDS.has(password.toLowerCase());
  }

  /* ---------------------------------------------------
     MAIN ASSESSOR — FINAL STRICT RULES
     --------------------------------------------------- */
  function assessPassword(password) {
    const L = password.length;

    // Character sets detected
    const sets = {
      lower: /[a-z]/.test(password),
      upper: /[A-Z]/.test(password),
      digit: /[0-9]/.test(password),
      symbol: /[^A-Za-z0-9]/.test(password)
    };

    const charsetSize =
      (sets.lower ? 26 : 0) +
      (sets.upper ? 26 : 0) +
      (sets.digit ? 10 : 0) +
      (sets.symbol ? 33 : 0);

    const typeCount =
      (sets.lower ? 1 : 0) +
      (sets.upper ? 1 : 0) +
      (sets.digit ? 1 : 0) +
      (sets.symbol ? 1 : 0);

    // Estimate entropy (classic Shannon log2(charset^L))
    const entropy = charsetSize > 0 ? Math.floor(L * Math.log2(charsetSize)) : 0;

    // ============================
    //    NIST-STRICT CLASSIFIER
    // ============================

    // TOO WEAK (anything < 8 chars)
    if (L < 8 || typeCount === 0) {
      return {
        level: "too-weak",
        label: "TOO WEAK!",
        leds: 1,
        entropy
      };
    }

    // WEAK: small charset or insufficient complexity
    if (typeCount === 1 || L < 10 || entropy < 30) {
      return {
        level: "weak",
        label: "WEAK",
        leds: 2,
        entropy
      };
    }

    // MEDIUM: moderate complexity
    if (typeCount >= 2 && L >= 10 && entropy >= 30 && entropy < 70) {
      return {
        level: "medium",
        label: "MEDIUM",
        leds: 3,
        entropy
      };
    }

    // STRONG: NIST-like strong password
    if (typeCount === 4 && L >= 12 && entropy >= 70) {
      return {
        level: "strong",
        label: "STRONG",
        leds: 4,
        entropy
      };
    }

    // Default fallback (rare)
    return {
      level: "medium",
      label: "MEDIUM",
      leds: 3,
      entropy
    };
  }

  /* ---------------------------------------------------
     UPDATE STRENGTH  
     --------------------------------------------------- */
  function updateStrengthUI(password) {
    const leds = document.querySelectorAll(".strength-leds .led");
    const labelEl = document.querySelector(".strength-label");

    if (!leds.length || !labelEl) return;

    // Reset global classes
    labelEl.classList.remove("too-weak", "weak", "medium", "strong");

    leds.forEach(led => {
      led.classList.remove("active", "too-weak", "weak", "medium", "strong", "turning-off", "animate");
    });

    if (!password) {
      labelEl.textContent = "";
      return;
    }

    const result = assessPassword(password);
    labelEl.textContent = result.label;
    labelEl.classList.add(result.level);

    // Light LEDs with animation
    for (let i = 0; i < result.leds; i++) {
      const led = leds[i];
      if (!led) continue;

      // restart animation
      led.classList.remove("animate");
      void led.offsetWidth;

      led.classList.add("active", result.level, "animate");
    }

    // Turning off LEDs above the new count
    for (let i = result.leds; i < leds.length; i++) {
      const led = leds[i];
      if (!led.classList.contains("active")) continue;

      led.classList.add("turning-off");
      setTimeout(() => led.classList.remove("turning-off", "active", "too-weak", "weak", "medium", "strong"), 380);
    }
  }

  // Generate button click
  function onGenerate(e) {
    e.preventDefault();
    hasGeneratedOnce = true;

    if (!validateForm()) return;

    const length = parseInt(lengthRange.value);
    const options = getSelectedCharacterTypes();
    const password = generatePassword(options, length);

    inputPassword.value = password;
    inputPassword.style.color = "var(--grey-200)";
    updatePasswordColor(password);
    updateStrengthUI(password);
  }

  // Range input
  function onRangeInput(e) {
    lengthOutput.textContent = e.target.value;
    const value = e.target.value;
    const min = e.target.min || 0;
    const max = e.target.max || 100;
    const percent = ((value - min) / (max - min)) * 100;
    e.target.style.background = `linear-gradient(to right, var(--green-200) ${percent}%, var(--grey-850) ${percent}%)`;
  }

  // Initialize
  function init() {
    if (!lengthRange || !lengthOutput || !inputPassword || !btnGenerate) return;

    lengthRange.value = 0;
    lengthOutput.textContent = 0;
    inputPassword.value = DEFAULT_PWD;
    inputPassword.style.color = "var(--grey-700)";


    lengthRange.addEventListener('input', onRangeInput);
    btnGenerate.addEventListener('click', onGenerate);

    if (btnCopy) {
      btnCopy.addEventListener('click', () => {
        if (!inputPassword.value) return;
        navigator.clipboard.writeText(inputPassword.value).then(() => {
          const copyStatus = document.querySelector('.copy-status');
          if (copyStatus) {
            copyStatus.style.opacity = '1';
            setTimeout(() => copyStatus.style.opacity = '0', 2000);
          }
        });
      });
    }
  }

  document.addEventListener('DOMContentLoaded', init);

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      inputPassword.value = DEFAULT_PWD;
      inputPassword.style.color = "var(--grey-700)";
    }
  });

  window.addEventListener('pagehide', () => {
    inputPassword.value = DEFAULT_PWD;
    inputPassword.style.color = "var(--grey-700)";
  });

  window.generatePassword = generatePassword;
})();
