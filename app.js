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

  function countCharsets(password) {
    let count = 0;
    if (/[A-Z]/.test(password)) count++; // uppercases
    if (/[a-z]/.test(password)) count++; // lowercases
    if (/[0-9]/.test(password)) count++; // numbers
    if (/[^A-Za-z0-9]/.test(password)) count++; // symbols
    return count;
  }

  // UPDATE STRENGTH
  function updateStrengthUI(password) {
    const leds = document.querySelectorAll(".strength-leds .led");
    const labelEl = document.querySelector(".strength-label");
    if (!leds.length || !labelEl) return;

    // Reset classes
    leds.forEach(led => {
      led.classList.remove("active", "too-weak", "weak", "medium", "strong");
    });
    labelEl.classList.remove("too-weak", "weak", "medium", "strong");

    if (!password || password.length === 0) {
      labelEl.textContent = "";
      return;
    }

    const len = password.length;
    const charsets = countCharsets(password);

    
    let level = "too-weak";

    if (len <= 3) {
      level = "too-weak";
    } else if (len === 4) {
      level = (charsets >= 2) ? "weak" : "too-weak";
    } else if (len >= 5 && len <= 7) {
      if (charsets <= 2) level = "weak";
      else if (charsets === 3) level = "weak";
      else level = "medium"; 
    } else if (len >= 8 && len <= 10) {
      if (charsets <= 1) level = "weak";
      else if (charsets === 2) level = "medium";
      else if (charsets === 3) level = "medium";
      else level = "strong"; 
    } else {
      if (charsets <= 2) level = "medium";
      else level = "strong";
    }

    // --- Mapping label & LEDs ---
    const levelToLabel = {
      "too-weak": "TOO WEAK!",
      "weak": "WEAK",
      "medium": "MEDIUM",
      "strong": "STRONG"
    };

    const levelToLeds = {
      "too-weak": 1,
      "weak": 2,
      "medium": 3,
      "strong": 4
    };

    const ledsToActivate = levelToLeds[level] || 1;

    for (let i = 0; i < ledsToActivate && i < leds.length; i++) {
      leds[i].classList.add("active", level);
    }

    labelEl.textContent = levelToLabel[level] || "";
    labelEl.classList.add(level);
  }

  function calculatePasswordScore(pwd) {
    let score = 0;

    score += Math.min(40, pwd.length * 4);

    if (/[A-Z]/.test(pwd)) score += 10;
    if (/[a-z]/.test(pwd)) score += 10;
    if (/[0-9]/.test(pwd)) score += 10;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 10;

    const typeCount =
      [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(r => r.test(pwd)).length;

    if (typeCount >= 3) score += 10;

    if (/(.)\1{1,}/.test(pwd)) score -= 10;

    if (/abc|123|abcd|qwerty|xyz|000/.test(pwd.toLowerCase())) score -= 15;

    return Math.max(0, score);
  }

  function calculateEntropy(password) {
    if (!password) return 0;

    const len = password.length;
    const freq = {};

    for (const char of password) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }

    return entropy * len;
  }

  function detectPatterns(password) {
    let penalty = 0;

    if (!password) return 0;

    const repeatRegex = /(.)\1{2,}/g;
    if (repeatRegex.test(password)) {
      penalty += 10;
    }

    const sequences = [
      "abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "0123456789",
      "qwertyuiopasdfghjklzxcvbnm"
    ];

    const lower = password.toLowerCase();

    sequences.forEach(seq => {
      for (let i = 0; i < seq.length - 2; i++) {
        const forward = seq.slice(i, i + 3);
        const backward = forward.split("").reverse().join("");

        if (lower.includes(forward) || lower.includes(backward)) {
          penalty += 15;
        }
      }
    });

    return penalty;
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
