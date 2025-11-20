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

  /* ---------------------------
   Professional strength module
   --------------------------- */

  /* Tiny blacklist (example). Replaced/extended with a real list in prod. */
  const COMMON_PASSWORDS = new Set([
    "123456", "password", "12345678", "qwerty", "abc123", "111111", "123456789",
    "12345", "1234", "password1", "iloveyou", "admin", "letmein", "welcome", "monkey",
    "login", "princess", "qwerty123", "sunshine", "dragon"
  ]);

  /* Estimate charset size more realistically */
  function estimateCharsetSize(password) {
    let size = 0;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigits = /[0-9]/.test(password);
    const hasSymbols = /[^A-Za-z0-9]/.test(password);

    if (hasLower) size += 26;
    if (hasUpper) size += 26;
    if (hasDigits) size += 10;
    if (hasSymbols) {
      // we approximate printable symbols set
      size += 33;
    }

    // Safety: if size 0 (shouldn't happen), return 1 to avoid log2(0)
    return Math.max(1, size);
  }

  /* Raw entropy: L * log2(charsetSize) */
  function rawEntropy(password) {
    const L = password.length;
    const charset = estimateCharsetSize(password);
    return L * Math.log2(charset);
  }

  /* Pattern penalties: returns number of bits to subtract */
  function patternPenalties(password) {
    if (!password) return 0;
    let penalty = 0;
    const lower = password.toLowerCase();

    // repeated characters or long runs (aaa, 1111)
    if (/(.)\1{2,}/.test(password)) penalty += 12; // repeated triple or more

    // short repeated groups (ababab)
    if (/([a-z0-9])(.{0,2})\1\2\1/.test(lower)) penalty += 8;

    // common sequences (abc, 123, qwerty, zxc)
    const seqRegex = /(abc|abcd|123|012|qwerty|asdf|zxc|password|letmein|iloveyou|admin)/;
    if (seqRegex.test(lower)) penalty += 18;

    // keyboard sequences common
    const keyboardSeq = /(qwerty|asdfgh|zxcvbn|1qaz|2wsx)/;
    if (keyboardSeq.test(lower)) penalty += 12;

    // ascending numeric long sequences
    if (/(0123|1234|2345|3456|4567|5678|6789)/.test(lower)) penalty += 12;

    return penalty;
  }

  /* Diversity penalty: if only 1 charset used, but long, apply a small penalty */
  function diversityPenalty(password) {
    let count = 0;
    if (/[a-z]/.test(password)) count++;
    if (/[A-Z]/.test(password)) count++;
    if (/[0-9]/.test(password)) count++;
    if (/[^A-Za-z0-9]/.test(password)) count++;
    if (count === 1) return 10;
    if (count === 2) return 4;
    return 0;
  }

  /* Final entropy estimate = rawEntropy - penalties (min 0) */
  function finalEntropy(password) {
    const raw = rawEntropy(password);
    const penalties = patternPenalties(password) + diversityPenalty(password);
    const finalE = Math.max(0, raw - penalties);
    return finalE;
  }

  /* NIST-aware check: blacklist, length rules */
  function isBlacklisted(password) {
    if (!password) return false;
    return COMMON_PASSWORDS.has(password.toLowerCase());
  }

  /* Main strength calculator returning an object */
  function assessPassword(password) {
    const len = password ? password.length : 0;
    const result = {
      label: "",
      level: "too-weak", // too-weak, weak, medium, strong
      leds: 1,
      entropy: 0,
      reasons: []
    };

    if (!password || len === 0) {
      result.label = "";
      result.level = "too-weak";
      result.leds = 0;
      result.entropy = 0;
      return result;
    }

    // 1) Blacklist => immediate too weak
    if (isBlacklisted(password) || /^\d+$/.test(password) && password.length <= 6) {
      result.label = "TOO WEAK!";
      result.level = "too-weak";
      result.leds = 1;
      result.entropy = finalEntropy(password);
      result.reasons.push("blacklist or simple number");
      return result;
    }

    // 2) For short passwords (< 8) stay conservative
    if (len < 4) {
      result.label = "TOO WEAK!";
      result.level = "too-weak";
      result.leds = 1;
      result.entropy = finalEntropy(password);
      result.reasons.push("too short");
      return result;
    }

    if (len >= 4 && len < 8) {
      // minimal checks: require >=2 charsets to avoid too-weak
      const charsetCount = countCharsets(password || "");
      if (len === 4 && charsetCount < 2) {
        result.label = "TOO WEAK!";
        result.level = "too-weak";
        result.leds = 1;
        result.entropy = finalEntropy(password);
        result.reasons.push("4 chars with low diversity");
        return result;
      }
      // Otherwise still weak or medium
      result.entropy = finalEntropy(password);
      if (result.entropy >= 30) {
        result.label = "MEDIUM";
        result.level = "medium";
        result.leds = 3;
      } else if (result.entropy >= 20) {
        result.label = "WEAK";
        result.level = "weak";
        result.leds = 2;
      } else {
        result.label = "TOO WEAK!";
        result.level = "too-weak";
        result.leds = 1;
      }
      return result;
    }

    // 3) For passwords >= 8 and especially >= 10 — use entropy + penalties
    const entropy = finalEntropy(password);
    result.entropy = entropy;

    // Thresholds (configurable)
    // We treat >=10 specially: require entropy >=60 for strong, else medium/weak
    if (len >= 10) {
      if (entropy >= 60) {
        result.label = "STRONG";
        result.level = "strong";
        result.leds = 4;
      } else if (entropy >= 45) {
        result.label = "MEDIUM";
        result.level = "medium";
        result.leds = 3;
      } else if (entropy >= 30) {
        result.label = "WEAK";
        result.level = "weak";
        result.leds = 2;
      } else {
        result.label = "TOO WEAK!";
        result.level = "too-weak";
        result.leds = 1;
      }
      return result;
    }

    // 8-9 characters: more conservative mapping
    if (len >= 8 && len <= 9) {
      if (entropy >= 50) {
        result.label = "STRONG";
        result.level = "strong";
        result.leds = 4;
      } else if (entropy >= 40) {
        result.label = "MEDIUM";
        result.level = "medium";
        result.leds = 3;
      } else if (entropy >= 25) {
        result.label = "WEAK";
        result.level = "weak";
        result.leds = 2;
      } else {
        result.label = "TOO WEAK!";
        result.level = "too-weak";
        result.leds = 1;
      }
      return result;
    }

    // Fallback
    result.label = "TOO WEAK!";
    result.level = "too-weak";
    result.leds = 1;
    return result;
  }

  /* ---------- UI binding ---------- */
  function updateStrengthUI(password) {
    const leds = document.querySelectorAll(".strength-leds .led");
    const labelEl = document.querySelector(".strength-label");
    if (!leds.length || !labelEl) return;

    // reset classes
    leds.forEach(led => {
      led.classList.remove("active", "too-weak", "weak", "medium", "strong", "turning-off");
    });
    labelEl.classList.remove("too-weak", "weak", "medium", "strong");

    if (!password || password.length === 0) {
      labelEl.textContent = "";
      return;
    }

    const assessment = assessPassword(password);

    // animate turning-off for previously active leds (gentle)
    leds.forEach((led, i) => {
      if (led.classList.contains("active") && i >= assessment.leds) {
        led.classList.add("turning-off");
        setTimeout(() => led.classList.remove("turning-off"), 360);
      }
    });

    // activate leds and color classes
    for (let i = 0; i < assessment.leds && i < leds.length; i++) {
      leds[i].classList.add("active", assessment.level);
    }

    labelEl.textContent = assessment.label;
    labelEl.classList.add(assessment.level);

    // debug: expose entropy on data-attribute if needed
    labelEl.dataset.entropy = Math.round(assessment.entropy);
  }

  /* Helper: reuse existing countCharsets if present; fallback here */
  function countCharsets(password) {
    let count = 0;
    if (/[A-Z]/.test(password)) count++;
    if (/[a-z]/.test(password)) count++;
    if (/[0-9]/.test(password)) count++;
    if (/[^A-Za-z0-9]/.test(password)) count++;
    return count;
  }

  /* ---------------------------
     End of module
     --------------------------- */


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
