console.log("===== TESTS DE generatePassword =====");

// Redéfinition locale de SIMILAR_CHARS et AMBIGUOUS pour les tests
const SIMILAR_CHARS = new Set([
  'i', 'I', 'l', 'L', '1',
  'o', 'O', '0',
  's', 'S', '5',
  'z', 'Z', '2',
  'b', 'B', '8',
  'g', 'q', '9',
  't', 'T', '+'
]);

const AMBIGUOUS = new Set([
  '{', '}', '[', ']', '(', ')', '/', '\\', "'", '"', '`', '~', ',', ';', ':', '<', '>'
]);

// Vérification option = tout activé
const options = {
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: true,
  excludeSimilar: true,
  excludeAmbiguous: true,
};

for (let i = 0; i < 5; i++) {
  const pwd = generatePassword(options, 16);
  console.log(`Mot de passe généré : ${pwd}`);

  const hasUpper = /[A-Z]/.test(pwd);
  const hasLower = /[a-z]/.test(pwd);
  const hasNumber = /[0-9]/.test(pwd);
  const hasSymbol = /[^A-Za-z0-9]/.test(pwd);

  console.log(`Contient au moins une majuscule : ${hasUpper}`);
  console.log(`Contient au moins une minuscule : ${hasLower}`);
  console.log(`Contient au moins un chiffre : ${hasNumber}`);
  console.log(`Contient au moins un symbole : ${hasSymbol}`);
  console.log("----------------------------");
}

// Test avec symboles désactivés
const pwd2 = generatePassword(
  {
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: false,
    excludeSimilar: true,
    excludeAmbiguous: false
  },
  12
);

console.log("Test sans symboles : ", pwd2);

// Vérification absence de caractères similaires
console.log("Contient des caractères similaires ? ", [...SIMILAR_CHARS].some(ch => pwd2.includes(ch)));

// Vérification absence de caractères ambigus
console.log("Contient des caractères ambigus ? ", [...AMBIGUOUS].some(ch => pwd2.includes(ch)));
