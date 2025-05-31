import { customMd5HashVector } from "./hashing.js";
import { PhishingModel } from "./phishing_model.js";
//dont needed ,to insert the model we need not whole columns just the data with out the url 

function smartSplitCsv(line) {
    const result = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
        const char = line[i];

        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            result.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }

    if (current !== '') {
        result.push(current.trim());
    }

    return result;
}

const rawLine = "34,0,14,0,0,1,0,0,0,1,0,0,0,inc-102890.weeblysite.com,1,1,Google Trust Services,4535,212,SafeNames Ltd.,0,15,1,49,29,1,1,0,0,0,0,0,0,0,0,7,0,1,22,4,0.181818182,11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,7,0.875,0,0,0,0,0,0";
const parts = rawLine.split(",");
console.log(parts);
for (let index = 0; index < parts.length; index++) {
    console.log(parts[index]);
    
}
const final_domain = parts[14];
const ssl_issuer = parts[17];
const registrar = parts[20];
const hash_vector = customMd5HashVector([final_domain, ssl_issuer, registrar]);
console.log(hash_vector)

const drop_indices = [ 14, 17, 20];
const numeric_features = parts
  .filter((_, index) => !drop_indices.includes(index))
  .map(x => parseFloat(x));

const full_input = [...numeric_features, ...hash_vector];

//console.log("🔢 Full Input Vector:", full_input);
//console.log("✅ Input Length:", full_input.length);

// הרצת מודל
const prediction = PhishingModel().predict(full_input);
console.log("🔮 Prediction:", prediction);
