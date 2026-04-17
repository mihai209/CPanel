const fs = require('fs');
const path = 'routes/legacy/server-pages.js';
let content = fs.readFileSync(path, 'utf8');

const regexUsers = /(const reactPageData = \{\s*routePath: `\/server\/\$\{server\.containerId\}\/users`[\s\S]*?if \(!wantsLegacyReactBypass[\s\S]*?\}\s*)+/g;
content = content.replace(regexUsers, (match) => {
    // Keep only the first occurrence by extracting it
    const firstOccur = match.match(/const reactPageData = \{[\s\S]*?\}\s*\}/)[0];
    return firstOccur + '\n            ';
});

const regexDB = /(const reactPageData = \{\s*routePath: `\/server\/\$\{state\.server\.containerId\}\/databases`[\s\S]*?if \(!wantsLegacyReactBypass[\s\S]*?\}\s*)+/g;
content = content.replace(regexDB, (match) => {
    const firstOccur = match.match(/const reactPageData = \{[\s\S]*?\}\s*\}/)[0];
    return firstOccur + '\n            ';
});

const regexSchedules = /(const reactPageData = \{\s*routePath: `\/server\/\$\{server\.containerId\}\/schedules`[\s\S]*?if \(!wantsLegacyReactBypass[\s\S]*?\}\s*)+/g;
content = content.replace(regexSchedules, (match) => {
    const firstOccur = match.match(/const reactPageData = \{[\s\S]*?\}\s*\}/)[0];
    return firstOccur + '\n            ';
});

const regexStartup = /(const reactPageData = \{\s*routePath: `\/server\/\$\{server\.containerId\}\/startup`[\s\S]*?if \(!wantsLegacyReactBypass[\s\S]*?\}\s*)+/g;
content = content.replace(regexStartup, (match) => {
    const firstOccur = match.match(/const reactPageData = \{[\s\S]*?\}\s*\}/)[0];
    return firstOccur + '\n            ';
});

// also clean up multiple empty formatting lines
content = content.replace(/\n(\s*\n){2,}/g, '\n\n');

fs.writeFileSync(path, content);
console.log('Fixed duplicates!');
