const fs = require('fs');
const path = 'routes/legacy/server-pages.js';
let content = fs.readFileSync(path, 'utf8');

// Each duplicated block has a unique routePath signature.
// Strategy: for each route, find ALL occurrences of "const reactPageData = {" followed by
// that specific routePath, and keep only the FIRST one.

const routes = [
    { marker: '/users`', rename: 'reactPageDataUsers' },
    { marker: '/databases`', rename: 'reactPageDataDatabases' },
    { marker: '/schedules`', rename: 'reactPageDataSchedules' },
    { marker: '/startup`', rename: 'reactPageDataStartup' },
];

for (const route of routes) {
    // Find all indexes of "const reactPageData = {" that are followed (within ~200 chars) by the marker
    const sections = [];
    let searchFrom = 0;
    while (true) {
        const idx = content.indexOf('const reactPageData = {', searchFrom);
        if (idx === -1) break;
        const nearby = content.substring(idx, idx + 300);
        if (nearby.includes(route.marker)) {
            sections.push(idx);
        }
        searchFrom = idx + 1;
    }

    console.log(`Route ${route.marker}: found ${sections.length} declaration(s)`);
    
    if (sections.length <= 1) continue;

    // Keep the first, remove duplicates (from second onwards until the matching closing "}")
    // We'll remove each duplicate block: "const reactPageData = {" ... up to matching "};"
    // plus the following wantsReactPageData and wantsLegacyReactBypass blocks (which are also duped)
    
    // Process from last to first to preserve indexes
    for (let i = sections.length - 1; i >= 1; i--) {
        const start = sections[i];
        // find the end: closing "};" of the reactPageData object
        let depth = 0;
        let end = start;
        let inObj = false;
        for (let j = start; j < content.length; j++) {
            if (content[j] === '{') { depth++; inObj = true; }
            if (content[j] === '}') {
                depth--;
                if (inObj && depth === 0) {
                    end = j + 1;
                    // consume trailing semicolon and whitespace
                    while (end < content.length && (content[end] === ';' || content[end] === '\n' || content[end] === '\r' || content[end] === ' ')) {
                        end++;
                    }
                    break;
                }
            }
        }

        // Now also consume the following duplicated "if (wantsReactPageData(req)) { ... }"
        // and "if (!wantsLegacyReactBypass(req) ...) { ... }" blocks
        for (let block = 0; block < 2; block++) {
            // Skip whitespace
            let pos = end;
            while (pos < content.length && (content[pos] === '\n' || content[pos] === '\r' || content[pos] === ' ')) pos++;
            if (content.startsWith('if (', pos) || content.startsWith('if(!', pos)) {
                let d = 0;
                for (let j = pos; j < content.length; j++) {
                    if (content[j] === '{') d++;
                    if (content[j] === '}') {
                        d--;
                        if (d === 0) {
                            end = j + 1;
                            while (end < content.length && (content[end] === '\n' || content[end] === '\r' || content[end] === ' ')) end++;
                            break;
                        }
                    }
                }
            }
        }

        content = content.substring(0, start) + content.substring(end);
        console.log(`  Removed duplicate at index ${start}`);
    }
}

// Clean up excessive blank lines
content = content.replace(/(\n\s*){3,}/g, '\n\n');

fs.writeFileSync(path, content);
console.log('\nDone! Verify with: node -e "require(\'./routes/legacy/server-pages.js\')"');
