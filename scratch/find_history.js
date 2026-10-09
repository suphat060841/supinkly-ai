const fs = require('fs');
const path = require('path');

const searchDirs = [
    path.join(process.env.APPDATA || '', 'Code', 'User', 'History'),
    path.join(process.env.APPDATA || '', 'Antigravity', 'User', 'History'),
    path.join(process.env.USERPROFILE || '', '.gemini'),
    path.join(process.env.USERPROFILE || '', 'AppData', 'Roaming')
];

console.log('Searching for index.html history and backups...');

function search(dir, depth = 0) {
    if (depth > 6) return;
    try {
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const full = path.join(dir, file);
            try {
                const stat = fs.statSync(full);
                if (stat.isDirectory()) {
                    if (file !== 'node_modules' && file !== '.git') {
                        search(full, depth + 1);
                    }
                } else {
                    if (stat.size > 250000 && stat.size < 400000) {
                        // check if it contains Supinkly
                        const buf = Buffer.alloc(512);
                        const fd = fs.openSync(full, 'r');
                        fs.readSync(fd, buf, 0, 512, 0);
                        fs.closeSync(fd);
                        const str = buf.toString('utf8');
                        if (str.includes('Supinkly') || str.includes('<!DOCTYPE html>')) {
                            console.log(`MATCH FOUND: ${full} (size: ${stat.size}, modified: ${stat.mtime.toISOString()})`);
                        }
                    }
                }
            } catch (e) {}
        }
    } catch (e) {}
}

for (const d of searchDirs) {
    if (fs.existsSync(d)) {
        console.log(`Searching in ${d}...`);
        search(d);
    }
}
console.log('Search complete.');
