const fs = require('fs');
const readline = require('readline');

const transcriptPath = 'C:\\Users\\BINARY\\.gemini\\antigravity-ide\\brain\\12380753-85e3-477a-b53f-8238a8c8e8a2\\.system_generated\\logs\\transcript_full.jsonl';

const rl = readline.createInterface({
    input: fs.createReadStream(transcriptPath),
    crlfDelay: Infinity
});

let lineNum = 0;
rl.on('line', (line) => {
    lineNum++;
    if (line.includes('File Path: `file:///c:/Users/BINARY/.gemini/antigravity/scratch/supinkly-ai/index.html`')) {
        const mLines = line.match(/Showing lines (\d+) to (\d+)/);
        const mTotal = line.match(/Total Lines: (\d+)/);
        if (mLines && mTotal && parseInt(mTotal[1]) > 4000) {
            console.log(`Line ${lineNum}: range ${mLines[1]}-${mLines[2]} (Total: ${mTotal[1]})`);
        }
    }
});
