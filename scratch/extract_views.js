const fs = require('fs');
const readline = require('readline');
const path = require('path');

const transcriptPath = 'C:\\Users\\BINARY\\.gemini\\antigravity-ide\\brain\\12380753-85e3-477a-b53f-8238a8c8e8a2\\.system_generated\\logs\\transcript_full.jsonl';

const rl = readline.createInterface({
    input: fs.createReadStream(transcriptPath),
    crlfDelay: Infinity
});

let lineNum = 0;
const indexViews = [];

rl.on('line', (line) => {
    lineNum++;
    if (line.includes('File Path: `file:///c:/Users/BINARY/.gemini/antigravity/scratch/supinkly-ai/index.html`')) {
        try {
            const obj = JSON.parse(line);
            const content = obj.content || '';
            const mLines = content.match(/Showing lines (\d+) to (\d+)/);
            const mTotal = content.match(/Total Lines: (\d+)/);
            if (mLines && mTotal) {
                indexViews.push({
                    transcriptLine: lineNum,
                    stepIndex: obj.step_index,
                    totalLines: parseInt(mTotal[1]),
                    start: parseInt(mLines[1]),
                    end: parseInt(mLines[2])
                });
            }
        } catch (e) {}
    }
});

rl.on('close', () => {
    console.log(`Found ${indexViews.length} views of index.html:`);
    indexViews.forEach(v => {
        console.log(`  Step ${v.stepIndex} (line ${v.transcriptLine}): Total ${v.totalLines} lines, range ${v.start}-${v.end}`);
    });
});
