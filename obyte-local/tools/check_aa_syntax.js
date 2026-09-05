// Strips // comments and validates all oscript formulas inside the AA files.
// Exit 1 on the first invalid formula. Usage: node tools/check_aa_syntax.js
const fs = require('fs');
const { validate } = require('aa-testkit/node_modules/ocore/formula/validation.js');

function strip(src) {
	let out = '',
		inStr = null;
	for (let i = 0; i < src.length; i++) {
		const ch = src[i];
		if (inStr) {
			out += ch;
			if (ch === inStr && src[i - 1] !== '\\') inStr = null;
			continue;
		}
		if (ch === '"' || ch === "'") {
			inStr = ch;
			out += ch;
			continue;
		}
		if (ch === '/' && src[i + 1] === '/') {
			while (i < src.length && src[i] !== '\n') i++;
			continue;
		}
		out += ch;
	}
	return out;
}

function formulas(def, path, acc) {
	if (Array.isArray(def)) {
		def.forEach((v, i) => formulas(v, path + '[' + i + ']', acc));
		return acc;
	}
	if (def && typeof def === 'object') {
		for (const [k, v] of Object.entries(def)) {
			if (k === 'if' || k === 'init' || k === 'state') acc.push([path + '.' + k, v]);
			else if (typeof v === 'string' && (k === 'state' || k === 'formula')) acc.push([path + '.' + k, v]);
			else if (v && typeof v === 'object') formulas(v, path + '.' + k, acc);
		}
	}
	return acc;
}

async function main() {
	for (const f of process.argv.slice(2)) {
		const def = JSON.parse(strip(fs.readFileSync(f, 'utf8')));
		const items = formulas(def, f, []);
		for (const [path, v] of items) {
			if (typeof v !== 'string') continue;
			const formula = v.startsWith('{') ? v.slice(1, -1) : v;
			const opts = {
				formula,
				bStateVarAssignmentAllowed: path.endsWith('.state') || path.endsWith('.init'),
				bStatementsOnly: path.endsWith('.state') || path.endsWith('.init'),
				complexity: 0,
				count_ops: 0,
			};
			const res = await new Promise((r) => validate(opts, (e) => r(e)));
			if (res) {
				console.error(`${f}${path}: ${res}`);
				process.exit(1);
			}
		}
		console.log(`${f}: ${items.length} formulas OK`);
	}
}
main().catch((e) => {
	console.error(e.message);
	process.exit(1);
});
