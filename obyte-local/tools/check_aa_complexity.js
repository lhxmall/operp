// Parses each .aa via ocore's own ojson parser, validates every oscript
// formula, and reports per-case complexity (exit 2 if > MAX_COMPLEXITY).
// Usage: node tools/check_aa_complexity.js agents/*.aa
const fs = require('fs');
const path = require('path');
const ocoreRoot = path.join(__dirname, '..', '..', 'vendor', 'aa-testkit', 'node_modules', 'ocore');
const parseOjson = require(path.join(ocoreRoot, 'formula', 'parse_ojson')).parse;
const { validate } = require(path.join(ocoreRoot, 'formula', 'validation.js'));
const constants = require(path.join(ocoreRoot, 'constants.js'));

function walk(def, path, acc) {
	if (Array.isArray(def)) {
		def.forEach((v, i) => walk(v, `${path}[${i}]`, acc));
		return acc;
	}
	if (def && typeof def === 'object') {
		for (const [k, v] of Object.entries(def)) {
			if ((k === 'if' || k === 'init' || k === 'state') && typeof v === 'string') {
				acc.push([`${path}.${k}`, v]);
			} else if (v && typeof v === 'object') {
				walk(v, `${path}.${k}`, acc);
			}
		}
	}
	return acc;
}

const SUBSTITUTIONS = {
	PERP_ASSET_ID_HERE: 'n9y3VghJdrwhU4nWem6P78yNc2NVFywqMdFcaXGBTeE=',
	ROLLUP_AA_HERE: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU',
};
async function check(f) {
	let src = fs.readFileSync(f, 'utf8');
	for (const [k, v] of Object.entries(SUBSTITUTIONS)) src = src.split(k).join(v);
	const [, def] = await new Promise((resolve, reject) =>
		parseOjson(src, (err, res) => (err ? reject(new Error(`${f}: ${err}`)) : resolve(res)))
	);
	const items = walk(def, path.basename(f), []);
	let max = 0;
	let i = 0;
	function next() {
		if (i >= items.length) {
			console.log(`${f}: ${items.length} formulas, max complexity ${max}`);
			return runNext();
		}
		const [p, v] = items[i++];
		const formula = v.startsWith('{') ? v.slice(1, -1) : v;
		const isStmt = p.endsWith('.state') || p.endsWith('.init');
		validate(
			{
				formula,
				bAA: true,
				bStateVarAssignmentAllowed: isStmt,
				bStatementsOnly: isStmt,
				bAssetCondition: p.endsWith('.if'),
				complexity: 0,
				count_ops: 0,
				locals: {},
				readGetterProps: (aa, name, cb) => cb(null),
			},
			(res) => {
				const err = res && typeof res === 'object' ? res.error : res;
				const cx = res && typeof res === 'object' ? res.complexity : 0;
				if (err) {
					console.error(`${f}${p}: ${err}`);
					process.exit(1);
				}
				if (cx > max) max = cx;
				if (cx > constants.MAX_COMPLEXITY) {
					console.error(`${f}${p}: complexity ${cx} > ${constants.MAX_COMPLEXITY}`);
					process.exit(2);
				}
				next();
			}
		);
	}
	next();
}

let fileIdx = 0;
function runNext() {
	const files = process.argv.slice(2);
	if (fileIdx >= files.length) process.exit(0);
	check(files[fileIdx++]);
}
runNext();
