// Validates every oscript formula in the AA files. The definitions are
// ojson (unquoted keys), so they parse through ocore's own parser — plain
// JSON.parse can never read them. Exit 1 on the first invalid formula.
// Usage: node tools/check_aa_syntax.js agents/*.aa
const fs = require('fs');
const path = require('path');
const ocoreRoot = path.join(__dirname, '..', '..', 'vendor', 'aa-testkit', 'node_modules', 'ocore');
const parseOjson = require(path.join(ocoreRoot, 'formula', 'parse_ojson')).parse;
const { validate } = require(path.join(ocoreRoot, 'formula', 'validation.js'));

// Deployment placeholders substituted before the AA is posted; mirror the
// complexity checker so both tools parse the same source.
const SUBSTITUTIONS = {
	PERP_ASSET_ID_HERE: 'n9y3VghJdrwhU4nWem6P78yNc2NVFywqMdFcaXGBTeE=',
	ROLLUP_AA_HERE: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU',
};

function formulas(def, accPath, acc) {
	if (Array.isArray(def)) {
		def.forEach((v, i) => formulas(v, `${accPath}[${i}]`, acc));
		return acc;
	}
	if (def && typeof def === 'object') {
		for (const [k, v] of Object.entries(def)) {
			if (k === 'if' || k === 'init' || k === 'state') acc.push([`${accPath}.${k}`, v]);
			else if (typeof v === 'string' && (k === 'state' || k === 'formula')) acc.push([`${accPath}.${k}`, v]);
			else if (v && typeof v === 'object') formulas(v, `${accPath}.${k}`, acc);
		}
	}
	return acc;
}

async function main() {
	for (const f of process.argv.slice(2)) {
		let src = fs.readFileSync(f, 'utf8');
		for (const [k, v] of Object.entries(SUBSTITUTIONS)) src = src.split(k).join(v);
		const [, def] = await new Promise((resolve, reject) =>
			parseOjson(src, (err, res) => (err ? reject(new Error(`${f}: ${err}`)) : resolve(res)))
		);
		const items = formulas(def, f, []);
		for (const [itemPath, v] of items) {
			if (typeof v !== 'string') continue;
			const formula = v.startsWith('{') ? v.slice(1, -1) : v;
			const isStmt = itemPath.endsWith('.state') || itemPath.endsWith('.init');
			const res = await new Promise((r) =>
				validate(
					{
						formula,
						bAA: true,
						bStateVarAssignmentAllowed: isStmt,
						bStatementsOnly: isStmt,
						bAssetCondition: itemPath.endsWith('.if'),
						complexity: 0,
						count_ops: 0,
						locals: {},
						readGetterProps: (aa, name, cb) => cb(null),
					},
					(x) => r(x)
				)
			);
			const err = res && typeof res === 'object' ? res.error : res;
			if (err) {
				console.error(`${itemPath}: ${err}`);
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
