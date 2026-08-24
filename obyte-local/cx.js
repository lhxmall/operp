const path=require('path');
module.paths.push(path.join('..','vendor','aa-testkit','node_modules'));
process.env.MAX_COMPLEXITY='99999';
const parseOjson=require('ocore/formula/parse_ojson').parse;
const aa_validation=require('ocore/aa_validation.js');
const f=process.argv[2]||'agents/operp_vault_base.aa';
const src=require('fs').readFileSync(f,'utf8');
parseOjson(src,(e,def)=>{
  aa_validation.validateAADefinition(def,(a,f2,cb)=>cb({complexity:0,count_ops:1}),Number.MAX_SAFE_INTEGER,(err,res)=>console.log('TOTAL:',res&&res.complexity,'ERR:',err));
});
