
const motorTsResult = ts.transpileModule("interface Item { value: number }; const item: Item = { value: 42 }; console.log(item.value);", { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext }, reportDiagnostics: true });
console.log(JSON.stringify({version:ts.version,output:motorTsResult.outputText,diagnostics:motorTsResult.diagnostics.length}));
