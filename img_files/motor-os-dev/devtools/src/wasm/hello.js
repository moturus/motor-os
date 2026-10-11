const numbers = [1, 2, 3, 4];
const squares = numbers.map(value => value * value);
const total = squares.reduce((sum, value) => sum + value, 0);

console.log("Hello from WebAssembly on Motor OS!");
console.log(JSON.stringify({ squares, total }));
