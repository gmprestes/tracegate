// benchmark.ts
import autocannon from 'autocannon';

const instance = autocannon({
  url: 'https://localhost.teste',
  connections: 100, // simultâneos
  duration: 10,     // segundos
  pipelining: 1
}, finishedBench);

function finishedBench(err: any, res: autocannon.Result) {
  if (err) {
    console.error('Erro no benchmark:', err);
    return;
  }
  console.log(`\n🏁 Benchmark finalizado.`);
  console.log(`➡️  Requisições por segundo: ${res.requests.average}`);
  console.log(`📈 Latência média: ${res.latency.average} ms`);
  console.log(`📊 Throughput: ${res.throughput.average} bytes/s`);
}

process.once('SIGINT', () => {
  instance.stop();
});
