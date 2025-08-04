import cluster from 'cluster';
import os from 'os';
import { startTraceGate } from './core/balancer';

console.log(`🧑‍💻 Running as user: ${process.getuid?.()} (${process.env.USER || process.env.LOGNAME || process.env.USERNAME})`);

startTraceGate();

if (cluster.isPrimary) {
  // const numCPUs = os.cpus().length;
  // console.log(`TraceGate iniciando com ${numCPUs} workers...`);
  // for (let i = 0; i < numCPUs; i++) {
  //   cluster.fork();
  // }

  // cluster.on('exit', (worker) => {
  //   console.warn(`Worker ${worker.process.pid} morreu. Reiniciando...`);
  //   cluster.fork();
  // });
} else {
  startTraceGate();
}
