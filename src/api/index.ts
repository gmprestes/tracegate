import express from 'express';

const app = express();
app.use(express.json());

app.get('/admin/health', (_, res) => {
  res.send({ status: 'ok', uptime: process.uptime() });
});

app.post('/admin/rules/ip-block', (req, res) => {
  // TODO: Store IP block rule
  res.send({ ok: true, rule: req.body });
});

export default app;
