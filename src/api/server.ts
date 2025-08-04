import app from './index';

const PORT = process.env.ADMIN_PORT || 8080;

app.listen(PORT, () => {
  console.log(`[admin] API server running at http://localhost:${PORT}`);
});
