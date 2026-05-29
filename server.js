const express = require('express');
const cors = require('cors');
const si = require('systeminformation');

const app = express();
app.use(cors());

const PORT = 3000;

app.get('/api/connections', async (req, res) => {
  try {
    const connections = await si.networkConnections();
    res.json({
      total: connections.length,
      data: connections.slice(0, 20)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});