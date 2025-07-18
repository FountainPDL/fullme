import express from 'express';
import supabase from '../supabaseClient.js';

const router = express.Router();

// Example: Submit a suspicious site report
router.post('/report', async (req, res) => {
  const { url, reason } = req.body;
  if (!url || !reason) {
    return res.status(400).json({ error: 'Missing url or reason' });
  }
  const { data, error } = await supabase
    .from('reports')
    .insert([{ url, reason }]);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, data });
});

// Example: Get all reports
router.get('/reports', async (req, res) => {
  const { data, error } = await supabase
    .from('reports')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
});

export default router;