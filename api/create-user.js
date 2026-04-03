// /api/create-user.js — Vercel Serverless Function
// Variables Vercel requises :
//   SUPABASE_URL               (ex: https://xxx.supabase.co)
//   SUPABASE_SERVICE_ROLE_KEY  (clé secrète service_role)
//   SUPABASE_ANON_KEY          (clé publique anon)

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(200).json({ status: 'ok', time: Date.now() });
};
