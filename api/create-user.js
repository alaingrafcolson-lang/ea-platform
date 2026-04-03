if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
  return res.status(500).json({
    error: 'Configuration serveur incomplète',
    missing: {
      SUPABASE_URL: !SUPABASE_URL,
      SERVICE_ROLE_KEY: !SERVICE_ROLE_KEY
    }
  });
}
