import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { data, error } = await supabase
    .from('security_questions')
    .select('id, question_text')
    .order('id');

  if (error) {
    console.error('Erreur fetch questions:', error);
    return res.status(500).json({ error: error.message });
  }

  res.status(200).json(data);
}
