import { createClient } from '@supabase/supabase-js';

export default async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      error: 'Method not allowed',
      method: req.method
    });
  }

  try {
    console.log('📋 [API] Reçu requête create-user');
    
    console.log('🔍 [API] Vérification des variables d\'env:');
    console.log('  SUPABASE_URL:', process.env.SUPABASE_URL ? '✅ défini' : '❌ MANQUANT');
    console.log('  SUPABASE_SERVICE_ROLE_KEY:', process.env.SUPABASE_SERVICE_ROLE_KEY ? '✅ défini' : '❌ MANQUANT');

    if (!process.env.SUPABASE_URL) {
      console.error('❌ [API] ERREUR: SUPABASE_URL non défini');
      return res.status(500).json({
        error: 'Configuration error',
        message: 'SUPABASE_URL not configured in environment',
        details: 'Check Vercel Settings > Environment Variables'
      });
    }

    if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
      console.error('❌ [API] ERREUR: SUPABASE_SERVICE_ROLE_KEY non défini');
      return res.status(500).json({
        error: 'Configuration error',
        message: 'SUPABASE_SERVICE_ROLE_KEY not configured',
        details: 'This endpoint requires SERVICE_ROLE_KEY for admin operations'
      });
    }

    console.log('🔗 [API] Initialisation du client Supabase...');
    
    const supabaseAdmin = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      }
    );

    console.log('✅ [API] Client Supabase initialisé');

    const { email, password, full_name, role } = req.body;

    console.log('📝 [API] Données reçues:', {
      email,
      full_name,
      role,
      password: password ? '***' : '❌ manquant'
    });

    if (!email || !password || !full_name) {
      console.warn('⚠️  [API] Données manquantes');
      return res.status(400).json({
        error: 'Bad request',
        message: 'Missing required fields',
        required: ['email', 'password', 'full_name']
      });
    }

    console.log(`🔐 [API] Création de l'utilisateur auth: ${email}`);
    
    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email: email.toLowerCase().trim(),
      password,
      email_confirm: true
    });

    if (authError) {
      console.error('❌ [API] Erreur auth:', authError.message);
      return res.status(400).json({
        error: 'Authentication error',
        message: authError.message,
        code: authError.code
      });
    }

    const userId = authData.user.id;
    console.log('✅ [API] Utilisateur auth créé:', userId);

    console.log(`📦 [API] Création du profil pour ${userId}`);

    const profileData = {
      id: userId,
      email: email.toLowerCase().trim(),
      full_name: full_name.trim(),
      role: role || 'viewer',
      status: 'active',
      profile_validated: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      metadata: {
        first_login: true,
        profile_completion: 0,
        modules_access: ['dashboard'],
        permissions: ['read'],
        provisioned_by: 'admin_api',
        provisioned_at: new Date().toISOString()
      }
    };

    const { data: profile, error: profileError } = await supabaseAdmin
      .from('profiles')
      .insert([profileData])
      .select();

    if (profileError) {
      console.error('❌ [API] Erreur création profil:', profileError.message);
      
      console.log('🧹 [API] Nettoyage: suppression de l\'utilisateur auth');
      await supabaseAdmin.auth.admin.deleteUser(userId);
      
      return res.status(400).json({
        error: 'Profile creation failed',
        message: profileError.message,
        code: profileError.code
      });
    }

    console.log('✅ [API] Profil créé:', profile[0]?.id);

    console.log(`✔️  [API] Marquage du profil comme validé`);

    const { data: validated, error: validateError } = await supabaseAdmin
      .from('profiles')
      .update({ profile_validated: true })
      .eq('id', userId)
      .select();

    if (validateError) {
      console.warn('⚠️  [API] Avertissement lors de la validation:', validateError.message);
    } else {
      console.log('✅ [API] Profil marqué comme validé');
    }

    console.log('✅ [API] Succès! Utilisateur créé:', userId);
    
    return res.status(201).json({
      success: true,
      user: {
        id: userId,
        email: email.toLowerCase(),
        full_name,
        role: role || 'viewer'
      },
      profile: {
        id: profile[0]?.id,
        validated: true,
        created_at: profile[0]?.created_at
      },
      message: 'User created successfully'
    });

  } catch (error) {
    console.error('❌ [API] ERREUR CRITIQUE:', error.message);
    console.error('Stack:', error.stack);

    return res.status(500).json({
      error: 'Internal server error',
      message: error.message,
      type: error.constructor.name
    });
  }
};
