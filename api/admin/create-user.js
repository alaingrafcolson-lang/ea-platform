// ══════════════════════════════════════════════════════════════════
// Vercel Serverless Function — /api/create-user
// Utilise SUPABASE_SERVICE_ROLE_KEY (variable Vercel, jamais exposée)
// pour créer des utilisateurs via auth.admin.createUser()
// ══════════════════════════════════════════════════════════════════

const { createClient } = require('@supabase/supabase-js');

// Rôles autorisés à créer des comptes
const ALLOWED_CALLER_ROLES = ['SUPER_ADMIN', 'DSI', 'RSSI', 'SYSTEM_ADMIN', 'NETWORK_ADMIN'];

module.exports = async function handler(req, res) {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.status(200).end();

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Méthode non autorisée' });
    }

    // ── Clés depuis les variables d'environnement Vercel ──
    const SUPABASE_URL         = process.env.SUPABASE_URL         || process.env.supabase_url;
    const SERVICE_ROLE_KEY     = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const ANON_KEY             = process.env.SUPABASE_ANON_KEY;

    if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
        return res.status(500).json({ error: 'Variables d\'environnement Supabase manquantes côté serveur' });
    }

    // ── Client admin (service_role) ──
    const sbAdmin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
        auth: { autoRefreshToken: false, persistSession: false }
    });

    // ── Client anon pour vérifier le token du demandeur ──
    const sbAnon = createClient(SUPABASE_URL, ANON_KEY || SERVICE_ROLE_KEY);

    // ── Vérifier le JWT du demandeur ──
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '').trim();
    if (!token) {
        return res.status(401).json({ error: 'Token d\'authentification manquant' });
    }

    const { data: { user: caller }, error: authErr } = await sbAdmin.auth.getUser(token);
    if (authErr || !caller) {
        return res.status(401).json({ error: 'Token invalide ou expiré' });
    }

    // ── Vérifier le rôle du demandeur ──
    const { data: roleRow } = await sbAdmin
        .from('user_roles')
        .select('role_id')
        .eq('user_id', caller.id)
        .maybeSingle();

    const callerRole = roleRow?.role_id;
    if (!callerRole || !ALLOWED_CALLER_ROLES.includes(callerRole)) {
        return res.status(403).json({ error: 'Droits insuffisants pour créer des utilisateurs' });
    }

    // ── Paramètres du nouvel utilisateur ──
    const { email, password, prenom, nom, role, company_id, must_change_password, send_email } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email et mot de passe requis' });
    }

    // ── Créer l'utilisateur dans auth.users ──
    const { data: newUser, error: createErr } = await sbAdmin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,   // confirme immédiatement sans email de vérification
        user_metadata: { prenom, nom, role, must_change_password: !!must_change_password }
    });

    if (createErr) {
        // Message d'erreur lisible
        if (createErr.message.includes('already registered') || createErr.message.includes('already exists')) {
            return res.status(409).json({ error: 'Cet email est déjà enregistré' });
        }
        return res.status(400).json({ error: createErr.message });
    }

    const userId = newUser.user.id;

    // ── Insérer dans la table users ──
    const { error: insertErr } = await sbAdmin.from('users').upsert({
        id: userId,
        email,
        prenom:               prenom || null,
        nom:                  nom    || null,
        company_id:           company_id || null,
        must_change_password: !!must_change_password,
        active:               true
    }, { onConflict: 'id' });

    if (insertErr) {
        console.error('Erreur insert users:', insertErr.message);
        // Ne pas bloquer — l'auth est créé, on continue
    }

    // ── Attribuer le rôle ──
    const roleToAssign = role || 'SERVICE_MANAGER';
    const { error: roleErr } = await sbAdmin.from('user_roles').upsert(
        { user_id: userId, role_id: roleToAssign },
        { onConflict: 'user_id' }
    );

    if (roleErr) {
        console.error('Erreur insert user_roles:', roleErr.message);
    }

    // ── Envoyer email de réinitialisation si demandé ──
    if (send_email) {
        await sbAdmin.auth.admin.generateLink({
            type: 'recovery',
            email,
            options: { redirectTo: (process.env.VERCEL_URL ? 'https://' + process.env.VERCEL_URL : 'https://ea-platform-omega.vercel.app') + '/index.html' }
        });
    }

    return res.status(200).json({
        success: true,
        user_id: userId,
        email,
        role: roleToAssign,
        message: 'Profil créé avec succès'
    });
};
