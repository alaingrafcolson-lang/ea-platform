// /api/create-user.js — Vercel Serverless Function
// Variables Vercel requises :
//   SUPABASE_URL               (ex: https://xxx.supabase.co)
//   SUPABASE_SERVICE_ROLE_KEY  (clé secrète service_role)
//   SUPABASE_ANON_KEY          (clé publique anon)

const ALLOWED_ROLES = ['SUPER_ADMIN','DSI','RSSI','SYSTEM_ADMIN','NETWORK_ADMIN'];

module.exports = async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST')   return res.status(405).json({ error: 'Méthode non autorisée' });

    // ── Variables d'environnement ──
    const SUPABASE_URL      = process.env.SUPABASE_URL || process.env.supabase_url;
    const SERVICE_ROLE_KEY  = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const ANON_KEY          = process.env.SUPABASE_ANON_KEY;

    console.log('[create-user] SUPABASE_URL:',     SUPABASE_URL      ? 'ok' : 'MISSING');
    console.log('[create-user] SERVICE_ROLE_KEY:',  SERVICE_ROLE_KEY  ? 'ok' : 'MISSING');
    console.log('[create-user] ANON_KEY:',          ANON_KEY          ? 'ok' : 'MISSING');

    if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
        return res.status(500).json({ error: 'Variables SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY manquantes' });
    }

    // ── Token JWT de l'appelant ──
    const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'Token JWT manquant dans Authorization header' });

    // ── Vérifier le token avec la clé anon (ou service_role en fallback) ──
    // Supabase exige apikey = anon pour valider un token utilisateur
    const apiKeyForAuth = ANON_KEY || SERVICE_ROLE_KEY;
    let caller;
    try {
        const r = await fetch(SUPABASE_URL + '/auth/v1/user', {
            headers: {
                'Authorization': 'Bearer ' + token,
                'apikey': apiKeyForAuth
            }
        });
        console.log('[create-user] auth/v1/user status:', r.status);
        if (!r.ok) {
            const body = await r.text();
            console.error('[create-user] auth/v1/user body:', body);
            return res.status(401).json({ error: 'Token invalide ou session expirée (' + r.status + ')' });
        }
        caller = await r.json();
        console.log('[create-user] caller email:', caller.email);
    } catch(e) {
        return res.status(500).json({ error: 'Erreur vérification token : ' + e.message });
    }

    // ── Récupérer le rôle de l'appelant (avec service_role pour bypass RLS) ──
    let callerRole = null;
    try {
        const r = await fetch(
            SUPABASE_URL + '/rest/v1/user_roles?user_id=eq.' + caller.id + '&select=role_id&limit=1',
            {
                headers: {
                    'apikey':         SERVICE_ROLE_KEY,
                    'Authorization':  'Bearer ' + SERVICE_ROLE_KEY
                }
            }
        );
        const rows = await r.json();
        callerRole = rows?.[0]?.role_id || null;
    } catch(e) {
        console.warn('[create-user] role fetch error:', e.message);
    }

    // Fallback propriétaire
    if (!callerRole && caller.email === 'alain.grafcolson@gmail.com') {
        callerRole = 'SUPER_ADMIN';
    }

    console.log('[create-user] callerRole:', callerRole);

    if (!callerRole || !ALLOWED_ROLES.includes(callerRole)) {
        return res.status(403).json({
            error: 'Accès refusé — rôle : ' + (callerRole || 'inconnu'),
            required: ALLOWED_ROLES.join(', ')
        });
    }

    // ── Paramètres du nouvel utilisateur ──
    const { email, password, prenom, nom, role, company_id, must_change_password, send_email } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email et password requis' });

    console.log('[create-user] creating:', email, '| role:', role);

    // ── Créer dans Supabase Auth (admin API) ──
    let userId;
    try {
        const r = await fetch(SUPABASE_URL + '/auth/v1/admin/users', {
            method: 'POST',
            headers: {
                'Content-Type':  'application/json',
                'apikey':        SERVICE_ROLE_KEY,
                'Authorization': 'Bearer ' + SERVICE_ROLE_KEY
            },
            body: JSON.stringify({
                email,
                password,
                email_confirm: true,
                user_metadata: {
                    prenom:               prenom || '',
                    nom:                  nom    || '',
                    role:                 role   || 'SERVICE_MANAGER',
                    must_change_password: !!must_change_password
                }
            })
        });
        const body = await r.json();
        console.log('[create-user] admin create status:', r.status);
        if (!r.ok) {
            const msg = body.msg || body.message || body.error_description || JSON.stringify(body);
            if (r.status === 422 || (msg && msg.toLowerCase().includes('already'))) {
                return res.status(409).json({ error: 'Cet email est déjà enregistré' });
            }
            return res.status(r.status).json({ error: 'Erreur création Auth : ' + msg });
        }
        userId = body.id;
        console.log('[create-user] new userId:', userId);
    } catch(e) {
        return res.status(500).json({ error: 'Auth admin create : ' + e.message });
    }

    // ── Insérer dans la table users ──
    try {
        const r = await fetch(SUPABASE_URL + '/rest/v1/users', {
            method:  'POST',
            headers: {
                'Content-Type':  'application/json',
                'apikey':        SERVICE_ROLE_KEY,
                'Authorization': 'Bearer ' + SERVICE_ROLE_KEY,
                'Prefer':        'resolution=merge-duplicates'
            },
            body: JSON.stringify({
                id:                   userId,
                email:                email,
                prenom:               prenom     || null,
                nom:                  nom        || null,
                company_id:           company_id || null,
                must_change_password: !!must_change_password,
                active:               true
            })
        });
        if (!r.ok) console.warn('[create-user] users insert:', r.status, await r.text());
    } catch(e) {
        console.warn('[create-user] users insert error:', e.message);
    }

    // ── Attribuer le rôle ──
    const roleToAssign = role || 'SERVICE_MANAGER';
    try {
        const r = await fetch(SUPABASE_URL + '/rest/v1/user_roles', {
            method:  'POST',
            headers: {
                'Content-Type':  'application/json',
                'apikey':        SERVICE_ROLE_KEY,
                'Authorization': 'Bearer ' + SERVICE_ROLE_KEY,
                'Prefer':        'resolution=merge-duplicates'
            },
            body: JSON.stringify({ user_id: userId, role_id: roleToAssign })
        });
        if (!r.ok) console.warn('[create-user] user_roles insert:', r.status, await r.text());
    } catch(e) {
        console.warn('[create-user] user_roles insert error:', e.message);
    }

    // ── Envoyer email de reset si demandé ──
    if (send_email) {
        try {
            const r = await fetch(SUPABASE_URL + '/auth/v1/admin/users/' + userId, {
                method:  'PUT',
                headers: {
                    'Content-Type':  'application/json',
                    'apikey':        SERVICE_ROLE_KEY,
                    'Authorization': 'Bearer ' + SERVICE_ROLE_KEY
                },
                body: JSON.stringify({ email_confirm: true })
            });
            console.log('[create-user] send email status:', r.status);
        } catch(e) {
            console.warn('[create-user] send email error:', e.message);
        }
    }

    console.log('[create-user] ✓ done:', email);
    return res.status(200).json({
        success:  true,
        user_id:  userId,
        email,
        role:     roleToAssign,
        message:  'Profil créé avec succès'
    });
};
