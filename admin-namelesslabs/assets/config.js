/* Nameless Labs admin config
 * - Passwords are NOT stored here, only salted PBKDF2 hashes (local fallback mode).
 * - For real security, fill SUPABASE_URL + SUPABASE_ANON_KEY: login then goes through
 *   Supabase Auth and all data is protected by row-level security (see /supabase/schema.sql).
 * - The anon key is public by design; never put the service_role key in this file.
 */
window.NL_CONFIG = {
  SUPABASE_URL: "https://nzaelikbjumaidaombmp.supabase.co",
  SUPABASE_ANON_KEY: "sb_publishable_IupVMhCmigAk4n5bTbRrjg_Fr05v-HE",
  EMAIL_DOMAIN: "namelesslabs.in.net",   // username "chethan" -> chethan@namelesslabs.in.net in Supabase Auth
  SESSION_HOURS: 8,
  IDLE_MINUTES: 30,
  PBKDF2_ITERATIONS: 150000,
  LOCAL_USERS: {
  "chethan": {
    "name": "Chethan",
    "role": "CEO",
    "salt": "0bcde79e7d5fbe71ca0c34470bc8395f",
    "hash": "191228af3da468bce1afad5973a284ee0426f92931fd3476c6d88f2dff536b52"
  },
  "vijay": {
    "name": "Vijay",
    "role": "Founder",
    "salt": "5e642afe67bbeab409b70d8caa890d03",
    "hash": "35f3da87153654bab006fa0d59a723da8ab6341498c6cc5af8206e89e64f2648"
  },
  "itadmin": {
    "name": "IT Admin",
    "role": "IT Admin",
    "salt": "c8363e96e567612f4043fa48742d7424",
    "hash": "ff1c2a1660f533f712795cf0916f9089a7ca383b8b4e881bffd57545781beada"
  },
  "kedar": {
    "name": "Kedar",
    "role": "CMO",
    "salt": "3c1a124d04fecfcf0e626a936e336b2a",
    "hash": "8b41ae400cc99496047ed6a3df883e10346fb63574869f13759e3f6772a04642"
  }
}
};
