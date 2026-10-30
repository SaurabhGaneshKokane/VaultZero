-- Forward-only Supabase Auth bridge. Review before applying in Supabase SQL Editor.
-- Preserves existing VaultZero profiles, key IDs, and key history.
-- Never stores Auth passwords or private keys.

-- Refuse ambiguous legacy email links or active-key conflicts before changing schema.
DO $preflight$
DECLARE
  auth_column_count integer;
  identity_conflict boolean;
BEGIN
  SELECT count(*) INTO auth_column_count
  FROM information_schema.columns
  WHERE table_schema = 'public'
    AND ((table_name = 'vault_users' AND column_name = 'auth_user_id')
      OR (table_name = 'vault_public_keys' AND column_name = 'auth_user_id'));

  IF auth_column_count = 1 THEN
    RAISE EXCEPTION 'Only one auth_user_id column exists; resolve the partial schema before continuing.';
  ELSIF auth_column_count = 2 THEN
    EXECUTE $query$
      SELECT EXISTS (
        SELECT 1
        FROM public.vault_public_keys pk
        JOIN public.vault_users vu ON vu.id = pk.user_id
        WHERE pk.auth_user_id IS NOT NULL
          AND pk.auth_user_id IS DISTINCT FROM vu.auth_user_id
      )
    $query$ INTO identity_conflict;

    IF identity_conflict THEN
      RAISE EXCEPTION 'A public-key Auth identity conflicts with its parent profile; resolve it before migration.';
    END IF;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.vault_users vu
    JOIN auth.users au
      ON lower(vu.email) = lower(au.email)
     AND au.email_confirmed_at IS NOT NULL
    GROUP BY au.id
    HAVING count(vu.id) > 1
  ) THEN
    RAISE EXCEPTION 'Multiple VaultZero profiles match one confirmed Auth user.';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.vault_users vu
    JOIN auth.users au
      ON lower(vu.email) = lower(au.email)
     AND au.email_confirmed_at IS NOT NULL
    GROUP BY vu.id
    HAVING count(au.id) > 1
  ) THEN
    RAISE EXCEPTION 'One VaultZero profile matches multiple confirmed Auth users.';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.vault_users vu
    JOIN auth.users au
      ON lower(vu.email) = lower(au.email)
     AND au.email_confirmed_at IS NOT NULL
    JOIN public.vault_public_keys pk ON pk.user_id = vu.id
    WHERE pk.status = 'active'
    GROUP BY au.id
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'An Auth user would be linked to multiple active public keys.';
  END IF;
END;
$preflight$;

ALTER TABLE public.vault_users
  ADD COLUMN IF NOT EXISTS auth_user_id uuid;
ALTER TABLE public.vault_public_keys
  ADD COLUMN IF NOT EXISTS auth_user_id uuid;

-- Add or validate the Auth foreign keys. RESTRICT retains profiles and key history.
DO $auth_fks$
DECLARE
  users_fk record;
  keys_fk record;
BEGIN
  SELECT c.confrelid, c.confdeltype, c.conkey, c.confkey
    INTO users_fk
  FROM pg_catalog.pg_constraint c
  WHERE c.conrelid = 'public.vault_users'::regclass
    AND c.conname = 'vault_users_auth_user_id_fkey'
    AND c.contype = 'f';

  IF FOUND THEN
    IF users_fk.confrelid <> 'auth.users'::regclass
       OR users_fk.confdeltype <> 'r'
       OR users_fk.conkey <> ARRAY[(
         SELECT a.attnum FROM pg_catalog.pg_attribute a
         WHERE a.attrelid = 'public.vault_users'::regclass
           AND a.attname = 'auth_user_id' AND NOT a.attisdropped
       )]::smallint[]
       OR users_fk.confkey <> ARRAY[(
         SELECT a.attnum FROM pg_catalog.pg_attribute a
         WHERE a.attrelid = 'auth.users'::regclass
           AND a.attname = 'id' AND NOT a.attisdropped
       )]::smallint[] THEN
      RAISE EXCEPTION 'Existing vault_users Auth foreign key has an unexpected definition.';
    END IF;
  ELSE
    IF EXISTS (
      SELECT 1 FROM pg_catalog.pg_constraint c
      WHERE c.conrelid = 'public.vault_users'::regclass
        AND c.contype = 'f'
        AND c.conkey = ARRAY[(
          SELECT a.attnum FROM pg_catalog.pg_attribute a
          WHERE a.attrelid = 'public.vault_users'::regclass
            AND a.attname = 'auth_user_id' AND NOT a.attisdropped
        )]::smallint[]
    ) THEN
      RAISE EXCEPTION 'Unexpected existing foreign key on vault_users.auth_user_id.';
    END IF;
    ALTER TABLE public.vault_users
      ADD CONSTRAINT vault_users_auth_user_id_fkey
      FOREIGN KEY (auth_user_id) REFERENCES auth.users(id) ON DELETE RESTRICT;
  END IF;

  SELECT c.confrelid, c.confdeltype, c.conkey, c.confkey
    INTO keys_fk
  FROM pg_catalog.pg_constraint c
  WHERE c.conrelid = 'public.vault_public_keys'::regclass
    AND c.conname = 'vault_public_keys_auth_user_id_fkey'
    AND c.contype = 'f';

  IF FOUND THEN
    IF keys_fk.confrelid <> 'auth.users'::regclass
       OR keys_fk.confdeltype <> 'r'
       OR keys_fk.conkey <> ARRAY[(
         SELECT a.attnum FROM pg_catalog.pg_attribute a
         WHERE a.attrelid = 'public.vault_public_keys'::regclass
           AND a.attname = 'auth_user_id' AND NOT a.attisdropped
       )]::smallint[]
       OR keys_fk.confkey <> ARRAY[(
         SELECT a.attnum FROM pg_catalog.pg_attribute a
         WHERE a.attrelid = 'auth.users'::regclass
           AND a.attname = 'id' AND NOT a.attisdropped
       )]::smallint[] THEN
      RAISE EXCEPTION 'Existing vault_public_keys Auth foreign key has an unexpected definition.';
    END IF;
  ELSE
    IF EXISTS (
      SELECT 1 FROM pg_catalog.pg_constraint c
      WHERE c.conrelid = 'public.vault_public_keys'::regclass
        AND c.contype = 'f'
        AND c.conkey = ARRAY[(
          SELECT a.attnum FROM pg_catalog.pg_attribute a
          WHERE a.attrelid = 'public.vault_public_keys'::regclass
            AND a.attname = 'auth_user_id' AND NOT a.attisdropped
        )]::smallint[]
    ) THEN
      RAISE EXCEPTION 'Unexpected existing foreign key on vault_public_keys.auth_user_id.';
    END IF;
    ALTER TABLE public.vault_public_keys
      ADD CONSTRAINT vault_public_keys_auth_user_id_fkey
      FOREIGN KEY (auth_user_id) REFERENCES auth.users(id) ON DELETE RESTRICT;
  END IF;
END;
$auth_fks$;

-- Replace the existing profile-to-key CASCADE, matching by columns so the
-- reported constraint name and PostgreSQL's default generated name both work.
DO $profile_fk$
DECLARE
  user_attnum smallint;
  profile_attnum smallint;
  fk record;
BEGIN
  SELECT a.attnum INTO user_attnum
  FROM pg_catalog.pg_attribute a
  WHERE a.attrelid = 'public.vault_public_keys'::regclass
    AND a.attname = 'user_id' AND NOT a.attisdropped;

  SELECT a.attnum INTO profile_attnum
  FROM pg_catalog.pg_attribute a
  WHERE a.attrelid = 'public.vault_users'::regclass
    AND a.attname = 'id' AND NOT a.attisdropped;

  FOR fk IN
    SELECT c.conname, c.confdeltype
    FROM pg_catalog.pg_constraint c
    WHERE c.conrelid = 'public.vault_public_keys'::regclass
      AND c.confrelid = 'public.vault_users'::regclass
      AND c.contype = 'f'
      AND c.conkey = ARRAY[user_attnum]::smallint[]
      AND c.confkey = ARRAY[profile_attnum]::smallint[]
  LOOP
    IF fk.confdeltype <> 'r' THEN
      EXECUTE pg_catalog.format(
        'ALTER TABLE public.vault_public_keys DROP CONSTRAINT %I', fk.conname
      );
    END IF;
  END LOOP;

  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint c
    WHERE c.conrelid = 'public.vault_public_keys'::regclass
      AND c.confrelid = 'public.vault_users'::regclass
      AND c.contype = 'f'
      AND c.conkey = ARRAY[user_attnum]::smallint[]
      AND c.confkey = ARRAY[profile_attnum]::smallint[]
      AND c.confdeltype = 'r'
  ) THEN
    ALTER TABLE public.vault_public_keys
      ADD CONSTRAINT vault_public_keys_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES public.vault_users(id) ON DELETE RESTRICT;
  END IF;
END;
$profile_fk$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_users_auth_user_id
  ON public.vault_users(auth_user_id) WHERE auth_user_id IS NOT NULL;

-- Link only confirmed, unambiguous matches. Do not rewrite email casing or audit timestamps.
UPDATE public.vault_users AS vu
SET auth_user_id = au.id,
    email_verified = true
FROM auth.users AS au
WHERE vu.auth_user_id IS NULL
  AND au.email_confirmed_at IS NOT NULL
  AND lower(vu.email) = lower(au.email);

UPDATE public.vault_public_keys AS pk
SET auth_user_id = vu.auth_user_id
FROM public.vault_users AS vu
WHERE pk.user_id = vu.id
  AND pk.auth_user_id IS NULL
  AND vu.auth_user_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_public_keys_one_active_auth_user
  ON public.vault_public_keys(auth_user_id)
  WHERE status = 'active' AND auth_user_id IS NOT NULL;

ALTER TABLE public.vault_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_public_keys ENABLE ROW LEVEL SECURITY;

-- Keep the migration-001 policies by name; narrow them to Auth identities.
ALTER POLICY "Public keys are discoverable"
  ON public.vault_public_keys TO authenticated
  USING (status = 'active' OR auth_user_id = auth.uid());

ALTER POLICY "Users can only insert own public keys"
  ON public.vault_public_keys TO authenticated
  WITH CHECK (auth_user_id = auth.uid());

ALTER POLICY "Users can only update own public keys"
  ON public.vault_public_keys TO authenticated
  USING (auth_user_id = auth.uid())
  WITH CHECK (auth_user_id = auth.uid());

-- Browser roles remain read-only. Backend access uses its server-only service role.
REVOKE ALL ON TABLE public.vault_public_keys FROM PUBLIC, anon, authenticated;
GRANT SELECT (
  key_id, owner_vault_id, owner_email, algorithm, key_size_bits,
  public_key_pem, fingerprint, status, previous_key_id, registered_at, revoked_at
) ON TABLE public.vault_public_keys TO authenticated;
REVOKE ALL ON TABLE public.vault_users FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.vault_public_keys, public.vault_users TO service_role;

-- Keep the RPC signature used by backend/app/services/database.py.
-- Ownership and audit fields are derived from the locked active key, not JSON.
CREATE OR REPLACE FUNCTION public.vaultzero_rotate_public_key(
  p_owner_profile_id uuid,
  p_auth_user_id uuid,
  p_old_key_id text,
  p_new_record jsonb,
  p_rotation_reason text
)
RETURNS SETOF public.vault_public_keys
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  old_key public.vault_public_keys%ROWTYPE;
  new_key_id text;
  new_pem text;
  new_fingerprint text;
  new_fingerprint_raw_hex text;
  reason_text text;
BEGIN
  IF pg_catalog.jsonb_typeof(p_new_record) <> 'object' THEN
    RAISE EXCEPTION 'New key record must be a JSON object.';
  END IF;

  new_key_id := p_new_record->>'key_id';
  new_pem := p_new_record->>'public_key_pem';
  new_fingerprint := p_new_record->>'fingerprint';
  new_fingerprint_raw_hex := p_new_record->>'fingerprint_raw_hex';

  IF new_key_id IS NULL OR new_pem IS NULL
     OR new_fingerprint IS NULL OR new_fingerprint_raw_hex IS NULL
     OR new_fingerprint_raw_hex !~ '^[0-9a-f]{64}$'
     OR new_key_id <> ('key_rsa2048_' || pg_catalog.substr(new_fingerprint_raw_hex, 1, 12))
     OR pg_catalog.strpos(new_pem, '-----BEGIN PUBLIC KEY-----') = 0
     OR pg_catalog.strpos(pg_catalog.upper(new_pem), 'PRIVATE KEY') > 0 THEN
    RAISE EXCEPTION 'New public key fields are invalid.';
  END IF;

  SELECT * INTO old_key
  FROM public.vault_public_keys
  WHERE key_id = p_old_key_id
    AND user_id = p_owner_profile_id
    AND auth_user_id = p_auth_user_id
    AND status = 'active'
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Active key does not belong to the authenticated user.'
      USING ERRCODE = '42501';
  END IF;

  reason_text := COALESCE(
    p_rotation_reason,
    'User-initiated cryptographic key rotation'
  );

  UPDATE public.vault_public_keys
  SET status = 'rotated',
      revoked_at = pg_catalog.now(),
      rotation_reason = reason_text
  WHERE id = old_key.id;

  RETURN QUERY
  INSERT INTO public.vault_public_keys (
    id, key_id, user_id, auth_user_id,
    owner_vault_id, owner_email, algorithm, key_size_bits,
    public_key_pem, fingerprint, fingerprint_raw_hex,
    status, previous_key_id, rotation_reason,
    created_at, registered_at, expires_at, revoked_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), new_key_id, old_key.user_id, old_key.auth_user_id,
    old_key.owner_vault_id, old_key.owner_email, old_key.algorithm, old_key.key_size_bits,
    new_pem, new_fingerprint, new_fingerprint_raw_hex,
    'active', old_key.key_id, reason_text,
    pg_catalog.now(), pg_catalog.now(), NULL, NULL
  )
  RETURNING *;
END;
$function$;

ALTER FUNCTION public.vaultzero_rotate_public_key(uuid, uuid, text, jsonb, text)
  OWNER TO postgres;

REVOKE ALL ON FUNCTION public.vaultzero_rotate_public_key(uuid, uuid, text, jsonb, text)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.vaultzero_rotate_public_key(uuid, uuid, text, jsonb, text)
  TO service_role;
