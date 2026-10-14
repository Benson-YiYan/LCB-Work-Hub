-- LOCAL disposable PostgreSQL only; fixtures roll back.
begin;
do $$
declare payload jsonb; uid text;
begin
 perform set_config('test.app_user','carol',true);
 payload:=jsonb_build_object(
 'matters',jsonb_build_array(jsonb_build_object('id','M1','data',jsonb_build_object('encrypted','lcb-e2ee-v1'))),
 'lcb_private_keys',jsonb_build_array(
 jsonb_build_object('user_id','carol','salt','new','private_iv','new','private_cipher','backup-carol'),
 jsonb_build_object('user_id','carlos','salt','new','private_iv','new','private_cipher','backup-carlos'),
 jsonb_build_object('user_id','hector','salt','new','private_iv','new','private_cipher','backup-hector')),
 'lcb_matter_keys',jsonb_build_array(
 jsonb_build_object('matter_id','M1','user_id','carol','wrapped_key','wk-carol'),
 jsonb_build_object('matter_id','M1','user_id','carlos','wrapped_key','wk-carlos'),
 jsonb_build_object('matter_id','M1','user_id','hector','wrapped_key','wk-hector')));
 insert into public.lcb_private_keys(user_id,salt,private_iv,private_cipher)
 values('carol','old','old','original-carol'),('carlos','old','old','original-carlos'),('hector','old','old','original-hector');
 -- Empty matter-key table: all three recipients must be restored.
 perform public.lcb_restore_encrypted_backup(payload);
 foreach uid in array array['carol','carlos','hector'] loop
  if (select wrapped_key from public.lcb_matter_keys where matter_id='M1' and user_id=uid) is distinct from 'wk-'||uid then
   raise exception 'FAIL: missing or incorrect restored matter key for %',uid;
  end if;
 end loop;
 if (select private_cipher from public.lcb_private_keys where user_id='carol') is distinct from 'backup-carol' then raise exception 'FAIL: Carol private key not restored'; end if;
 foreach uid in array array['carlos','hector'] loop
  if (select private_cipher from public.lcb_private_keys where user_id=uid) is distinct from 'original-'||uid then raise exception 'FAIL: other private key overwritten'; end if;
 end loop;
 perform public.lcb_restore_encrypted_backup(payload);
 if (select count(*) from public.lcb_matter_keys)<>3 then raise exception 'FAIL: restore not idempotent'; end if;
 -- Partial backup must preserve existing recipient keys.
 update public.lcb_matter_keys set wrapped_key='EXISTING-'||user_id where user_id in ('carlos','hector');
 perform public.lcb_restore_encrypted_backup(jsonb_build_object('lcb_matter_keys',jsonb_build_array(
 jsonb_build_object('matter_id','M1','user_id','carol','wrapped_key','new-carol'))));
 foreach uid in array array['carlos','hector'] loop
  if (select wrapped_key from public.lcb_matter_keys where matter_id='M1' and user_id=uid) is distinct from 'EXISTING-'||uid then raise exception 'FAIL: existing recipient key changed'; end if;
 end loop;
 foreach uid in array array['carlos','hector',''] loop
  perform set_config('test.app_user',uid,true);
  begin
   perform public.lcb_restore_encrypted_backup('{}');
   raise exception 'FAIL: non-admin restore accepted';
  exception when others then if sqlerrm<>'admin required' then raise; end if; end;
 end loop;
end $$;
do $$ begin
 if has_function_privilege('anon','public.lcb_restore_encrypted_backup(jsonb)','EXECUTE') then raise exception 'FAIL: anonymous execution grant'; end if;
 if not has_function_privilege('authenticated','public.lcb_restore_encrypted_backup(jsonb)','EXECUTE') then raise exception 'FAIL: authenticated execution missing'; end if;
end $$;
rollback;
