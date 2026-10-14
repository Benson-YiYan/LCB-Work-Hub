-- Site-local practice-area configuration. Does not modify existing matters, keys or storage.
begin;
create table if not exists public.lcb_practice_areas(
 id text primary key, name jsonb not null, members jsonb not null,
 deleted boolean not null default false, created_at timestamptz not null default now()
);
alter table public.lcb_practice_areas enable row level security;
revoke all on public.lcb_practice_areas from public,anon,authenticated;
insert into public.lcb_practice_areas(id,name,members) values
('mx_invest','{"zh":"墨西哥公司／投资","en":"Corporate matters / Investment in Mexico","es":"Derecho corporativo / Inversión en México"}'::jsonb,'["carol","carlos","hector"]'::jsonb),
('mx_reg','{"zh":"墨西哥监管","en":"Regulatory matters in Mexico","es":"Regulación en México"}'::jsonb,'["carol","carlos","hector"]'::jsonb),
('sanctions','{"zh":"制裁／涉美","en":"Sanctions / U.S.-related","es":"Sanciones / Asuntos relacionados con EE. UU."}'::jsonb,'["carol","carlos"]'::jsonb),
('aml','{"zh":"反洗钱／跨境支付","en":"AML / Cross-border Payments","es":"Prevención de lavado de dinero / Pagos transfronterizos"}'::jsonb,'["carol","carlos","hector"]'::jsonb),
('dispute','{"zh":"争议解决","en":"Dispute Resolution","es":"Resolución de disputas"}'::jsonb,'["carol","carlos","hector"]'::jsonb),
('internal','{"zh":"内部项目","en":"Internal Project","es":"Proyecto interno"}'::jsonb,'["carol","carlos","hector"]'::jsonb),
('other','{"zh":"其他","en":"Other","es":"Otro"}'::jsonb,'["carol","carlos","hector"]'::jsonb)
on conflict(id) do nothing;
-- Preserve previously configured defaults without overwriting on reapplication.
do $migration$
begin
 if to_regclass('public.lcb_team_preferences') is not null then
  update public.lcb_practice_areas a set members=p.value->a.id
  from public.lcb_team_preferences p where p.id='default_teams'
  and jsonb_typeof(p.value->a.id)='array'
  and not exists(select 1 from jsonb_array_elements_text(p.value->a.id) u where u not in ('carol','carlos','hector'))
  and a.created_at=now();
 end if;
end $migration$;
create or replace function public.lcb_get_practice_areas() returns jsonb
language plpgsql security definer set search_path=public as $$
begin
 if public.lcb_team_id() is null or public.lcb_team_id() not in ('carol','carlos','hector') then raise exception 'authentication required'; end if;
 return coalesce((select jsonb_agg(jsonb_build_object('id',id,'name',name,'members',members,'deleted',deleted) order by created_at,id) from public.lcb_practice_areas),'[]'::jsonb);
end $$;
create or replace function public.lcb_mutate_practice_area(payload jsonb) returns jsonb
language plpgsql security definer set search_path=public as $$
declare uid text:=public.lcb_team_id(); action text:=payload->>'action'; area_id text:=payload->>'id';
 names jsonb:=payload->'name'; selected jsonb:=payload->'members'; snap jsonb; blocked jsonb;
begin
 if uid is null or uid not in ('carol','carlos','hector') then raise exception 'authentication required'; end if;
 if payload is null or jsonb_typeof(payload)<>'object' then raise exception 'invalid practice area'; end if;
 if action not in ('create','member','delete') or action is null then raise exception 'invalid action'; end if;
 if action in ('member','delete') and uid not in ('carol') then raise exception 'admin required'; end if;
 if action='create' then
  if area_id is null or area_id !~ '^custom_[a-zA-Z0-9_-]{1,80}$' or jsonb_typeof(names) is distinct from 'object' then raise exception 'invalid practice area'; end if;
  if exists(select 1 from unnest(array['zh','en','es']) locale where jsonb_typeof(names->locale) is distinct from 'string' or length(btrim(names->>locale)) not between 1 and 100) then raise exception 'invalid name'; end if;
  if jsonb_typeof(selected) is distinct from 'array' or exists(select 1 from jsonb_array_elements(selected) u where jsonb_typeof(u)<>'string' or u#>>'{}' not in ('carol','carlos','hector')) then raise exception 'invalid members'; end if;
  lock table public.lcb_practice_areas in share row exclusive mode;
  if exists(select 1 from public.lcb_practice_areas a where not deleted and lower(btrim(a.name->>'zh'))=lower(btrim(names->>'zh'))) then raise exception 'duplicate practice area'; end if;
  insert into public.lcb_practice_areas(id,name,members) values(area_id,names,selected);
 elsif action='member' then
  if payload->>'user' is null or payload->>'user' not in ('carol','carlos','hector') or jsonb_typeof(payload->'enabled') is distinct from 'boolean' then raise exception 'invalid members'; end if;
  update public.lcb_practice_areas set members=case when (payload->>'enabled')::boolean
   then case when members ? (payload->>'user') then members else members||jsonb_build_array(payload->>'user') end
   else coalesce((select jsonb_agg(u) from jsonb_array_elements(members) u where u#>>'{}'<>payload->>'user'),'[]'::jsonb) end
   where id=area_id and not deleted;
  if not found then raise exception 'practice area unavailable'; end if;
 else
  -- Encrypted bodies cannot be inspected in SQL. A fresh, complete decrypted
  -- snapshot is supplied only by an authorized administrator. No names are sent.
  -- Table lock + row timestamps prevent a stale/concurrent snapshot from being used.
  snap:=payload->'snapshot';
  if jsonb_typeof(snap) is distinct from 'array' then raise exception 'stale matter snapshot'; end if;
  lock table public.matters in share mode;
  perform 1 from public.lcb_practice_areas where id=area_id and not deleted for update;
  if not found then raise exception 'practice area unavailable'; end if;
  if jsonb_array_length(snap)<>(select count(*) from public.matters)
    or jsonb_array_length(snap)<>(select count(distinct x->>'id') from jsonb_array_elements(snap) x)
    or exists(select 1 from public.matters m left join jsonb_to_recordset(snap) x(id text,updated_at timestamptz,area text,kind text) on x.id=m.id
     where x.id is null or x.updated_at is distinct from m.updated_at or (m.data->>'encrypted'='lcb-e2ee-v1' and (x.area is null or x.kind is null)))
  then raise exception 'stale matter snapshot'; end if;
  select coalesce(jsonb_agg(m.id order by m.id),'[]'::jsonb) into blocked
   from public.matters m join jsonb_to_recordset(snap) x(id text,area text,kind text) on x.id=m.id
   where coalesce(case when m.data->>'encrypted'='lcb-e2ee-v1' then x.area else m.data->>'area' end,'')=area_id
   and coalesce(case when m.data->>'encrypted'='lcb-e2ee-v1' then x.kind else m.data->>'kind' end,'') not in ('schedule','client','chat-channel');
  if jsonb_array_length(blocked)>0 then return jsonb_build_object('blocked',blocked); end if;
  update public.lcb_practice_areas set deleted=true where id=area_id;
 end if;
 return jsonb_build_object('areas',public.lcb_get_practice_areas());
end $$;
revoke all on function public.lcb_get_practice_areas() from public,anon;
revoke all on function public.lcb_mutate_practice_area(jsonb) from public,anon;
grant execute on function public.lcb_get_practice_areas() to authenticated;
grant execute on function public.lcb_mutate_practice_area(jsonb) to authenticated;
notify pgrst,'reload schema';
commit;

