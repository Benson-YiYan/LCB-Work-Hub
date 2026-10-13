create table if not exists public.lcb_team_preferences (
  id text primary key check (id='default_teams'),
  value jsonb not null default '{}'::jsonb
);
alter table public.lcb_team_preferences enable row level security;
revoke all on public.lcb_team_preferences from public,anon,authenticated;
create or replace function public.lcb_get_default_teams() returns jsonb
language plpgsql security definer set search_path=public as $$
begin
  if public.lcb_app_user_id() is null then raise exception 'authentication required'; end if;
  return coalesce((select value from public.lcb_team_preferences where id='default_teams'),'{}'::jsonb);
end $$;
create or replace function public.lcb_set_default_teams(payload jsonb) returns void
language plpgsql security definer set search_path=public as $$
begin
  if public.lcb_app_user_id() is distinct from 'carol' then raise exception 'Carol only'; end if;
  if jsonb_typeof(payload)<>'object' then raise exception 'invalid defaults'; end if;
  insert into public.lcb_team_preferences(id,value) values('default_teams',payload)
  on conflict(id) do update set value=excluded.value;
end $$;
revoke all on function public.lcb_get_default_teams() from public,anon;
revoke all on function public.lcb_set_default_teams(jsonb) from public,anon;
grant execute on function public.lcb_get_default_teams() to authenticated;
grant execute on function public.lcb_set_default_teams(jsonb) to authenticated;
