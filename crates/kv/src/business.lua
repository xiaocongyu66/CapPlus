-- Redis 7 required. No rollback guarantee on runtime errors or lost replies.
local op = ARGV[1]
local expected = {'hash','string','string','string','string'}
for i,k in ipairs(KEYS) do
  if not ((op == 'consume' or op == 'state') and i == 2) then
    local t = redis.call('TYPE', k).ok
    if t ~= 'none' and t ~= expected[i] then return redis.error_reply('WRONGTYPE business') end
  end
end
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000)
local r = redis.call('HMGET',KEYS[1],'schema','fp','claims','credential','iat','exp','state','until','result','result_exp','bind')
local exists = r[1] ~= false
if not exists and redis.call('EXISTS',KEYS[1]) == 1 then return redis.error_reply('invalid business record') end
if exists then
  if r[1] ~= '1' or not r[2] or not r[3] or not r[4] or not tonumber(r[5]) or not tonumber(r[6]) or not tonumber(r[8]) or (r[7] ~= 'issued' and r[7] ~= 'solved' and r[7] ~= 'consumed') then return redis.error_reply('invalid business record') end
  local ok, claims = pcall(cjson.decode, r[3])
  if not ok or type(claims) ~= 'table' or claims.typ ~= 'cap-business' or claims.v ~= 1 or claims.iat ~= tonumber(r[5]) or claims.exp ~= tonumber(r[6]) or tonumber(r[6])-tonumber(r[5]) < 1 or tonumber(r[6])-tonumber(r[5]) > 300000 or tonumber(r[5]) > now or tonumber(r[8]) <= now then
    return redis.error_reply('inconsistent business claims')
  end
  if r[2] ~= ARGV[2] then return {'conflict'} end
  if tonumber(r[6]) <= now then return {'expired'} end
  if r[7] == 'consumed' then return {'used'} end
end
local function acl(cmd,...)
  if not redis.acl_check_cmd(cmd,...) then error('NOPERM business preflight') end
end
if op == 'issue' then
  if exists then
    if r[7] ~= 'issued' then return {'used'} end
    return {'ok',r[3],r[4]}
  end
  local iat,exp = tonumber(ARGV[5]),tonumber(ARGV[6])
  if iat > now or exp <= now then return {'expired'} end
  local until_ms = now + 86400000
  acl('HSET',KEYS[1],'schema','1','fp',ARGV[2],'claims',ARGV[3],'credential',ARGV[4],'iat',ARGV[5],'exp',ARGV[6],'state','issued','until',until_ms)
  acl('PEXPIREAT',KEYS[1],until_ms)
  redis.call('HSET',KEYS[1],'schema','1','fp',ARGV[2],'claims',ARGV[3],'credential',ARGV[4],'iat',ARGV[5],'exp',ARGV[6],'state','issued','until',until_ms)
  redis.call('PEXPIREAT',KEYS[1],until_ms)
  return {'ok',ARGV[3],ARGV[4]}
end
if not exists then return {'invalid'} end
if op == 'check' or op == 'complete' then
  if r[3] ~= ARGV[3] or r[4] ~= ARGV[4] then return {'mismatch'} end
  if r[7] ~= 'issued' then return {'used'} end
  if op == 'check' then return {'ok'} end
  local challenge_exp,lifetime = tonumber(ARGV[9]),tonumber(ARGV[10])
  if challenge_exp <= now then return {'expired'} end
  local exp = math.min(tonumber(r[6]),now+lifetime)
  for i=2,5 do if redis.call('EXISTS',KEYS[i]) == 1 then return {'used'} end end
  acl('SET',KEYS[2],'1','PXAT',challenge_exp)
  acl('SET',KEYS[3],tostring(exp),'PXAT',exp)
  acl('SET',KEYS[4],ARGV[8],'PXAT',exp)
  acl('SET',KEYS[5],'1','PXAT',exp)
  acl('HSET',KEYS[1],'state','solved','result',ARGV[7],'result_exp',tostring(exp),'bind',ARGV[8])
  redis.call('SET',KEYS[2],'1','PXAT',challenge_exp)
  redis.call('SET',KEYS[3],tostring(exp),'PXAT',exp)
  redis.call('SET',KEYS[4],ARGV[8],'PXAT',exp)
  redis.call('SET',KEYS[5],'1','PXAT',exp)
  -- Authority is committed LAST; orphan markers cannot authorize consumption.
  redis.call('HSET',KEYS[1],'state','solved','result',ARGV[7],'result_exp',tostring(exp),'bind',ARGV[8])
  return {'ok',tostring(exp)}
end
if op == 'consume' or op == 'state' then
  if r[7] ~= 'solved' then return {'invalid'} end
  if not r[9] or not tonumber(r[10]) or not r[11] then return redis.error_reply('invalid solved record') end
  if r[9] ~= ARGV[7] then return {'mismatch'} end
  if tonumber(r[10]) <= now then return {'expired'} end
  if tonumber(r[10]) > tonumber(r[6]) then return redis.error_reply('invalid result expiry') end
  if op == 'state' then
    if redis.call('GET',KEYS[3]) ~= r[10] or redis.call('GET',KEYS[4]) ~= r[11] or redis.call('GET',KEYS[5]) ~= '1' then return {'invalid'} end
    return {'ok',r[11],r[10]}
  end
  -- Compare the exact snapshot checked by the caller, even if another writer
  -- replaced BOTH authority and marker consistently after the caller's read.
  if r[11] ~= ARGV[8] or redis.call('GET',KEYS[4]) ~= ARGV[8] then return {'mismatch'} end
  if redis.call('GET',KEYS[3]) ~= r[10] or redis.call('GET',KEYS[5]) ~= '1' then return {'invalid'} end
  acl('HSET',KEYS[1],'state','consumed')
  acl('DEL',KEYS[3],KEYS[4],KEYS[5])
  redis.call('HSET',KEYS[1],'state','consumed')
  redis.call('DEL',KEYS[3],KEYS[4],KEYS[5])
  return {'ok',r[11]}
end
return redis.error_reply('invalid business operation')
