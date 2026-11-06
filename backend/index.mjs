// AWS Lambda entry: DynamoDB + S3 + SES + Cognito + Secrets Manager, wired into core.mjs
import { DynamoDBClient, GetItemCommand, PutItemCommand, DeleteItemCommand, QueryCommand, TransactWriteItemsCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';
import { CognitoIdentityProviderClient, GetUserCommand, AdminCreateUserCommand, AdminSetUserPasswordCommand, AdminGetUserCommand, AdminEnableUserCommand, AdminDisableUserCommand, AdminResetUserPasswordCommand, ListUsersCommand, AdminSetUserMFAPreferenceCommand } from '@aws-sdk/client-cognito-identity-provider';
import { createSign, createHmac, createHash } from 'node:crypto';
import { ApiGatewayManagementApiClient, PostToConnectionCommand } from '@aws-sdk/client-apigatewaymanagementapi';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { gzipSync, gunzipSync } from 'node:zlib';
import { makeCore, tenantOf } from './core.mjs';

const E = process.env;
const ddb = new DynamoDBClient({}), s3 = new S3Client({}), ses = new SESv2Client({}), cog = new CognitoIdentityProviderClient({}), sm = new SecretsManagerClient({}), lam = new LambdaClient({});
const lc = s => String(s || '').trim().toLowerCase();

// documents are stored gzip-compressed to stay well under DynamoDB's 400 KB item limit
const pack = d => gzipSync(Buffer.from(JSON.stringify(d)));
const unpack = i => JSON.parse(gunzipSync(Buffer.from(i.data.B)).toString('utf8'));
const store = {
  async get(pk, sk) { const r = await ddb.send(new GetItemCommand({ TableName: E.TABLE, Key: { pk: { S: pk }, sk: { S: sk } } })); return r.Item ? unpack(r.Item) : null; },
  async put(pk, sk, data, ttl) {
    const Item = { pk: { S: pk }, sk: { S: sk }, data: { B: pack(data) }, at: { S: new Date().toISOString() } };
    if (ttl) Item.ttl = { N: String(ttl) };
    await ddb.send(new PutItemCommand({ TableName: E.TABLE, Item }));
  },
  async del(pk, sk) { await ddb.send(new DeleteItemCommand({ TableName: E.TABLE, Key: { pk: { S: pk }, sk: { S: sk } } })); },
  async list(pk) {
    const out = []; let k;
    do { const r = await ddb.send(new QueryCommand({ TableName: E.TABLE, KeyConditionExpression: 'pk = :p', ExpressionAttributeValues: { ':p': { S: pk } }, ExclusiveStartKey: k }));
      (r.Items || []).forEach(i => out.push({ id: i.sk.S, data: unpack(i) })); k = r.LastEvaluatedKey; } while (k);
    return out;
  },
  // versioned records (see docs.mjs)
  async items(pk) {
    const out = []; let k;
    do { const r = await ddb.send(new QueryCommand({ TableName: E.TABLE, KeyConditionExpression: 'pk = :p', ExpressionAttributeValues: { ':p': { S: pk } }, ExclusiveStartKey: k }));
      (r.Items || []).forEach(i => out.push({ sk: i.sk.S, data: unpack(i), v: +(i.v ? i.v.N : 0), o: +(i.o ? i.o.N : 0), by: i.by ? i.by.S : '' })); k = r.LastEvaluatedKey; } while (k);
    return out;
  },
  async txn(ops) {
    const TransactItems = ops.map(op => {
      const cond = op.cond === null ? { ConditionExpression: 'attribute_not_exists(pk)' } : { ConditionExpression: '#v = :v', ExpressionAttributeNames: { '#v': 'v' }, ExpressionAttributeValues: { ':v': { N: String(op.cond) } } };
      if (op.put) { const x = op.put; return { Put: Object.assign({ TableName: E.TABLE, Item: { pk: { S: x.pk }, sk: { S: x.sk }, data: { B: pack(x.data) }, v: { N: String(x.v) }, o: { N: String(x.o || 0) }, by: { S: x.by || '' }, at: { S: new Date().toISOString() } } }, cond) }; }
      return { Delete: Object.assign({ TableName: E.TABLE, Key: { pk: { S: op.del.pk }, sk: { S: op.del.sk } } }, cond) };
    });
    try { await ddb.send(new TransactWriteItemsCommand({ TransactItems })); }
    catch (e) { if (e.name === 'TransactionCanceledException' || e.name === 'ConditionalCheckFailedException') throw Object.assign(new Error('conflict'), { code: 'conflict' }); throw e; }
  }
};
const blobs = {
  async put(key, buf, ct) { await s3.send(new PutObjectCommand({ Bucket: E.ASSETS, Key: key, Body: buf, ContentType: ct, CacheControl: 'private, max-age=31536000, immutable' })); },
  async get(key) { try { const o = await s3.send(new GetObjectCommand({ Bucket: E.ASSETS, Key: key })); return { buf: Buffer.from(await o.Body.transformToByteArray()), ct: o.ContentType }; } catch (e) { return null; } }
};
const tokCache = new Map();
async function auth(h) {
  const t = h['x-bannaa-token']; if (!t) return null;
  const c = tokCache.get(t); if (c && c.exp > Date.now()) return c.u;
  try {
    const r = await cog.send(new GetUserCommand({ AccessToken: t }));
    const a = Object.fromEntries((r.UserAttributes || []).map(x => [x.Name, x.Value]));
    if (a.email_verified !== 'true') return null;
    const u = { id: 'u_' + a.sub, email: lc(a.email), name: a.name || '' };
    tokCache.set(t, { u, exp: Date.now() + 5 * 60e3 }); if (tokCache.size > 500) tokCache.clear();
    return u;
  } catch (e) { return null; }
}
async function mail({ to, subject, text, html }) {
  await ses.send(new SendEmailCommand({ FromEmailAddress: E.SENDER_EMAIL, Destination: { ToAddresses: to },
    Content: { Simple: { Subject: { Data: subject, Charset: 'UTF-8' }, Body: Object.assign({ Text: { Data: text, Charset: 'UTF-8' } }, html ? { Html: { Data: html, Charset: 'UTF-8' } } : {}) } } }));
}
const attrs = a => Object.fromEntries((a || []).map(x => [x.Name, x.Value]));
const P = { UserPoolId: E.USER_POOL_ID };
// Accounts are created by the admin only; the user sets their own password with "Forgot your password?"
const users = {
  async create({ email, name, password, temporary }) {
    let sub;
    try {
      const r = await cog.send(new AdminCreateUserCommand({ ...P, Username: email, MessageAction: 'SUPPRESS',
        UserAttributes: [{ Name: 'email', Value: email }, { Name: 'email_verified', Value: 'true' }, { Name: 'name', Value: name || email.split('@')[0] }] }));
      sub = attrs(r.User.Attributes).sub;
      await cog.send(new AdminSetUserPasswordCommand({ ...P, Username: email, Permanent: !temporary, Password: password }));
    } catch (e) {
      if (e.name !== 'UsernameExistsException') throw e;
      const g = await cog.send(new AdminGetUserCommand({ ...P, Username: email })); sub = attrs(g.UserAttributes).sub;
      await cog.send(new AdminEnableUserCommand({ ...P, Username: email }));
      await cog.send(new AdminSetUserPasswordCommand({ ...P, Username: email, Permanent: !temporary, Password: password }));
    }
    return sub;
  },
  async list() {
    const out = []; let tok;
    do { const r = await cog.send(new ListUsersCommand({ ...P, Limit: 60, PaginationToken: tok }));
      (r.Users || []).forEach(x => { const a = attrs(x.Attributes); out.push({ sub: a.sub, email: lc(a.email), name: a.name || '', enabled: x.Enabled, status: x.UserStatus, created: x.UserCreateDate }); });
      tok = r.PaginationToken; } while (tok);
    await Promise.all(out.map(async u => { try { const g = await cog.send(new AdminGetUserCommand({ ...P, Username: u.email })); u.mfa = (g.UserMFASettingList || []).includes('SOFTWARE_TOKEN_MFA'); } catch (e) {} }));
    return out;
  },
  async setEnabled(sub, on) { const u = (await this.list()).find(x => x.sub === sub); if (!u) throw Object.assign(new Error('no user'), { code: 'not_found' });
    await cog.send(new (on ? AdminEnableUserCommand : AdminDisableUserCommand)({ ...P, Username: u.email })); },
  async setPassword(sub, password, temporary) { const u = (await this.list()).find(x => x.sub === sub); if (!u) throw Object.assign(new Error('no user'), { code: 'not_found' });
    await cog.send(new AdminSetUserPasswordCommand({ ...P, Username: u.email, Permanent: !temporary, Password: password })); },
  async mfaOff(sub) { const u = (await this.list()).find(x => x.sub === sub); if (!u) throw Object.assign(new Error('no user'), { code: 'not_found' });
    await cog.send(new AdminSetUserMFAPreferenceCommand({ ...P, Username: u.email, SoftwareTokenMfaSettings: { Enabled: false, PreferredMfa: false } })); },
  async reset(sub) { const u = (await this.list()).find(x => x.sub === sub); if (!u) throw Object.assign(new Error('no user'), { code: 'not_found' });
    await cog.send(new AdminResetUserPasswordCommand({ ...P, Username: u.email })); }
};
// CloudFront signed cookies: site photos (/_blob/*) load only for signed-in members
let CFKEY;
const cfB64 = b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/=/g, '_').replace(/\//g, '~');
async function cookies(u, h, tid) {
  if (!E.CF_KEY_PAIR_ID) return [];
  if (CFKEY === undefined) { try { CFKEY = (await sm.send(new GetSecretValueCommand({ SecretId: E.CF_KEY_SECRET }))).SecretString; } catch (e) { console.error('cf key', e); CFKEY = ''; } }
  if (!CFKEY) return [];
  const exp = Math.floor(Date.now() / 1000) + 12 * 3600;
  const policy = JSON.stringify({ Statement: [{ Resource: `https://*/_blob/${tid}/*`, Condition: { DateLessThan: { 'AWS:EpochTime': exp } } }] });   // this company's files only
  const sig = createSign('RSA-SHA1').update(policy).sign(CFKEY);
  const opt = '; Path=/_blob/; Secure; HttpOnly; SameSite=Lax; Max-Age=43200';
  return [`CloudFront-Policy=${cfB64(policy)}${opt}`, `CloudFront-Signature=${cfB64(sig)}${opt}`, `CloudFront-Key-Pair-Id=${E.CF_KEY_PAIR_ID}${opt}`];
}
// S3 presigned PUT (SigV4, query-string auth) — large documents upload straight to storage
const uriEnc = x => encodeURIComponent(x).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
export function presignUrl({ method = 'PUT', host, key, region, accessKey, secretKey, token, now = new Date(), expires = 900, payload = 'UNSIGNED-PAYLOAD' }) {
  const amz = now.toISOString().replace(/[:-]|\.\d{3}/g, ''), date = amz.slice(0, 8), scope = `${date}/${region}/s3/aws4_request`;
  const q = { 'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': `${accessKey}/${scope}`, 'X-Amz-Date': amz, 'X-Amz-Expires': String(expires), 'X-Amz-SignedHeaders': 'host' };
  if (token) q['X-Amz-Security-Token'] = token;
  const qs = Object.keys(q).sort().map(k => uriEnc(k) + '=' + uriEnc(q[k])).join('&'), path = '/' + key.split('/').map(uriEnc).join('/');
  const canon = [method, path, qs, `host:${host}\n`, 'host', payload].join('\n');
  const sts = ['AWS4-HMAC-SHA256', amz, scope, createHash('sha256').update(canon).digest('hex')].join('\n');
  const hm = (k, d) => createHmac('sha256', k).update(d).digest();
  const sig = createHmac('sha256', hm(hm(hm(hm('AWS4' + secretKey, date), region), 's3'), 'aws4_request')).update(sts).digest('hex');
  return `https://${host}${path}?${qs}&X-Amz-Signature=${sig}`;
}
const presign = async (key, ct) => ({ uploadUrl: presignUrl({ host: `${E.ASSETS}.s3.${E.AWS_REGION}.amazonaws.com`, key, region: E.AWS_REGION, accessKey: E.AWS_ACCESS_KEY_ID, secretKey: E.AWS_SECRET_ACCESS_KEY, token: E.AWS_SESSION_TOKEN }), method: 'PUT', headers: { 'content-type': ct } });

// live updates: tell every open browser of the same company that a document changed (they then fetch only the delta)
const wsApi = E.WS_ENDPOINT ? new ApiGatewayManagementApiClient({ endpoint: E.WS_ENDPOINT }) : null;
async function broadcast(tid, path) {
  if (!wsApi) return;
  const conns = await store.list('WS#' + tid), Data = Buffer.from(JSON.stringify({ type: 'changed', path }));
  await Promise.allSettled(conns.map(async c => { try { await wsApi.send(new PostToConnectionCommand({ ConnectionId: c.id, Data })); }
    catch (e) { if (e.name === 'GoneException' || (e.$metadata && e.$metadata.httpStatusCode === 410)) await store.del('WS#' + tid, c.id); } }));
}
let fnName = '';
const core = makeCore({ store, blobs, auth, mail, users, cookies, broadcast, presign, ownerEmail: E.OWNER_EMAIL,
  startJob: async job => { await lam.send(new InvokeCommand({ FunctionName: fnName, InvocationType: 'Event', Payload: Buffer.from(JSON.stringify({ job })) })); } });
let KEY;
const getKey = async () => { if (KEY === undefined) { try { KEY = (await sm.send(new GetSecretValueCommand({ SecretId: E.SECRET_ID }))).SecretString.trim(); } catch (e) { console.error('secret', e); KEY = ''; } } return KEY; };

export const handler = async (ev, ctx) => {
  fnName = ctx.functionName;
  if (ev.job) { await core.runJob(ev.job, { getKey, model: E.MODEL, modelComplex: E.MODEL_COMPLEX }); return { ok: true }; }
  // only CloudFront (which adds this secret header) may call the API — blocks anyone bypassing the firewall
  const h = ev.headers || {};
  if (E.ORIGIN_SECRET && (h['x-origin-verify'] || h['X-Origin-Verify']) !== E.ORIGIN_SECRET) return { statusCode: 403, body: '{"code":"forbidden"}' };
  const r = await core.handler(ev);
  // Lambda responses are capped at 6 MB — compress big JSON (a project with thousands of records) ~10x
  const ae = h['accept-encoding'] || h['Accept-Encoding'] || '';
  if (r && typeof r.body === 'string' && r.body.length > 64 * 1024 && /gzip/.test(ae) && !r.isBase64Encoded) {
    r.body = gzipSync(Buffer.from(r.body)).toString('base64'); r.isBase64Encoded = true;
    r.headers = Object.assign({}, r.headers, { 'content-encoding': 'gzip', vary: 'accept-encoding' });
  }
  return r;
};

// WebSocket API ($connect / $disconnect / $default) — the token is checked when the browser connects
export const ws = async ev => {
  const rc = ev.requestContext || {}, id = rc.connectionId, ttl = Math.floor(Date.now() / 1000) + 3 * 3600;
  if (rc.routeKey === '$connect') {
    const u = await auth({ 'x-bannaa-token': (ev.queryStringParameters || {}).t || '' });
    if (!u) return { statusCode: 401 };
    const tid = await tenantOf(store, u, E.OWNER_EMAIL);
    await store.put('WS#' + tid, id, { uid: u.id }, ttl); await store.put('WSC', id, { tid }, ttl);
    return { statusCode: 200 };
  }
  if (rc.routeKey === '$disconnect') { const m = await store.get('WSC', id); if (m) await store.del('WS#' + m.tid, id); await store.del('WSC', id); }
  return { statusCode: 200 };
};
