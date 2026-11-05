// AWS Lambda entry: DynamoDB + S3 + SES + Cognito + Secrets Manager, wired into core.mjs
import { DynamoDBClient, GetItemCommand, PutItemCommand, DeleteItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';
import { CognitoIdentityProviderClient, GetUserCommand, AdminCreateUserCommand, AdminSetUserPasswordCommand, AdminGetUserCommand, AdminEnableUserCommand, AdminDisableUserCommand, AdminResetUserPasswordCommand, ListUsersCommand } from '@aws-sdk/client-cognito-identity-provider';
import { randomBytes } from 'node:crypto';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { gzipSync, gunzipSync } from 'node:zlib';
import { makeCore } from './core.mjs';

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
  async create({ email, name }) {
    let sub;
    try {
      const r = await cog.send(new AdminCreateUserCommand({ ...P, Username: email, MessageAction: 'SUPPRESS',
        UserAttributes: [{ Name: 'email', Value: email }, { Name: 'email_verified', Value: 'true' }, { Name: 'name', Value: name || email.split('@')[0] }] }));
      sub = attrs(r.User.Attributes).sub;
      await cog.send(new AdminSetUserPasswordCommand({ ...P, Username: email, Permanent: true, Password: 'Bn' + randomBytes(24).toString('base64url') + 'a9' }));
    } catch (e) {
      if (e.name !== 'UsernameExistsException') throw e;
      const g = await cog.send(new AdminGetUserCommand({ ...P, Username: email })); sub = attrs(g.UserAttributes).sub;
      await cog.send(new AdminEnableUserCommand({ ...P, Username: email }));
    }
    return sub;
  },
  async list() {
    const out = []; let tok;
    do { const r = await cog.send(new ListUsersCommand({ ...P, Limit: 60, PaginationToken: tok }));
      (r.Users || []).forEach(x => { const a = attrs(x.Attributes); out.push({ sub: a.sub, email: lc(a.email), name: a.name || '', enabled: x.Enabled, status: x.UserStatus, created: x.UserCreateDate }); });
      tok = r.PaginationToken; } while (tok);
    return out;
  },
  async setEnabled(sub, on) { const u = (await this.list()).find(x => x.sub === sub); if (!u) throw Object.assign(new Error('no user'), { code: 'not_found' });
    await cog.send(new (on ? AdminEnableUserCommand : AdminDisableUserCommand)({ ...P, Username: u.email })); },
  async reset(sub) { const u = (await this.list()).find(x => x.sub === sub); if (!u) throw Object.assign(new Error('no user'), { code: 'not_found' });
    await cog.send(new AdminResetUserPasswordCommand({ ...P, Username: u.email })); }
};
let fnName = '';
const core = makeCore({ store, blobs, auth, mail, users, ownerEmail: E.OWNER_EMAIL,
  startJob: async job => { await lam.send(new InvokeCommand({ FunctionName: fnName, InvocationType: 'Event', Payload: Buffer.from(JSON.stringify({ job })) })); } });
let KEY;
const getKey = async () => { if (KEY === undefined) { try { KEY = (await sm.send(new GetSecretValueCommand({ SecretId: E.SECRET_ID }))).SecretString.trim(); } catch (e) { console.error('secret', e); KEY = ''; } } return KEY; };

export const handler = async (ev, ctx) => {
  fnName = ctx.functionName;
  if (ev.job) { await core.runJob(ev.job, { getKey, model: E.MODEL, modelComplex: E.MODEL_COMPLEX }); return { ok: true }; }
  return core.handler(ev);
};
