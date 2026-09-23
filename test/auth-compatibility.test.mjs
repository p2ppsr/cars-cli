import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { mkdtempSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import * as esm from '@bsv/sdk';
const cjs = createRequire(import.meta.url)('@bsv/sdk');
const originals = [esm, cjs].map(sdk => ({
  handshake: sdk.Peer.prototype.initiateHandshake,
  send: sdk.SimplifiedFetchTransport.prototype.send,
}));
await import('../dist/index.js');

for (const [index, sdk] of [esm, cjs].entries()) {
  const label = index === 0 ? 'ESM' : 'CommonJS';
  test(`${label}: CLI leaves SDK authentication intact`, () => {
    assert.equal(sdk.Peer.prototype.initiateHandshake, originals[index].handshake);
    assert.equal(sdk.SimplifiedFetchTransport.prototype.send, originals[index].send);
  });
  test(`${label}: synchronous mutual authentication, messages and replay rejection`, async () => {
    let receiveA, receiveB, lastGeneral;
    const walletA = new sdk.ProtoWallet(sdk.PrivateKey.fromRandom());
    const walletB = new sdk.ProtoWallet(sdk.PrivateKey.fromRandom());
    const idA = (await walletA.getPublicKey({ identityKey: true })).publicKey;
    const idB = (await walletB.getPublicKey({ identityKey: true })).publicKey;
    const peerA = new sdk.Peer(walletA, {
      onData: callback => { receiveA = callback; },
      send: async message => {
        if (message.messageType === 'general') lastGeneral = structuredClone(message);
        await receiveB(message);
      },
    });
    const peerB = new sdk.Peer(walletB, {
      onData: callback => { receiveB = callback; },
      send: async message => { await receiveA(message); },
    });
    const received = [];
    peerB.listenForGeneralMessages((sender, payload) => { received.push({sender, payload}); });
    await peerA.toPeer([1, 2, 3], idB);
    assert.deepEqual(received, [{sender: idA, payload: [1, 2, 3]}]);
    assert.equal((await peerA.getAuthenticatedSession(idB)).isAuthenticated, true);
    await assert.rejects(receiveB(structuredClone(lastGeneral)), /replay|nonce/i);
    assert.equal(received.length, 1);
  });
  test(`${label}: native auth transport rejects oversized handshake bodies`, async t => {
    const server = createServer((req, res) => {
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(' '.repeat(256));
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => server.close());
    const transport = new sdk.SimplifiedFetchTransport(
      `http://127.0.0.1:${server.address().port}`, fetch, {maxHandshakeResponseBytes: 64}
    );
    const peer = new sdk.Peer(new sdk.ProtoWallet(sdk.PrivateKey.fromRandom()), transport);
    await assert.rejects(peer.toPeer([1]), /limit|exceed|large/i);
  });
  test(`${label}: native auth transport never follows redirects`, async t => {
    let targetRequests = 0, authRequests = 0;
    const server = createServer((req, res) => {
      if (req.url === '/.well-known/auth') {
        authRequests++;
        res.writeHead(307, { Location: '/unexpected-recipient' });
      } else {
        targetRequests++;
        res.writeHead(200);
      }
      res.end('{}');
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => server.close());
    const transport = new sdk.SimplifiedFetchTransport(`http://127.0.0.1:${server.address().port}`);
    const peer = new sdk.Peer(new sdk.ProtoWallet(sdk.PrivateKey.fromRandom()), transport);
    await assert.rejects(peer.toPeer([1]), /fetch|network|redirect/i);
    assert.equal(authRequests, 1);
    assert.equal(targetRequests, 0);
  });
}

test('npm-style symlink still executes the CLI', t => {
  const dir = mkdtempSync(join(tmpdir(), 'cars-cli-entry-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const bin = join(dir, 'cars');
  symlinkSync(resolve('dist/index.js'), bin);
  const result = spawnSync(process.execPath, [bin, '--help'], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /doctor/);
  assert.match(result.stdout, /release/);
});
