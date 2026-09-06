import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { NONCE_BYTES, MAC_BYTES } from '../../src/control/control-auth.js';
import { encodeBase64Url } from '../../src/control/control-codec.js';
import {
  buildHelloBody,
  buildRequestBody,
  buildResultBody,
  FRAME_ERROR,
  FrameAccumulator,
  frameMessage,
  MAX_BODY_BYTES,
  parseClientRequest,
  parseHelloBody,
  parseResultBody,
  PROTOCOL_VERSION,
} from '../../src/control/control-channel.js';
import { CONTROL_RESULT } from '../../src/control/control-command.js';

function validRequestBody(command = 'OPEN_HUMAN_GATE'): Buffer {
  return buildRequestBody(randomBytes(NONCE_BYTES), command, randomBytes(MAC_BYTES));
}

describe('D062 frame accumulator — bounded, one frame per connection', () => {
  it('is incomplete below the length prefix', () => {
    const acc = new FrameAccumulator();
    acc.push(Buffer.from([0, 0]));
    expect(acc.tryRead().kind).toBe('incomplete');
  });

  it('rejects a zero-length frame', () => {
    const acc = new FrameAccumulator();
    acc.push(Buffer.from([0, 0, 0, 0]));
    const outcome = acc.tryRead();
    expect(outcome.kind).toBe('error');
    if (outcome.kind === 'error') {
      expect(outcome.reason).toBe(FRAME_ERROR.ZERO_LENGTH);
    }
  });

  it('rejects an oversized declared length', () => {
    const acc = new FrameAccumulator();
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(MAX_BODY_BYTES + 1, 0);
    acc.push(prefix);
    const outcome = acc.tryRead();
    expect(outcome.kind).toBe('error');
    if (outcome.kind === 'error') {
      expect(outcome.reason).toBe(FRAME_ERROR.OVERSIZED);
    }
  });

  it('accumulates partial reads into one frame', () => {
    const acc = new FrameAccumulator();
    const body = Buffer.from('hello', 'utf8');
    const framed = frameMessage(body);
    acc.push(framed.subarray(0, 2));
    expect(acc.tryRead().kind).toBe('incomplete');
    acc.push(framed.subarray(2, 5));
    expect(acc.tryRead().kind).toBe('incomplete');
    acc.push(framed.subarray(5));
    const outcome = acc.tryRead();
    expect(outcome.kind).toBe('frame');
    if (outcome.kind === 'frame') {
      expect(outcome.body.equals(body)).toBe(true);
    }
  });

  it('rejects extra bytes past one frame (a second request on the same connection)', () => {
    const acc = new FrameAccumulator();
    const framed = frameMessage(Buffer.from('one', 'utf8'));
    acc.push(Buffer.concat([framed, Buffer.from([0, 0, 0, 1, 65])]));
    const outcome = acc.tryRead();
    expect(outcome.kind).toBe('error');
    if (outcome.kind === 'error') {
      expect(outcome.reason).toBe(FRAME_ERROR.EXTRA_DATA);
    }
  });
});

describe('D062 client-request parser — hostile input, fail closed', () => {
  it('accepts a well-formed request (command vocabulary is checked later)', () => {
    const parsed = parseClientRequest(validRequestBody());
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.command).toBe('OPEN_HUMAN_GATE');
      expect(parsed.nonceC.length).toBe(NONCE_BYTES);
      expect(parsed.mac.length).toBe(MAC_BYTES);
    }
  });

  it('carries an unknown command string through parsing (rejected at dispatch, not here)', () => {
    const parsed = parseClientRequest(validRequestBody('CLOSE_REQUESTED'));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.command).toBe('CLOSE_REQUESTED');
    }
  });

  it('rejects invalid UTF-8', () => {
    expect(parseClientRequest(Buffer.from([0xff, 0xfe, 0xfd])).ok).toBe(false);
  });

  it('rejects malformed JSON', () => {
    expect(parseClientRequest(Buffer.from('{not json', 'utf8')).ok).toBe(false);
  });

  it('rejects a non-object and an array', () => {
    expect(parseClientRequest(Buffer.from('42', 'utf8')).ok).toBe(false);
    expect(parseClientRequest(Buffer.from('"x"', 'utf8')).ok).toBe(false);
    expect(parseClientRequest(Buffer.from('[]', 'utf8')).ok).toBe(false);
  });

  it('rejects an unknown/extra field', () => {
    const body = Buffer.from(
      JSON.stringify({
        v: PROTOCOL_VERSION,
        nonceC: encodeBase64Url(randomBytes(NONCE_BYTES)),
        command: 'OPEN_HUMAN_GATE',
        mac: encodeBase64Url(randomBytes(MAC_BYTES)),
        extra: 1,
      }),
      'utf8',
    );
    expect(parseClientRequest(body).ok).toBe(false);
  });

  it('rejects a missing field', () => {
    const body = Buffer.from(
      JSON.stringify({ v: PROTOCOL_VERSION, command: 'OPEN_HUMAN_GATE', mac: 'x' }),
      'utf8',
    );
    expect(parseClientRequest(body).ok).toBe(false);
  });

  it('rejects a __proto__ key as a surplus own key', () => {
    const body = Buffer.from(
      `{"v":${String(PROTOCOL_VERSION)},"nonceC":"${encodeBase64Url(
        randomBytes(NONCE_BYTES),
      )}","command":"OPEN_HUMAN_GATE","mac":"${encodeBase64Url(
        randomBytes(MAC_BYTES),
      )}","__proto__":{"polluted":true}}`,
      'utf8',
    );
    expect(parseClientRequest(body).ok).toBe(false);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  it('rejects a wrong protocol version', () => {
    const body = Buffer.from(
      JSON.stringify({
        v: 999,
        nonceC: encodeBase64Url(randomBytes(NONCE_BYTES)),
        command: 'OPEN_HUMAN_GATE',
        mac: encodeBase64Url(randomBytes(MAC_BYTES)),
      }),
      'utf8',
    );
    expect(parseClientRequest(body).ok).toBe(false);
  });

  it('rejects a nonce or mac of the wrong length, and a non-string command', () => {
    const shortNonce = Buffer.from(
      JSON.stringify({
        v: PROTOCOL_VERSION,
        nonceC: encodeBase64Url(randomBytes(8)),
        command: 'OPEN_HUMAN_GATE',
        mac: encodeBase64Url(randomBytes(MAC_BYTES)),
      }),
      'utf8',
    );
    expect(parseClientRequest(shortNonce).ok).toBe(false);
    const nonStringCommand = Buffer.from(
      JSON.stringify({
        v: PROTOCOL_VERSION,
        nonceC: encodeBase64Url(randomBytes(NONCE_BYTES)),
        command: 7,
        mac: encodeBase64Url(randomBytes(MAC_BYTES)),
      }),
      'utf8',
    );
    expect(parseClientRequest(nonStringCommand).ok).toBe(false);
  });
});

describe('D062 wire bodies round-trip', () => {
  it('hello body round-trips a nonce', () => {
    const nonceS = randomBytes(NONCE_BYTES);
    const parsed = parseHelloBody(buildHelloBody(nonceS));
    expect(parsed?.equals(nonceS)).toBe(true);
  });

  it('result body round-trips status + mac', () => {
    const mac = randomBytes(MAC_BYTES);
    const parsed = parseResultBody(buildResultBody(CONTROL_RESULT.APPLIED, mac));
    expect(parsed?.result).toBe('APPLIED');
    expect(parsed?.mac.equals(mac)).toBe(true);
  });

  it('a built request body parses back', () => {
    const nonceC = randomBytes(NONCE_BYTES);
    const mac = randomBytes(MAC_BYTES);
    const parsed = parseClientRequest(buildRequestBody(nonceC, 'OPEN_HUMAN_GATE', mac));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.nonceC.equals(nonceC)).toBe(true);
      expect(parsed.mac.equals(mac)).toBe(true);
    }
  });
});
