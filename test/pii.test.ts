import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanText, PII_RULES } from '../src/detect/index.js';
import { luhnValid, ibanValid, isPublicIpv4 } from '../src/detect/validators.js';
import { PLANTS } from './helpers/plants.js';

function types(text: string): string[] {
  return scanText(text, PII_RULES).map((s) => s.rule.id);
}

test('credit cards require Luhn + brand', () => {
  assert.ok(luhnValid('4111111111111111'));
  assert.ok(!luhnValid('4111111111111112'));
  assert.deepEqual(types(`card ${PLANTS.card} pls`), ['credit-card']);
  assert.deepEqual(types('card 4111 1111 1111 1112 pls'), []); // bad checksum
  assert.deepEqual(types('order id 1234 5678 9012 3456'), []); // luhn fails
  assert.deepEqual(types('build 41111111111111112222 tag'), []); // too long digit run
});

test('iban: checksum-gated, spaces allowed', () => {
  assert.ok(ibanValid(PLANTS.ibanCompact));
  assert.ok(!ibanValid('DE89370400440532013001'));
  assert.deepEqual(types(`wire to ${PLANTS.ibanCompact}`), ['iban']);
  assert.deepEqual(types(`wire to ${PLANTS.iban} today`), ['iban']);
  assert.deepEqual(types('code DE89370400440532013001 fails'), []);
});

test('ssn: context-gated and structurally valid', () => {
  assert.deepEqual(types(`my ssn is ${PLANTS.ssn}`), ['ssn']);
  assert.deepEqual(types(`the ticket is ${PLANTS.ssn}`), []); // no context
  assert.deepEqual(types('ssn: 000-12-3456'), []); // invalid area
  assert.deepEqual(types('ssn: 666-12-3456'), []);
  assert.deepEqual(types('social security number 219099999'), ['ssn-bare']);
});

test('emails: real ones flagged, artifacts skipped', () => {
  assert.deepEqual(types(`mail ${PLANTS.email} now`), ['email']);
  assert.deepEqual(types('user@example.com is the docs placeholder'), []);
  assert.deepEqual(types('see img@2x.png and logo@3x.jpg'), []);
  assert.deepEqual(types('noreply@realcorp.com sent it'), []);
});

test('phones: NANP + international, dates excluded', () => {
  assert.deepEqual(types(`call ${PLANTS.phone} ok`), ['phone-us']);
  assert.deepEqual(types('call 415-555-0132 ok'), ['phone-us']);
  assert.deepEqual(types('reach me at +44 20 7946 0958'), ['phone-intl']);
  assert.deepEqual(types('released 2024-06-15 at noon'), []); // ISO date
  assert.deepEqual(types('version 1.2.3-4567 shipped'), []);
  assert.deepEqual(types('the id is 123-456-7890'), []); // NANP area codes start 2-9
});

test('ips: public only, versions excluded', () => {
  assert.ok(isPublicIpv4(PLANTS.publicIp));
  assert.ok(!isPublicIpv4('192.168.1.1'));
  assert.ok(!isPublicIpv4('10.0.0.5'));
  assert.ok(!isPublicIpv4('203.0.113.9')); // TEST-NET
  assert.deepEqual(types(`server at ${PLANTS.publicIp} up`), ['ipv4']);
  assert.deepEqual(types('gateway 192.168.1.1 and 127.0.0.1 up'), []);
  assert.deepEqual(types('upgraded to v1.2.3.4 today'), []);
});

test('addresses: street-suffix heuristic', () => {
  assert.deepEqual(types(`ship to ${PLANTS.address}, Springfield`), ['street-address']);
  assert.deepEqual(types('see 2024 Annual Ave report'), []); // year guard
  assert.deepEqual(types('Dr. Smith lives nearby'), []); // no leading number
});

test('dob and id numbers: context-gated', () => {
  assert.deepEqual(types('born on 03/07/1987 in Ohio'), ['dob']);
  assert.deepEqual(types('deployed on 03/07/2024 in prod'), []); // no birth context
  assert.deepEqual(types('my passport number is X4821937 ok'), ['passport-or-license']);
  assert.deepEqual(types('reference X4821937 in the doc'), []);
});
