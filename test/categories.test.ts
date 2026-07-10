import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCategories, detectMessage } from '../src/detect/index.js';

function cats(text: string): string[] {
  return scanCategories(text).map((h) => h.category);
}

test('first-person gating: asking about a topic is not disclosing it', () => {
  assert.deepEqual(cats('What is sertraline used for?'), []);
  assert.deepEqual(cats('Explain how divorce law works in Ohio.'), []);
  assert.deepEqual(cats('The company reported salary bands publicly.'), []);
  assert.deepEqual(cats('I take sertraline every morning.'), ['mental-health']);
  assert.deepEqual(cats('My divorce hearing is on Monday.'), ['legal']);
});

test('self-sufficient phrases fire without extra markers', () => {
  assert.deepEqual(cats('My therapist suggested journaling.'), ['mental-health']);
  assert.deepEqual(cats('My lawyer wants the contract by Friday.'), ['legal']);
  assert.deepEqual(cats('My boss keeps rescheduling our 1:1.'), ['employment']);
  assert.deepEqual(cats('My wife Sarah started a new job.'), ['relationships']);
  assert.deepEqual(cats('My salary is $145,000 a year.'), ['financial']);
  assert.deepEqual(cats('My doctor changed my dosage.'), ['health']);
});

test('health conditions and meds are gated but detected', () => {
  assert.deepEqual(cats('I was diagnosed with hypertension last spring.'), ['health']);
  assert.deepEqual(cats('They put me on lisinopril after the ER visit.'), ['health']);
});

test('identity: names captured, gerunds rejected', () => {
  const hits = scanCategories('My name is John Carter and I need a bio.');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].category, 'identity');
  assert.equal(hits[0].hasName, true);

  const intro = scanCategories("Hi, I'm Jane Rodriguez from the platform team.");
  assert.ok(intro.some((h) => h.category === 'identity' && h.hasName));

  assert.deepEqual(cats("I'm Getting Started with the SDK."), []);
  assert.ok(scanCategories('I work at Stripe as a data engineer.').some((h) => h.category === 'identity'));
});

test('financial custom rule: money + finance word + first person', () => {
  assert.deepEqual(cats('I still owe $23,000 on the loan.'), ['financial']);
  assert.deepEqual(cats('The invoice total is $23,000.'), []);
});

test('one hit per category per sentence; multiple categories allowed', () => {
  const hits = scanCategories('My therapist upped my sertraline and my anxiety is rough.');
  assert.equal(hits.filter((h) => h.category === 'mental-health').length, 1);

  const multi = scanCategories('My lawyer says I should check our NDA before I share the repo.');
  const set = new Set(multi.map((h) => h.category));
  assert.ok(set.has('legal'));
  assert.ok(set.has('employment'));
});

test('layer 3 runs only on user messages', () => {
  const asUser = detectMessage('My therapist suggested journaling.', 'user');
  const asAssistant = detectMessage('My therapist suggested journaling.', 'assistant');
  const asTool = detectMessage('My therapist suggested journaling.', 'tool');
  assert.equal(asUser.categories.length, 1);
  assert.equal(asAssistant.categories.length, 0);
  assert.equal(asTool.categories.length, 0);
});
