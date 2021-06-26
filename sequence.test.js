const sequence = require("./sequence");
const { pvKey1, pvKey2, pvKey3, pbKey1, pbKey2, pbKey3 } = require("./keys");

test("Can verify simple sequence", () => {
  const originalPayload = { ok: true };
  const machine1SignedPayload = sequence.signSequence(originalPayload, pvKey1);
  const machine2SignedPayload = sequence.signSequence(
    machine1SignedPayload,
    pvKey2
  );
  const machine3SignedPayload = sequence.signSequence(
    machine2SignedPayload,
    pvKey3
  );
  const expectedSequence = [pbKey1, pbKey2, pbKey3];
  const actual = sequence.verifySequence(
    machine3SignedPayload,
    expectedSequence
  );
  expect(actual).toBeTruthy();
});

test("Can de-verfiy wrong sequence", () => {
  const originalPayload = { ok: true };
  const machine1SignedPayload = sequence.signSequence(originalPayload, pvKey1);
  const machine2SignedPayload = sequence.signSequence(
    machine1SignedPayload,
    pvKey2
  );
  const machine3SignedPayload = sequence.signSequence(
    machine2SignedPayload,
    pvKey3
  );

  const expectedSequence = [pbKey1, pbKey3, pbKey2];
  const result = sequence.verifySequence(
    machine3SignedPayload,
    expectedSequence
  );
  expect(result).toBeFalsy();
});

test("Can de-verfiy wrong sequence #2", () => {
  const originalPayload = { ok: true };
  const machine1SignedPayload = sequence.signSequence(originalPayload, pvKey1);
  const machine2SignedPayload = sequence.signSequence(
    machine1SignedPayload,
    pvKey2
  );
  const machine2reSignedPayload = sequence.signSequence(
    machine2SignedPayload,
    pvKey2
  );
  const machine3SignedPayload = sequence.signSequence(
    machine2reSignedPayload,
    pvKey3
  );

  const expectedSequence = [pbKey1, pbKey2, pbKey3];
  const result = sequence.verifySequence(
    machine3SignedPayload,
    expectedSequence
  );
  expect(result).toBeFalsy();
});

test("Cannot hijack/reuse old session", () => {
  const originalPayload = { ok: true };
  const machine1SignedPayload = sequence.signSequence(originalPayload, pvKey1);
  const newSessionStartOnMachine2 = sequence.signSequence(
    originalPayload,
    pvKey2
  );

  const hackedPayload = {
    payload: newSessionStartOnMachine2,
    signatures: [
      ...machine1SignedPayload.signatures,
      ...newSessionStartOnMachine2.signatures,
    ],
  };

  const expectedSequence = [pbKey1, pbKey2];
  const result = sequence.verifySequence(hackedPayload, expectedSequence);
  expect(result).toBeFalsy();
});

test("Cannot switch order", () => {
  const originalPayload = { ok: true };
  const machine1SignedPayload = sequence.signSequence(originalPayload, pvKey1);
  const newSessionStartOnMachine2 = sequence.signSequence(
    machine1SignedPayload,
    pvKey2
  );

  const hackedPayload = {
    payload: newSessionStartOnMachine2,
    signatures: [
      newSessionStartOnMachine2.signatures[1],
      newSessionStartOnMachine2.signatures[0],
    ],
  };

  const expectedSequence = [pbKey2, pbKey1];
  const result = sequence.verifySequence(hackedPayload, expectedSequence);
  expect(result).toBeFalsy();
});
