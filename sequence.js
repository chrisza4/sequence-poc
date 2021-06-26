const jwt = require("jsonwebtoken");

function signSequence(payload, privateKey) {
  const payloadWithSignatures = payload.signatures
    ? payload
    : { payload, signatures: [] };
  return {
    payload: payloadWithSignatures.payload,
    signatures: [
      ...payloadWithSignatures.signatures,
      jwt.sign({ created: new Date().toISOString() }, privateKey, {
        algorithm: "RS256",
      }),
    ],
  };
}

function verifySequence(payload, publicKeys) {
  if (!payload.signatures) {
    throw Error("payload not signed");
  }
  if (publicKeys.length !== payload.signatures.length) {
    return false;
  }
  for (const index in payload.signatures) {
    const signature = payload.signatures[index];
    const publicKey = publicKeys[index];
    try {
      jwt.verify(signature, publicKey, {
        algorithms: "RS256",
      });
    } catch (err) {
      if (err.name === "JsonWebTokenError") {
        return false;
      }
      throw err;
    }
  }
  return true;
}

module.exports = {
  signSequence,
  verifySequence,
};
