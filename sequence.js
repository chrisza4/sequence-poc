const jwt = require("jsonwebtoken");
const uuid = require("uuid");

function parseJwt(token) {
  const base64Url = token.split(".")[1];
  const base64 = base64Url.replace("-", "+").replace("_", "/");
  const buff = new Buffer(base64, "base64");
  const text = buff.toString("ascii");
  return JSON.parse(text);
}

function sessionIdForPayload(payload) {
  return payload.signatures[0]
    ? parseJwt(payload.signatures[0]).sessionId
    : uuid.v4();
}

function createPayloadWithSignatures(payload) {
  return payload.signatures ? payload : { payload, signatures: [] };
}

function signSequence(payload, privateKey) {
  const payloadWithSignatures = createPayloadWithSignatures(payload);
  const sessionId = sessionIdForPayload(payloadWithSignatures);
  const newSignatures = [
    ...payloadWithSignatures.signatures,
    jwt.sign({ sessionId, created: new Date().toISOString() }, privateKey, {
      algorithm: "RS256",
    }),
  ];
  return {
    ...payloadWithSignatures,
    signatures: newSignatures,
  };
}

function verifySequence(payload, publicKeys) {
  if (!payload.signatures) {
    throw Error("payload not signed");
  }
  if (publicKeys.length !== payload.signatures.length) {
    return false;
  }
  const sessionIds = [];
  for (const index in payload.signatures) {
    const signature = payload.signatures[index];
    const publicKey = publicKeys[index];
    const sessionId = parseJwt(signature).sessionId;
    try {
      jwt.verify(signature, publicKey, {
        algorithms: "RS256",
      });
      sessionIds.push(sessionId);
    } catch (err) {
      if (err.name === "JsonWebTokenError") {
        return false;
      }
      throw err;
    }
  }
  const isUniqueSessionId = new Set(sessionIds).size === 1;
  return isUniqueSessionId;
}

module.exports = {
  signSequence,
  verifySequence,
};
