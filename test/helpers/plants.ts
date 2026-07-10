/**
 * Planted fake secrets/PII shared by fixtures and tests. Every value is
 * format-valid but fabricated (AWS values are the official documentation
 * examples; the JWT is the canonical jwt.io demo token). A consistency test
 * asserts the fixture files actually contain these exact strings, and the
 * report test asserts none of them ever appear unredacted in output.
 */
export const PLANTS = {
  awsKeyId: 'AKIAIOSFODNN7EXAMPLE',
  awsSecret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  ghToken: 'ghp_x7K9mQ2pL4nR8vT1wY5uI3oP6aS0dF2gH4jK',
  anthropicKey: 'sk-ant-api03-Xy7Kq2mNp9Lr4Tv8Wz1Ju5Io3Pa6Sd0Fg2Hj4Kl',
  stripeLive: 'sk_live_4X9mQ2pL7nR8vT1wY5uI3oK6',
  googleKey: 'AIzaSyD9xQ2Lp7Kn4Rv8Tw1Yz5Ui3Po6As0Dk2H',
  slackToken: 'xoxb-9876543210123-1234567890123-Ab1Cd2Ef3Gh4Ij5Kl6Mn7O',
  npmToken: 'npm_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
  genericToken: 'q7R2mX9kL4pW8vN1zY5t',
  jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  pgUri: 'postgres://appuser:S3cr3tDbPass@db.internal.corp:5432/prod',
  urlAuth: 'https://admin:hunter2pass@internal.corp/health',
  password: 'Tr0ub4dor&3',
  privateKeyBody: 'MIIEpAIBAAKCAQEA7X9mQ2pL4nR8vT1wY5uI3oP6aS0dF2gH4jK9xQ2Lp7Kn4Rv8',
  card: '4111 1111 1111 1111',
  cardDigits: '4111111111111111',
  iban: 'DE89 3704 0044 0532 0130 00',
  ibanCompact: 'DE89370400440532013000',
  ssn: '219-09-9999',
  email: 'john.carter1984@gmail.com',
  phone: '(415) 555-0132',
  address: '742 Evergreen Terrace',
  publicIp: '52.14.203.7',
  // planted in the agent-activity fixture (session-0002): read from .env / ssh by the agent
  agentStripe: 'sk_live_51H8xqLK2eZvKYlo2C9xQ4rT6wY8uI0oP',
  agentSendgrid: 'SG.aB3dEfGhIjKlMnOpQrStUv.wXyZ1234567890abcdefghijklmnopqrstuv',
  agentSshBody: 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW',
} as const;

export const PRIVATE_KEY_PEM = `-----BEGIN RSA PRIVATE KEY-----
${PLANTS.privateKeyBody}
kX3nQ8vT2wY6uI4oP7aS1dF3gH5jK0xQ3Lp8Kn5Rv9Tw2Yz6Ui4Po7As1Dk3Hq
-----END RSA PRIVATE KEY-----`;

/** Raw strings that must NEVER appear in any report or JSON output. */
export const MUST_NOT_LEAK: string[] = [
  PLANTS.awsKeyId,
  PLANTS.awsSecret,
  PLANTS.ghToken,
  PLANTS.anthropicKey,
  PLANTS.stripeLive,
  PLANTS.googleKey,
  PLANTS.slackToken,
  PLANTS.npmToken,
  PLANTS.jwt,
  PLANTS.password,
  PLANTS.privateKeyBody,
  PLANTS.card,
  PLANTS.cardDigits,
  PLANTS.ssn,
  PLANTS.email,
  'S3cr3tDbPass',
  'hunter2pass',
  PLANTS.agentStripe,
  PLANTS.agentSendgrid,
  PLANTS.agentSshBody,
];
