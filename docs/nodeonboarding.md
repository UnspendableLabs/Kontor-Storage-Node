# Node Storage Onboarding

## Components

### Horizon Market

- Serves as the user interface for Horizon Portal.
- Supports user registration and verification.
- Allows assigning the Storage Node role to a user.

### Horizon Portal

- No user interface, REST API only.
- Verifies API caller identity with Market.
- Allows Storage Nodes to list and join agreements.

### Storage Node

- Command-line application.
- Communicates with Horizon Portal to list and join agreements.

## Actors

1. Admin: Horizon Market administrator; can assign the Node role to a user.
2. Operator: the person responsible for a Storage Node.
3. Portal: shorthand for the Horizon Portal API.

## Workflow

1. After a manual KYC step, the Admin assigns the Storage Node role to a user, giving access to a dedicated Operator page.
Note: the KYC step links a person to a Bitcoin address.

2. The Operator installs the Storage Node application on their server. On first launch, the application asks for a password and generates a BLS key pair. The private key is stored in an encrypted file with the password, and the public key is displayed for step 3.

3. The Operator takes the BLS public key shown by the Storage Node application and goes to Horizon Market. On a dedicated page, the Operator signs the BLS public key with Horizon Wallet and sends it to the Horizon Market server, which stores it in the database.
Note: signing the BLS key with the Bitcoin address links a person to a BLS key.

4. The Storage Node application uses the BLS private key to sign requests to the Horizon Portal API. To verify the signature, Horizon Portal asks Horizon Market for the caller's BLS public key.

## Security Considerations

The Storage Node application follows industry-standard practices for private key management:

- **Password-protected startup**: The BLS private key is stored encrypted on disk (Argon2id + AES-256-GCM). The operator must enter the password on every application start—there is no way to auto-unlock.

- **Memory protection**: Once decrypted, the private key is secured in RAM using Rust best practices:
  - `zeroize`: automatic memory wiping on drop
  - `secrecy`: controlled exposure of secret values
  - `memsec`: memory locking (`mlock`) to prevent swapping to disk

This approach mirrors how Ethereum validators (Lighthouse, Prysm) and SSH agents handle sensitive key material.

- **Request signing**: API calls to Horizon Portal are signed using RFC 9421 (HTTP Message Signatures) with BLS, ensuring authenticity and integrity of each request.