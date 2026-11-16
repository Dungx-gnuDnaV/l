# Security Specification — ENGLISH QR CAMPUS

## 1. Data Invariants
1. **PII Isolation**: Student email addresses exist exclusively in `/users/{userId}` and are strictly readable/writable only by the verified owner (`request.auth.uid == userId`). Public leaderboard records in `/leaderboard/{userId}` contain zero PII (only `displayName`, `className`, and scores).
2. **Identity Integrity**: Every document created or updated under `/users/{userId}`, `/users/{userId}/quizAttempts/{attemptId}`, or `/leaderboard/{userId}` must enforce `uid == request.auth.uid` and `request.auth.token.email_verified == true`.
3. **Immutable Audit Trail**: `QuizAttempt` records in `/users/{userId}/quizAttempts/{attemptId}` are append-only (`update` and `delete` denied), have bounded point caps (`pointsEarned <= 500`, `score <= maxScore`), and require atomic existence/update of the user's `/leaderboard/{userId}` document via `existsAfter()`.
4. **Temporal & Schema Rigor**: All `createdAt` and `updatedAt` timestamps must equal `request.time`. All strings enforce explicit `.size()` bounds and IDs match `^[a-zA-Z0-9_\-]+$`.

## 2. Dirty Dozen Adversarial Payloads (Must Return PERMISSION_DENIED)
1. Unauthenticated write to `/leaderboard/attacker123`.
2. Authenticated user A attempting to read `/users/userB` (PII leak attempt).
3. Authenticated user A attempting to write `/leaderboard/userB` (score spoofing for another student).
4. Authenticated user with `email_verified: false` creating `/users/{uid}`.
5. Shadow field injection: adding `isAdmin: true` or `role: "teacher"` when creating `/users/{uid}`.
6. Shadow field injection on `/leaderboard/{uid}`: adding `email: "leak@test.com"`.
7. Client-forged timestamp: setting `createdAt` to a past/future client timestamp instead of `request.time`.
8. Resource poisoning: sending a 2KB string for `displayName` or `className` or document ID `{attemptId}`.
9. Score inflation attack: submitting `pointsEarned: 999999` on a `QuizAttempt` or `totalScore: 9999999` on `/leaderboard/{uid}`.
10. Orphaned quiz attempt: creating `/users/{uid}/quizAttempts/{attemptId}` when `/users/{uid}` does not exist or without updating `/leaderboard/{uid}` atomically.
11. Mutating an immutable `QuizAttempt` (update or delete).
12. Overwriting immutable `createdAt` or `uid` during `/users/{uid}` update.
