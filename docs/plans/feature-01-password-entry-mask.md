# Feature 1/4 — Password input masking and visibility toggle

## Scope

Replace the browser-native password `prompt()` used by the add-entry flow with an in-app password input. The add and edit password fields both start masked and each has a right-side eye control to reveal or hide its value on demand. Entered passwords remain in the existing encrypted entry payload; this feature does not change the vault data format.

## Acceptance criteria

- Add-entry form includes site, account, and password inputs; clicking Add uses the form value and no longer calls `prompt("密碼：")`.
- Add and edit password fields have `type="password"` on initial render and whenever the edit form is opened again.
- Each eye control toggles only its associated field between `password` and `text`, exposes an accessible name/state, and does not persist revealed state after save/cancel/successful add.
- The entry list continues not to render password values. Existing Show/Edit/Delete behavior and encrypted persistence continue to work.
- Add UI regression tests before production changes; observe the expected failure, implement the smallest change, then run the targeted and complete UI test suites plus `git diff --check`.

## Explicitly out of scope

Password history/retention, clipboard copying, custom FIDO key aliases, changes to vault serialization, and changes to the existing Show action. They will be handled in separate feature cards/PRs in the agreed order.

## Implementation sequence

1. Add failing tests for masked defaults, eye toggles, and add-form submission without a password prompt.
2. Implement HTML/CSS/JavaScript changes.
3. Run targeted UI tests and all existing Node UI tests; review the diff and push the PR update.
