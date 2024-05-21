---
name: Generic PR Template
about: A Suite of Manual Tests
title: ''
labels: ''
assignees: ''

---

SECTION 1: WEVE GOT POEMS (http://localhost:5173/)
[ ] Log in with 'tester' / '1234'
[ ] Log in anonymously with Layer8
[ ] Clicking "Get Next Poem" loads different poem correctly x 3
[ ] Clicking "Logout" takes you to the login screen
[ ] Clicking "Register" takes you to the registration page
[ ] Registering with a username, password, and profile image is successful
[ ] Logging in with the new username / password succeeds
[ ] Logging in with Layer8 opens the pop-up
[ ] Logging in with the "tester" & "12341234" works
[ ] User chooses to share their new "Username" & "Country" from the Layer8 Resource Server
[ ] Clicking "Get Next Poem" loads different poem correctly x 3
[ ] Clicking "Logout" takes you to the login page

SECTION 2: IMSHARER (http://localhost:5174/)
[ ] Main page loads
[ ] Upload of image works
[ ] Reload leads to instant reload (demonstrating proper caching)
[ ] Clicking the newly loaded image shows it in a light boxLog in using tester and 12341234 should succeed
